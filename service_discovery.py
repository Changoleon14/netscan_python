#!/usr/bin/python
import re
from host_discovery import *
from port_discovery import *
from db_operations import DBManager
import socket
import requests

db = DBManager("scan.db")

def parse_nmap_probe_line(line, match):
    """
    line: línea del archivo nmap-service-probes (ya match del banner)
    match: el objeto re.Match de tu banner grabbing previo
    """
    pattern = re.compile(r'([a-z]+)/([^/]*)/')
    result = {}
    for m in pattern.finditer(line):
      key = m.group(1)
      value = m.group(2).strip()

      # Reemplaza $1, $2, ... con los grupos del match
      def replace_group_var(matchobj):
        idx = int(matchobj.group(1))
        return match.group(idx)
      value = re.sub(r'\$(\d+)', replace_group_var, value)

      # cpe puede aparecer varias veces
      if key.startswith("cpe"):
        if "cpe" not in result:
          result["cpe"] = []
        result["cpe"].append(value)
      else:
        result[key] = value

    return result

# nmap-service-probes
def version_scan(ip, port):
  result = tcp_connection(ip, port, con_scan=True)
  if not result:
    return False
  banner, ack = result
  if not banner or not banner.haslayer(Raw):
    return False
  payload = banner[Raw].load.decode()

  file_path = "/usr/share/nmap/nmap-service-probes"
  file = open(file_path, "rb")
  for _ in range(41):
    file.readline()

  match_pattern = r'match\s+(\S+)\s+m(.*$)'
  probe_pattern = r'^Probe\s'

  line = file.readline().decode("utf-8", errors="ignore")
  while line:
    match_1 = re.match(match_pattern, line)
    match_2 = re.match(probe_pattern, line)
    if match_1:
      service = match_1.group(1)
      regex = match_1.group(2)
      delimiter = regex[0]
      field_list = regex.split(delimiter)
      service_pattern = field_list[1]
      versionInfo = field_list[2]
      service_pattern_bytes = service_pattern
      srv_patrn_bytes_compiled = re.compile(service_pattern_bytes)
      service_match = srv_patrn_bytes_compiled.match(payload)
      if service_match:
        vinfo_dict = parse_nmap_probe_line(versionInfo, service_match)
        version_string = f"{service}\t{vinfo_dict.get('p', '')} {vinfo_dict.get('v', '')}"
        host_id = db.upsert_host(ip)
        db.upsert_host_port(
          host_id,
          db.upsert_port(port, "tcp"),
          "open",
          "tcp-conn-scan",
          db.upsert_service(service, version_string),
          banner=payload
        )
        if "o" in vinfo_dict:
          db.upsert_os_guess(host_id, vinfo_dict["o"], f"banner-{service}", None, "From service detection")

        return version_string
    
    elif match_2:
      return False

    line = file.readline().decode("utf-8", errors="ignore")
  return False

def version_scan_multy(ip, ports):
  port_range = parse_range(ports)
  for port in port_range:
    result = version_scan(ip, port)
  # db.report(ip)


def http_version_probe(ip, port, timeout=5):
  """
  Performs an HTTP GET request using requests and tries to guess the web server version from headers.
  Returns the server/version string if found, else None.
  """
  url = f"http://{ip}:{port}/"
  info = ""
  try:
    response = requests.get(url, timeout=timeout)
    server_header = response.headers.get("Server")
    if server_header:
      print(f"Discovered HTTP service on {ip}:{port} - Server: {server_header}")
      info += f"Server: {server_header} - "
      # return server_header
    # Optionally, check other headers for version info
    for header in ["X-Powered-By", "Via"]:
      if header in response.headers:
        print(f"Additional info from {header}: {response.headers[header]}")
        info += f"{header}: {response.headers[header]} - "
        # return response.headers[header]
    return info
  except Exception as e:
    print(f"Error probing HTTP service on {ip}:{port} - {e}")
    return None
