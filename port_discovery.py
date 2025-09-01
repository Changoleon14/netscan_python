#!/usr/bin/python
from host_discovery import *
from db_operations import DBManager
from concurrent.futures import ThreadPoolExecutor, as_completed

db = DBManager("scan.db")
max_threads = 50

"""
Funcion para sacar rangos de puertos
"""
def parse_range(prange: str):
  pranges = prange.split(",")
  for prange in pranges:
    if "-" in prange:
      begin, end = map(int, prange.split("-"))
      yield from range(begin, end + 1)
    else:
      yield int(prange)

def guess_os_from_ttl(host_id, ttl_observed):
  if ttl_observed is None:
    return False

  # TTL iniciales típicos por sistema operativo
  ttl_guesses = {
    64: "Linux/Unix",
    128: "Windows",
    255: "Cisco/Network device/BSD"
  }

  # Buscar el TTL inicial más cercano al observado
  closest_ttl = min(ttl_guesses.keys(), key=lambda ref: abs(ref - ttl_observed))
  os_guess = ttl_guesses[closest_ttl]

  db.upsert_os_guess(host_id, os_guess, method="ttl-guess", confidence="medium",
                     notes=f"Observed TTL: {ttl_observed}")

  return True

"""

"""
def syn_scan(ip, r_port="0-1023"):

  # Creamos el pool de threads
  with ThreadPoolExecutor(max_workers=max_threads) as executor:
    # Generamos tareas para todos los puertos
    futures = [executor.submit(tcp_syn_ping, ip, port) for port in parse_range(r_port)]
    
    # Iteramos conforme los threads terminan
    for future in as_completed(futures):
      # Get port since it is concurrent we dont know which packet corresponds to which port
      result = future.result()
      replied, unans = result
      if not replied:
        sent, answer = unans[0]
      else:
        sent, answer = replied[0]
      port = sent.dport

      host_id = db.upsert_host(ip)
      port_id = db.upsert_port(port, "tcp")
      # Process results here
      if not replied:
        # This means no response meaning filtered
        db.upsert_host_port(host_id, port_id, "filtered", "no-response")
      only_once = 0
      for sent, answer in replied:
        if only_once == 0:
          ttl = answer[IP].ttl
          guess_os_from_ttl(host_id, ttl)
          only_once += 1
        if answer.haslayer(TCP):
          tcp_layer = answer.getlayer(TCP)
          if tcp_layer.flags == 0x4:
            # This means the port is closed
            db.upsert_host_port(host_id, port_id, "closed", "tcp-reset")
          elif tcp_layer.flags == 0x12: 
            # This means the port is open
            db.upsert_host_port(host_id, port_id, "open", "tcp-syn-ack")
          elif tcp_layer.flags == 0x14: # rst-ack
            # This means the port is filtered
            db.upsert_host_port(host_id, port_id, "closed", "tcp-rst")

        elif answer.haslayer(ICMP):
          icmp_layer = answer.getlayer(ICMP)
          # Códigos que indican "filtrado"
          # ICMP type = 3 (Destination Unreachable)
          # Códigos (code):
          #   1 → Host unreachable
          #   2 → Protocol unreachable
          #   3 → Port unreachable
          #   9 → Communication with destination administratively prohibited
          #   10 → Host administratively prohibited
          #   13 → Communication administratively filtered
          if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
            # This means the port is filtered
            db.upsert_host_port(host_id, port_id, "filtered", "icmp-unreachable")

  # db.report(ip)

# ------------------------------------------------------------------------------
# Firewall evation part
# ------------------------------------------------------------------------------

def null_scan(ip, port=0):
  pkt = IP(dst=ip) / TCP(sport=custRandshort(), dport=port, flags=0x0)
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  
  host_id = db.upsert_host(ip)
  port_id = db.upsert_port(port, "tcp")

  if not resp:
    db.upsert_host_port(host_id, port_id, "open|filtered", "null-scan-no-response")
    return False
  else:
    answer = resp[0][1]
    if answer.haslayer(TCP) and answer[TCP].flags == "R":
      db.upsert_host_port(host_id, port_id, "closed", "null-scan-tcp-reset")
    elif answer.haslayer(ICMP):
      icmp_layer = answer.getlayer(ICMP)
      # Códigos que indican "filtrado"
      # ICMP type = 3 (Destination Unreachable)
      # Códigos (code):
      #   1 → Host unreachable
      #   2 → Protocol unreachable
      #   3 → Port unreachable
      #   9 → Communication with destination administratively prohibited
      #   10 → Host administratively prohibited
      #   13 → Communication administratively filtered
      if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
        # This means the port is filtered
        db.upsert_host_port(host_id, port_id, "filtered", "null-scan-icmp-unreachable")

  return resp

def fin_scan(ip, port=0):
  pkt = IP(dst=ip) / TCP(sport=custRandshort(), dport=port, flags="F")
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  
  host_id = db.upsert_host(ip)
  port_id = db.upsert_port(port, "tcp")

  if not resp:
    db.upsert_host_port(host_id, port_id, "open|filtered", "fin-scan-no-response")
    return False
  else:
    answer = resp[0][1]
    if answer.haslayer(TCP) and answer[TCP].flags == "R":
      db.upsert_host_port(host_id, port_id, "closed", "fin-scan-tcp-reset")
    elif answer.haslayer(ICMP):
      icmp_layer = answer.getlayer(ICMP)
      # Códigos que indican "filtrado"
      # ICMP type = 3 (Destination Unreachable)
      # Códigos (code):
      #   1 → Host unreachable
      #   2 → Protocol unreachable
      #   3 → Port unreachable
      #   9 → Communication with destination administratively prohibited
      #   10 → Host administratively prohibited
      #   13 → Communication administratively filtered
      if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
        # This means the port is filtered
        db.upsert_host_port(host_id, port_id, "filtered", "fin-scan-icmp-unreachable")

  return resp

def xmas_scan(ip, port=0):
  pkt = IP(dst=ip) / TCP(sport=custRandshort(), dport=port, flags="FPU")
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  
  host_id = db.upsert_host(ip)
  port_id = db.upsert_port(port, "tcp")

  if not resp:
    db.upsert_host_port(host_id, port_id, "open|filtered", "xmas-scan-no-response")
    return False
  else:
    answer = resp[0][1]
    if answer.haslayer(TCP) and answer[TCP].flags == "R":
      db.upsert_host_port(host_id, port_id, "closed", "xmas-scan-tcp-reset")
    elif answer.haslayer(ICMP):
      icmp_layer = answer.getlayer(ICMP)
      # Códigos que indican "filtrado"
      # ICMP type = 3 (Destination Unreachable)
      # Códigos (code):
      #   1 → Host unreachable
      #   2 → Protocol unreachable
      #   3 → Port unreachable
      #   9 → Communication with destination administratively prohibited
      #   10 → Host administratively prohibited
      #   13 → Communication administratively filtered
      if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
        # This means the port is filtered
        db.upsert_host_port(host_id, port_id, "filtered", "xmas-scan-icmp-unreachable")

  return resp

def ack_scan(ip, port=0):
  pkt = IP(dst=ip) / TCP(sport=custRandshort(), dport=port, flags="A")
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  
  host_id = db.upsert_host(ip)
  port_id = db.upsert_port(port, "tcp")

  if not resp:
    db.upsert_host_port(host_id, port_id, "filtered", "ack-scan-no-response")
    return False
  else:
    answer = resp[0][1]
    if answer.haslayer(TCP) and answer[TCP].flags == "R":
      db.upsert_host_port(host_id, port_id, "no-filtered", "ack-scan-tcp-reset")
    elif answer.haslayer(ICMP):
      icmp_layer = answer.getlayer(ICMP)
      # Códigos que indican "filtrado"
      # ICMP type = 3 (Destination Unreachable)
      # Códigos (code):
      #   1 → Host unreachable
      #   2 → Protocol unreachable
      #   3 → Port unreachable
      #   9 → Communication with destination administratively prohibited
      #   10 → Host administratively prohibited
      #   13 → Communication administratively filtered
      if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
        # This means the port is filtered
        db.upsert_host_port(host_id, port_id, "filtered", "ack-scan-icmp-unreachable")

  return resp


if __name__ == "__main__":
  # Module Testing
  # Test parse_range function
  a = parse_range("22,80,443,8000-8010")
  type(a)
  print(a)
  print(list(a))