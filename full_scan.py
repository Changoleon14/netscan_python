#!/usr/bin/python
from host_discovery import *
from port_discovery import *
from service_discovery import *
from db_operations import DBManager


"""
from /usr/share/nmap/nmap-services these are the http/tcp common ports
http	80/tcp
http-mgmt	280/tcp
https	443/tcp
http-alt	591/tcp
http-rpc-epmap	593/tcp
httpx	4180/tcp
http-alt	8000/tcp
http	8008/tcp
http-proxy	8080/tcp
https-alt	8443/tcp
http-wmap	8990/tcp
https-wmap	8991/tcp
"""
http_ports = [80, 280, 443, 591, 593, 4180, 8000, 8008, 8080, 8443, 8990, 8991]
db = DBManager("scan.db")


def full_scan(ip, ports = "0-1000"):
  syn_scan(ip, ports)
  ports = db.get_ports(ip)

  for port, status, service_name in ports:
    if status == "open":
      version_scan(ip, port)

    if status == "open" and port in http_ports and service_name is None:
      print(f"Probing HTTP service on {ip}:{port}")
      service = http_version_probe(ip, port)
      if service:
        host_id = db.upsert_host(ip)
        db.upsert_host_port(
          host_id,
          db.upsert_port(port, "tcp"),
          "open",
          "http-get-probe",
          db.upsert_service("http", service),
          banner=None
        )
    
    if status == "filtered":
      null_scan(ip, port)
      xmas_scan(ip, port)
      fin_scan(ip, port)
      ack_scan(ip, port)

  db.report(ip)
    


