#!/usr/bin/python

from host_discovery import *
from port_discovery import *
from service_discovery import *
from full_scan import *

db = DBManager("scan.db")
# target_IP = "10.10.10.245"
# target_IP = "192.168.238.137"
target_IP = "10.10.10.245"
# target_IP = "127.0.0.1"

# icmp_ping(target_IP)
# tcp_syn_ping(target_IP)
# tcp_syn_ping(target_IP, 12345)
# udp_ping(target_IP)

db.clear_all_tables()
# syn_scan(target_IP, "21,22,8888")
# syn_scan(target_IP, "22")
# version_scan_multy(target_IP, "22")
# http_version_probe(target_IP, 80)
# ack = tcp_connection(target_IP, 22)

full_scan(target_IP, "21,22,80")