#!/usr/bin/python
"""
# Host Discovery Script
# This script is used to discover hosts in a network.
"""

# Imports
import socket
from scapy.all import *
from scapy.all import TCP, IP, ICMP, ARP, Ether, srp, sr, send, conf, L3RawSocket, UDP
from db_operations import DBManager
# conf.L3socket = L3RawSocket

# we will only use this 1000 ports, for more info about why take a look into configure_ports.sh
def custRandshort():
  return RandNum(54000, 55000)

# Constants
RETRY_COUNT = 1
TIMEOUT = 2
db = DBManager("scan.db")

def arp_ping(ip_range):
  """
  Que es Arp Ping?
  ARP Ping es un método para descubrir hosts activos en una red local enviando solicitudes ARP.
  A diferencia de los pings ICMP tradicionales, que pueden ser bloqueados por firewalls, 
  las solicitudes ARP son esenciales para la comunicación en redes Ethernet y, por lo tanto, 
  suelen ser respondidas por los dispositivos activos.
  Esto hace que ARP Ping sea una herramienta efectiva para identificar dispositivos en una red local.
  
  Lo que hace el protocolo ARP:
  El Protocolo de Resolución de Direcciones (ARP) es un protocolo de red utilizado para mapear 
  direcciones IP a direcciones MAC en una red local. Cuando un dispositivo quiere comunicarse 
  con otro dispositivo en la misma red, necesita conocer la dirección MAC del destinatario. 
  Si el dispositivo no conoce la dirección MAC correspondiente a una dirección IP específica,
  envía una solicitud ARP en la red. El dispositivo que posee la dirección IP solicitada responde 
  con su dirección MAC, permitiendo así la comunicación directa entre los dos dispositivos.
  
  la direccion destino es ff:ff:ff:ff:ff:ff (broadcast) ya que no sabemos quien respondera

  el ip_range puede ser una ip individual o un rango con el formato CIDR 
  (por ejemplo, 192.168.1.0/24).

  lo que hace srp:
  La función srp() en Scapy se utiliza para enviar y recibir paquetes a nivel de enlace de datos 
  (capa 2 del modelo OSI). Su nombre significa "send and receive packets". Y es packets porque asi
  se les llama a los datos en la capa 2.
  mientras que en la capa 3 (IP) se les llama datagramas y en la capa 4 (TCP/UDP) se les llama 
  segmentos, por otro lado en la capa 1 (fisica) se habla de bits y bytes.
  

  """
  pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
  SndRcvList, PacketList = srp(pkt, timeout=5, verbose=0, retry=RETRY_COUNT)
  for sent, received in SndRcvList:
    print(f"Host {received.psrc} está activo (MAC: {received.hwsrc})")

"""
Este es el clasico ping, es como hacer un ping en la terminal
"""
def icmp_ping(ip):
  pkt = IP(dst=ip) / ICMP()
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  resp.summary(lambda s,r: r.sprintf("%IP.src% is alive"))
  return resp

"""
From Scapy Documentation:
'In cases where ICMP echo requests are blocked, we can still use various TCP Pings such as TCP SYN 
Ping. Any response to our probes will indicate a live host. We can collect results with the 
following command:'

In this case I will try to do a TCP syn, in which I have to respond a rst to the syn-ack
"""
def tcp_syn_ping(ip, port=80):
  pkt = IP(dst=ip) / TCP(sport=custRandshort(), dport=port, flags='S')
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  # resp.summary(lambda s,r: r.sprintf("%IP.src% is alive"))
  # If resp is empty this loop wont run
  for sent, answer in resp:
    if answer.haslayer(TCP) and answer[TCP].flags == 0x12: #syn-ack
      sport = sent.getlayer(TCP).sport
      send(IP(dst=ip)/TCP(sport=sport, dport=port, flags='R', ack=answer[TCP].ack), verbose=0)
      # send(IP(dst=ip)/TCP(sport=sport, dport=port, flags='R', ack=acknum, reserved=0x1), verbose=0)
  return resp, unans
    

# Rules for the tcp sequence numbers

# | Tipo de paquete | `SEQ`                    | `ACK`                                 |
# | --------------- | ------------------------ | ------------------------------------- |
# | **SYN**         | Número aleatorio inicial | 0 o ausente (no hay datos aún)        |
# | **SYN-ACK**     | Número aleatorio         | `SEQ del SYN + 1`                     |
# | **ACK**         | `SEQ anterior + 1`       | `SEQ del SYN-ACK + 1`                 |
# | **PSH-ACK**     | `SEQ` = último enviado   | `ACK` = último recibido + tamaño data |


# | Evento               | `SEQ`         | `ACK`             |
# | -------------------- | ------------- | ----------------- |
# | `SYN`                | `X`           | –                 |
# | `SYN-ACK`            | `Y`           | `X+1`             |
# | `ACK`                | `X+1`         | `Y+1`             |
# | `PSH-ACK (con data)` | `X+1` (mismo) | `Y+1`             |
# | `ACK` (respuesta)    | `Y+1`         | `X+1 + len(data)` |


def tcp_connection(ip, port=80, con_scan = True):
  sport = custRandshort()
  syn = IP(dst=ip) / TCP(sport=sport, dport=port, flags='S', seq = 1000)
  # synack
  synack = sr1(syn, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  if not synack:
    return False
  host_id = db.upsert_host(ip)
  if synack[TCP].flags == 0x12: #syn-ack
    db.upsert_host_port(host_id, db.upsert_port(port, "tcp"), "open", "tcp-conn-synack")
    sport = synack.getlayer(TCP).dport
    # Send final ACK (of the 3-way handshake)
    ack = TCP(sport=sport, dport=port, flags='A',seq=synack.ack, ack=synack.seq + 1)
    banner = sr1(IP(dst=ip)/ack, verbose=0, timeout=5)
  elif synack[TCP].flags == "R" or synack[TCP].flags == "RA":
    db.upsert_host_port(host_id, db.upsert_port(port, "tcp"), "closed", "tcp-conn-reset")
    return False

  if con_scan:
    send(IP(dst=ip)/TCP(sport=sport, dport=port, flags='R', seq=ack.seq), verbose=0)

  return banner, ack


def tcp_ack_ping(ip, port=80):
  pkt = IP(dst=ip) / TCP(sport=custRandshort(), dport=port, flags='A')
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  resp.summary(lambda s,r: r.sprintf("%IP.src% is alive"))
  # Ir resp is empty this loop wont run
  for sent, answer in resp:
    if answer.haslayer(TCP) and answer[TCP].flags == 0x12:  
      send(IP(dst=ip)/TCP(dport=port, flags='R'), verbose=0)
  return resp

"""
If all else fails there is always UDP Ping which will produce ICMP Port unreachable errors from live
hosts. Here you can pick any port which is most likely to be closed, such as port 0:

ans, unans = sr( IP(dst="192.168.*.1-10")/UDP(dport=0) )
Once again, results can be collected with this command:

ans.summary( lambda s,r : r.sprintf("%IP.src% is alive") )
"""
def udp_ping(ip, port=0):
  pkt = IP(dst=ip) / UDP(sport=custRandshort(), dport=port)
  resp, unans = sr(pkt, timeout=TIMEOUT, verbose=0, retry=RETRY_COUNT)
  resp.summary(lambda s,r: r.sprintf("%IP.src% is alive"))
  return resp
