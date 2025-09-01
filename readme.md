# PyNetRecon - Network Scanning Tool

## Overview

PyNetRecon is a comprehensive network scanning tool developed in Python for penetration testing purposes. This tool was created as a Master's degree final project and provides a flexible framework for network discovery, port scanning, service detection, and OS fingerprinting.

## Features

- **Host Discovery**: Multiple techniques including ICMP ping, TCP SYN ping, UDP ping, and ARP discovery
- **Port Scanning**: TCP SYN scans, connection scans, and various stealth scanning techniques
- **Service Detection**: Banner grabbing and service version detection using Nmap-style pattern matching
- **OS Fingerprinting**: TTL-based OS detection and service banner analysis
- **Firewall Evasion**: NULL, FIN, XMAS, and ACK scans for bypassing firewall rules
- **Database Storage**: SQLite backend for storing scan results persistently
- **Concurrent Scanning**: Multi-threaded implementation for faster scanning
- **HTTP Service Detection**: Specialized probing for web services

## Installation

### Prerequisites
- Python 3.6+
- Scapy library
- Requests library
- Nmap service probes database (typically located at /usr/share/nmap/nmap-service-probes)

### Setup
1. Clone the repository:
```bash
git clone https://github.com/your-username/pynetrecon.git
cd pynetrecon
```

2. Install required dependencies:
```bash
pip install scapy requests
```

3. Initialize the database:
```bash
python create_db.py
```

4. Configure iptables (required for proper TCP handshake manipulation):
```bash
sudo bash configure_ports.sh
```

## Usage

### Basic Scanning
The main entry point is `run.py`:

```python
from full_scan import full_scan

# Perform a full scan on target IP
target_IP = "10.10.10.245"
full_scan(target_IP, "21,22,80,443")
```

### Individual Modules
You can also use specific scanning modules directly:

```python
from host_discovery import icmp_ping, tcp_syn_ping
from port_discovery import syn_scan
from service_discovery import version_scan

# Host discovery
icmp_ping("192.168.1.1")
tcp_syn_ping("192.168.1.1", 80)

# Port scanning
syn_scan("192.168.1.1", "20-100")

# Service detection
version_scan("192.168.1.1", 80)
```

### Database Operations
View scan results from the database:

```python
from db_operations import DBManager

db = DBManager("scan.db")
db.report("10.10.10.245")  # Print scan report for specific host
```

## Project Structure

```
pynetrecon/
├── run.py                 # Main execution file
├── host_discovery.py      # Host discovery techniques
├── port_discovery.py      # Port scanning methods
├── service_discovery.py   # Service detection and banner grabbing
├── full_scan.py          # Comprehensive scanning workflow
├── db_operations.py      # Database management class
├── create_db.py          # Database initialization script
├── create_db.sql         # Database schema
├── configure_ports.sh    # IPTables configuration script
└── scan.db               # SQLite database (created after first run)
```

## Technical Details

### Host Discovery Techniques
- ICMP Echo Request (Ping)
- TCP SYN Ping (to specified ports)
- UDP Ping (with ICMP response analysis)
- ARP Ping (for local network discovery)

### Port Scanning Methods
- TCP SYN Scan (Stealth scan)
- TCP Connect Scan (Full handshake)
- NULL, FIN, XMAS Scans (Firewall evasion)
- ACK Scan (Firewall mapping)

### Service Detection
- Banner grabbing from open ports
- Nmap-style service pattern matching
- HTTP header analysis for web servers
- Version extraction from service responses

### OS Fingerprinting
- Initial TTL analysis for OS detection
- Service banner analysis for OS clues
- Multiple guess support with confidence levels

## Limitations

1. Requires root privileges for raw socket operations
2. IPTables configuration needed for proper TCP handshake manipulation
3. Service detection depends on Nmap's pattern database
4. Stealth scans may not work against all firewall configurations

## Future Enhancements

- Additional protocol support (SCTP, IPX)
- Vulnerability assessment integration
- Graphical user interface
- Report generation in multiple formats
- API for integration with other tools

## License

This project is created for academic purposes as part of a Master's degree program. Please ensure you have proper authorization before scanning any networks.

## Author

Developed as a Master's thesis project in Penetration Testing.