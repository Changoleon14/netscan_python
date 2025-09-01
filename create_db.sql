/*
1. hosts
* Almacena cada IP escaneada.

sql
id         INTEGER PRIMARY KEY AUTOINCREMENT
ip         TEXT NOT NULL UNIQUE
hostname   TEXT -- si haces reverse DNS
os         TEXT -- Linux, Windows, etc.
timestamp  TEXT -- cuándo se descubrió


2. ports
* Lista de puertos conocidos (puede estar prellenada o llenarse dinámicamente).

id         INTEGER PRIMARY KEY AUTOINCREMENT
port       INTEGER NOT NULL
protocol   TEXT CHECK(protocol IN ('tcp', 'udp'))
UNIQUE(port, protocol)


3. services
* Información sobre servicios identificados por banner grabbing, etc.

id         INTEGER PRIMARY KEY AUTOINCREMENT
name       TEXT NOT NULL
version    TEXT


4. host_ports
* Relación N:M entre hosts, ports y services (resultado de escaneo)

id           INTEGER PRIMARY KEY AUTOINCREMENT
host_id      INTEGER REFERENCES hosts(id)
port_id      INTEGER REFERENCES ports(id)
status       TEXT CHECK(status IN ('open', 'closed', 'filtered')) NOT NULL
service_id   INTEGER REFERENCES services(id)
banner       TEXT -- opcional, texto crudo del banner
scan_time    TEXT -- cuándo se escaneó este puerto

*/
-- Tabla de hosts
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    hostname TEXT DEFAULT 'Unknown',
    timestamp TEXT
);

-- Tabla de puertos
CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port INTEGER NOT NULL,
    protocol TEXT CHECK(protocol IN ('tcp', 'udp')) NOT NULL,
    UNIQUE(port, protocol)
);

-- Tabla de servicios
CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT
);

-- Relación host - puerto - servicio (resultado de escaneo)
CREATE TABLE host_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    reason TEXT DEFAULT NULL,
    service_id INTEGER,
    banner TEXT,
    scan_time TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    FOREIGN KEY (port_id) REFERENCES ports(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

CREATE TABLE os_guesses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    os_name TEXT NOT NULL,
    method TEXT NOT NULL,       -- "TTL", "Banner", "WindowSize", etc.
    confidence INTEGER,         
    notes TEXT,                 -- descripción más detallada
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
