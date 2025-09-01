#!/usr/bin/python
 
"""
* upsert_host(ip, hostname=None, os=None)
Si la IP ya existe → devuelve su id.
Si no existe → la inserta con timestamp y devuelve su nuevo id.

* upsert_port(port, protocol)
Si el puerto y protocolo ya están en la tabla → devuelve su id.
Si no → los inserta y devuelve su nuevo id.

* upsert_service(name, version=None)
Si el servicio con ese nombre y versión ya existe → devuelve su id.
Si no → lo inserta y devuelve el nuevo id.

* upsert_host_port(host_id, port_id, status, service_id=None, banner=None)
Si ya existe una entrada para ese host y puerto:
Actualiza el status, service_id, banner, y scan_time.
Si no existe:
Inserta una nueva fila con todos esos datos.
"""

from os import path
import sqlite3
from datetime import datetime

class DBManager:
  def __init__(self, db_path="scan.db"):
    if not path.isfile(db_path):
      import create_db

    self.conn = sqlite3.connect(db_path)
    self.cursor = self.conn.cursor()

  # This method inserts or updates a host record
  # If the host with the given IP already exists, it updates its details
  # Otherwise, it inserts a new record
  # Returns the host ID
  def upsert_host(self, ip, hostname=None):
    self.cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
    result = self.cursor.fetchone()
    if result:
      # IP already in DB
      host_id = result[0]
      if hostname is None:
        # We only want the host ID, we will not update anything
        return host_id
      self.cursor.execute(
        "UPDATE hosts SET hostname = ?, timestamp = ? WHERE id = ?",
        (hostname, datetime.now().isoformat(), host_id)
      )
    else:
      self.cursor.execute(
        "INSERT INTO hosts (ip, hostname, timestamp) VALUES (?, ?, ?)",
        (ip, hostname, datetime.now().isoformat())
      )
      host_id = self.cursor.lastrowid
    self.conn.commit()
    return host_id

  # this method inserts a port
  def upsert_port(self, port, protocol):
    self.cursor.execute("SELECT id FROM ports WHERE port = ? AND protocol = ?", (port, protocol))
    result = self.cursor.fetchone()
    if result:
      return result[0]
    else:
      self.cursor.execute(
        "INSERT INTO ports (port, protocol) VALUES (?, ?)",
        (port, protocol)
      )
      self.conn.commit()
      return self.cursor.lastrowid

  def upsert_service(self, name, version=None):
    self.cursor.execute("SELECT id FROM services WHERE name = ? AND version IS ?", (name, version))
    result = self.cursor.fetchone()
    if result:
      return result[0]
    else:
      self.cursor.execute(
        "INSERT INTO services (name, version) VALUES (?, ?)",
        (name, version)
      )
      self.conn.commit()
      return self.cursor.lastrowid

  def upsert_host_port(self, host_id, port_id, status, reason, service_id=None, banner=None):
    self.cursor.execute(
      "SELECT id FROM host_ports WHERE host_id = ? AND port_id = ?",
      (host_id, port_id)
    )
    result = self.cursor.fetchone()
    scan_time = datetime.now().isoformat()
    if result:
      self.cursor.execute("""
        UPDATE host_ports
        SET status = ?, reason = ?, service_id = ?, banner = ?, scan_time = ?
        WHERE host_id = ? AND port_id = ?
      """, (status, reason, service_id, banner, scan_time, host_id, port_id))
    else:
      self.cursor.execute("""
        INSERT INTO host_ports (host_id, port_id, status, reason, service_id, banner, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      """, (host_id, port_id, status, reason, service_id, banner, scan_time))
    self.conn.commit()

  def upsert_os_guess(self, host_id, os_name, method, confidence, notes):
    # self.cursor.execute(
    #   "SELECT id FROM os_guesses WHERE host_id = ? AND method = ?",
    #   (host_id, method)
    # )
    # result = self.cursor.fetchone()
    # if result:
    #   self.cursor.execute("""
    #     UPDATE os_guesses
    #     SET method = ?, confidence = ?, notes = ?
    #     WHERE id = ?
    #   """, (method, confidence, notes, result[0]))
    # else:
    #   self.cursor.execute("""
    #     INSERT INTO os_guesses (host_id, os_name, method, confidence, notes)
    #     VALUES (?, ?, ?, ?, ?)
    #   """, (host_id, os_name, method, confidence, notes))
    # self.conn.commit()

        
    self.cursor.execute(
      "SELECT os_name, method FROM os_guesses WHERE host_id = ?",
      (host_id,)
    )
    result = self.cursor.fetchone()
    if result:
        saved_os_name, saved_method = result
        if saved_method == method and saved_os_name == os_name:
          return  # Same guess already exists, do nothing
        else:
          if confidence is None:
            confidence = "unknown"
          self.cursor.execute("""
            INSERT INTO os_guesses (host_id, os_name, method, confidence, notes)
            VALUES (?, ?, ?, ?, ?)
          """, (host_id, os_name, method, confidence, notes))
          self.conn.commit()



  def clear_all_tables(self):
    """
    Borra todos los datos de las tablas del esquema de la DB.
    Útil para pruebas y reseteos.
    """
    cursor = self.cursor

    # Desactivar temporalmente las llaves foráneas para evitar errores
    cursor.execute("PRAGMA foreign_keys = OFF;")
    
    # Orden correcto: primero las tablas dependientes, luego las independientes
    cursor.execute("DELETE FROM host_ports;")
    cursor.execute("DELETE FROM services;")
    cursor.execute("DELETE FROM ports;")
    cursor.execute("DELETE FROM hosts;")
    
    # Activar de nuevo las llaves foráneas
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # Commit para aplicar los cambios
    self.conn.commit()
    
    # Opcional: liberar espacio en disco
    cursor.execute("VACUUM;")

  def get_ports(self, ip):
    """
    Returns a list of (port, status, service_name)
    for all ports discovered for the given IP.
    """
    self.cursor.execute("""
      SELECT p.port, hp.status, s.name
      FROM host_ports hp
      JOIN hosts h ON hp.host_id = h.id
      JOIN ports p ON hp.port_id = p.id
      LEFT JOIN services s ON hp.service_id = s.id
      WHERE h.ip = ?
      ORDER BY p.port
    """, (ip,))
    return self.cursor.fetchall()

  def report(self, ip):
    self.cursor.execute("""
      SELECT h.ip, p.port, p.protocol, hp.status, hp.reason, s.name, s.version, hp.banner
      FROM host_ports hp
      JOIN hosts h ON hp.host_id = h.id
      JOIN ports p ON hp.port_id = p.id
      LEFT JOIN services s ON hp.service_id = s.id
      WHERE hp.status == "open" or hp.status == "filtered" and h.ip = ?
      ORDER BY h.ip
    """, (ip,))
    report = self.cursor.fetchall()
    print(f"Scan Report for [{ip}]")
    print(f"PORT\tSTATE\t(REASON)\tSERVICE\t")
    for row in report:
      ip, port, protocol, status, reason, service_name, service_version, banner = row
      service_info = f"{service_name} {service_version}" if service_name else "Unknown Service"
      banner_info = f" | Banner: {banner}" if banner else ""
      print(f"{port}/{protocol} - {status} ({reason}) - {service_info}{banner_info}")

    # Report OS guesses for the host
    self.cursor.execute("""
      SELECT os_name, method, confidence, notes
      FROM os_guesses
      JOIN hosts ON os_guesses.host_id = hosts.id
      WHERE hosts.ip = ?
    """, (ip,))
    os_guesses = self.cursor.fetchall()
    if os_guesses:
      print("\nOS Guesses:")
      for os_name, method, confidence, notes in os_guesses:
        print(f"- OS: {os_name}, Method: {method}, Confidence: {confidence}, Notes: {notes}")
    else:
      pass
      # print("\nNo OS guesses found for this host.")

  def close(self):
    self.conn.close()