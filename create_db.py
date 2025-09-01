import sqlite3

# Crear conexión a la base de datos (la crea si no existe)
conn = sqlite3.connect("scan.db")

# Leer el archivo .sql
with open("create_db.sql", "r") as f:
    sql_script = f.read()

# Ejecutar el script SQL
cursor = conn.cursor()
cursor.executescript(sql_script)
conn.commit()
conn.close()

print("Base de datos creada exitosamente.")