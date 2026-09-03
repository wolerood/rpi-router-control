import sqlite3

DB_PATH = "/home/pi/rpi-router-api/router.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_mac TEXT NOT NULL,
    device_name TEXT,
    user_name TEXT,
    action TEXT NOT NULL,
    reason TEXT,
    timestamp TEXT NOT NULL
)
""")

conn.commit()
conn.close()

print("access_log table created")
