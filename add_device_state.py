import sqlite3

DB_PATH = "/home/pi/rpi-router-api/router.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS device_state (
    mac TEXT PRIMARY KEY,
    device_name TEXT,
    user_name TEXT,
    action TEXT NOT NULL,
    reason TEXT,
    timestamp TEXT NOT NULL
)
""")

conn.commit()
conn.close()

print("device_state table created")
