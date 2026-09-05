import sqlite3

DB_PATH = "/home/pi/rpi-router-api/router.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
ALTER TABLE users
ADD COLUMN access_mode TEXT DEFAULT 'schedule'
""")

conn.commit()
conn.close()

print("Database updated")
