import os
import sqlite3

from access_policy import normalize_mac


DB_PATH = os.environ.get(
    "RPI_ROUTER_DB_PATH",
    "/home/pi/rpi-router-api/router.db",
)
SCHEMA_VERSION = 1


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _column_names(cur, table):
    return {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}


def _normalize_existing_devices(cur):
    rows = cur.execute("SELECT id, mac FROM devices ORDER BY id").fetchall()
    seen = {}

    for device_id, stored_mac in rows:
        try:
            normalized_mac = normalize_mac(stored_mac)
        except ValueError as error:
            raise RuntimeError(
                f"device {device_id} has invalid MAC {stored_mac!r}: {error}"
            ) from error

        previous_id = seen.get(normalized_mac)
        if previous_id is not None:
            raise RuntimeError(
                f"devices {previous_id} and {device_id} have duplicate MAC "
                f"{normalized_mac}"
            )

        seen[normalized_mac] = device_id
        if stored_mac != normalized_mac:
            cur.execute(
                "UPDATE devices SET mac = ? WHERE id = ?",
                (normalized_mac, device_id),
            )


def init_database(db_path=None):
    """Create or migrate the database to the current schema."""
    conn = get_connection(db_path)

    try:
        # WAL lets the API and the timer service coexist with fewer lock errors.
        conn.execute("PRAGMA journal_mode = WAL")
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                access_mode TEXT NOT NULL DEFAULT 'schedule'
                    CHECK (access_mode IN (
                        'schedule',
                        'always_allow',
                        'always_block'
                    ))
            )
        """)

        # Migration from the original schema.
        if "access_mode" not in _column_names(cur, "users"):
            cur.execute("""
                ALTER TABLE users
                ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'schedule'
            """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                mac TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                weekday INTEGER NOT NULL CHECK (weekday BETWEEN 1 AND 7),
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
            )
        """)

        _normalize_existing_devices(cur)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                device_name TEXT,
                user_name TEXT,
                action TEXT NOT NULL CHECK (action IN ('ALLOW', 'BLOCK')),
                reason TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_state (
                mac TEXT PRIMARY KEY COLLATE NOCASE,
                device_name TEXT,
                user_name TEXT,
                action TEXT NOT NULL CHECK (action IN ('ALLOW', 'BLOCK')),
                reason TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_schedules_user_weekday
            ON schedules(user_id, weekday, start_time)
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac_normalized
            ON devices(lower(mac))
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_access_log_timestamp
            ON access_log(timestamp)
        """)

        cur.execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        cur.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_database()
    print(f"Database initialized at schema version {SCHEMA_VERSION}")
