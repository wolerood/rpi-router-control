import sqlite3
import tempfile
import unittest
from pathlib import Path

from database import SCHEMA_VERSION, get_connection, init_database


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).parent / ".tmp"
        temp_root.mkdir(exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=temp_root)
        self.db_path = Path(self.temp_dir.name) / "router.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_creates_complete_schema_and_is_idempotent(self):
        init_database(self.db_path)
        init_database(self.db_path)

        conn = get_connection(self.db_path)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue(
                {
                    "users",
                    "devices",
                    "schedules",
                    "access_log",
                    "device_state",
                    "schema_migrations",
                }.issubset(tables)
            )
            self.assertEqual(
                conn.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            self.assertEqual(
                conn.execute("PRAGMA journal_mode").fetchone()[0],
                "wal",
            )
        finally:
            conn.close()

    def test_migrates_original_users_table(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO users(name) VALUES ('Test')")
        conn.commit()
        conn.close()

        init_database(self.db_path)

        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT name, access_mode FROM users"
            ).fetchone()
            self.assertEqual(row, ("Test", "schedule"))
        finally:
            conn.close()

    def test_normalizes_existing_device_mac(self):
        init_database(self.db_path)
        conn = get_connection(self.db_path)
        try:
            user_id = conn.execute(
                "INSERT INTO users(name) VALUES ('Test')"
            ).lastrowid
            conn.execute(
                "INSERT INTO devices(user_id, mac, name) VALUES (?, ?, ?)",
                (user_id, "CA-EF-D8-95-11-B5", "Phone"),
            )
            conn.commit()
        finally:
            conn.close()

        init_database(self.db_path)

        conn = get_connection(self.db_path)
        try:
            self.assertEqual(
                conn.execute("SELECT mac FROM devices").fetchone()[0],
                "ca:ef:d8:95:11:b5",
            )
        finally:
            conn.close()

    def test_rejects_case_variant_duplicate_mac(self):
        init_database(self.db_path)
        conn = get_connection(self.db_path)
        try:
            user_id = conn.execute(
                "INSERT INTO users(name) VALUES ('Test')"
            ).lastrowid
            conn.execute(
                "INSERT INTO devices(user_id, mac, name) VALUES (?, ?, ?)",
                (user_id, "ca:ef:d8:95:11:b5", "Phone"),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO devices(user_id, mac, name) VALUES (?, ?, ?)",
                    (user_id, "CA:EF:D8:95:11:B5", "Duplicate"),
                )
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
