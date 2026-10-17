import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import schedule_engine
from database import get_connection, init_database


class ScheduleEngineTests(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).parent / ".tmp"
        temp_root.mkdir(exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=temp_root)
        self.db_path = Path(self.temp_dir.name) / "router.db"
        self.log_path = Path(self.temp_dir.name) / "access.log"
        init_database(self.db_path)

        conn = get_connection(self.db_path)
        try:
            user_id = conn.execute(
                "INSERT INTO users(name, access_mode) VALUES (?, ?)",
                ("User", "always_allow"),
            ).lastrowid
            conn.execute(
                "INSERT INTO devices(user_id, mac, name) VALUES (?, ?, ?)",
                (user_id, "CA-EF-D8-95-11-B5", "Phone"),
            )
            conn.execute(
                """
                INSERT INTO device_state(
                    mac, device_name, user_name, action, reason, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "00:11:22:33:44:66",
                    "Old device",
                    "Old user",
                    "BLOCK",
                    "outside schedule",
                    "2026-01-01 00:00:00",
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_reconciles_firewall_and_removes_stale_state(self):
        allowed_macs = []

        with (
            patch.object(schedule_engine, "init_database"),
            patch.object(
                schedule_engine,
                "get_connection",
                side_effect=lambda: get_connection(self.db_path),
            ),
            patch.object(
                schedule_engine,
                "get_blocked_macs",
                return_value={
                    "ca:ef:d8:95:11:b5",
                    "00:11:22:33:44:66",
                },
            ),
            patch.object(
                schedule_engine,
                "allow_mac",
                side_effect=allowed_macs.append,
            ),
            patch.object(schedule_engine, "LOG_FILE", str(self.log_path)),
        ):
            self.assertEqual(schedule_engine.main(), 0)

        self.assertEqual(
            set(allowed_macs),
            {"ca:ef:d8:95:11:b5", "00:11:22:33:44:66"},
        )

        conn = get_connection(self.db_path)
        try:
            states = conn.execute(
                "SELECT lower(mac), action, reason FROM device_state"
            ).fetchall()
            self.assertEqual(
                states,
                [("ca:ef:d8:95:11:b5", "ALLOW", "manual allow")],
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM access_log").fetchone()[0],
                1,
            )
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
