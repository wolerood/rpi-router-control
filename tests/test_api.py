import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database import get_connection, init_database


FLASK_AVAILABLE = importlib.util.find_spec("flask") is not None

if FLASK_AVAILABLE:
    import app as app_module


@unittest.skipUnless(FLASK_AVAILABLE, "Flask is not installed")
class ApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).parent / ".tmp"
        temp_root.mkdir(exist_ok=True)
        self.temp_dir = tempfile.TemporaryDirectory(dir=temp_root)
        self.db_path = Path(self.temp_dir.name) / "router.db"
        init_database(self.db_path)

        conn = get_connection(self.db_path)
        try:
            self.user_id = conn.execute(
                "INSERT INTO users(name, access_mode) VALUES (?, ?)",
                ("Test user", "always_allow"),
            ).lastrowid
            self.device_id = conn.execute(
                "INSERT INTO devices(user_id, mac, name) VALUES (?, ?, ?)",
                (self.user_id, "ca:ef:d8:95:11:b5", "Phone"),
            ).lastrowid
            conn.commit()
        finally:
            conn.close()

        self.connection_patch = patch.object(
            app_module,
            "get_connection",
            side_effect=lambda: get_connection(self.db_path),
        )
        self.connection_patch.start()
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.connection_patch.stop()
        self.temp_dir.cleanup()

    def test_reads_users_and_shared_access_policy(self):
        users_response = self.client.get("/users")
        self.assertEqual(users_response.status_code, 200)
        self.assertEqual(users_response.get_json()[0]["access_mode"], "always_allow")

        access_response = self.client.get(f"/access/{self.user_id}")
        self.assertEqual(access_response.status_code, 200)
        self.assertTrue(access_response.get_json()["allowed"])

    def test_status_reports_database_and_firewall_health(self):
        with patch.object(
            app_module,
            "get_blocked_macs",
            return_value={"ca:ef:d8:95:11:b5"},
        ):
            response = self.client.get("/status")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["api_version"], 1)
        self.assertEqual(payload["database"]["users"], 1)
        self.assertEqual(payload["database"]["devices"], 1)
        self.assertEqual(payload["firewall"]["blocked_devices"], 1)

    def test_status_is_degraded_when_firewall_is_unavailable(self):
        with patch.object(
            app_module,
            "get_blocked_macs",
            side_effect=app_module.FirewallError("nft failed"),
        ):
            response = self.client.get("/status")

        self.assertEqual(response.status_code, 503)
        payload = response.get_json()
        self.assertEqual(payload["status"], "degraded")
        self.assertTrue(payload["database"]["ok"])
        self.assertFalse(payload["firewall"]["ok"])

    def test_creating_device_normalizes_mac(self):
        response = self.client.post(
            "/devices",
            json={
                "user_id": self.user_id,
                "mac": "02-11-22-33-44-55",
                "name": "Tablet",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["mac"], "02:11:22:33:44:55")

    def test_reports_actual_firewall_state(self):
        with patch.object(
            app_module,
            "get_blocked_macs",
            return_value={"ca:ef:d8:95:11:b5"},
        ):
            response = self.client.get("/devices/state")

        self.assertEqual(response.status_code, 200)
        state = response.get_json()[0]
        self.assertEqual(state["actual_action"], "BLOCK")
        self.assertFalse(state["in_sync"])

    def test_deleting_blocked_device_cleans_firewall_and_state(self):
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO device_state(
                    mac, device_name, user_name, action, reason, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "ca:ef:d8:95:11:b5",
                    "Phone",
                    "Test user",
                    "BLOCK",
                    "manual block",
                    "2026-10-17 20:00:00",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        with (
            patch.object(
                app_module,
                "get_blocked_macs",
                return_value={"ca:ef:d8:95:11:b5"},
            ),
            patch.object(app_module, "allow_mac") as allow_mac,
        ):
            response = self.client.delete(f"/devices/{self.device_id}")

        self.assertEqual(response.status_code, 200)
        allow_mac.assert_called_once_with("ca:ef:d8:95:11:b5")

        conn = get_connection(self.db_path)
        try:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM devices").fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM device_state").fetchone()[0],
                0,
            )
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
