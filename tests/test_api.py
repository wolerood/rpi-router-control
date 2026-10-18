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
        self.original_api_token = app_module.app.config.get("API_TOKEN")
        app_module.app.config["API_TOKEN"] = "test-token"
        self.auth_headers = {"X-API-Token": "test-token"}
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.connection_patch.stop()
        app_module.app.config["API_TOKEN"] = self.original_api_token
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
        self.assertEqual(payload["api_version"], 2)
        self.assertEqual(
            payload["write_auth"],
            {"configured": True, "mode": "token"},
        )
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
            headers=self.auth_headers,
            json={
                "user_id": self.user_id,
                "mac": "02-11-22-33-44-55",
                "name": "Tablet",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["mac"], "02:11:22:33:44:55")

    def test_clients_include_wifi_station_without_dhcp_lease(self):
        dhcp_client = {
            "mac": "ca:ef:d8:95:11:b5",
            "ip": "192.168.50.10",
            "name": "phone",
        }
        wifi_only_mac = "02:11:22:33:44:55"

        with (
            patch.object(app_module, "get_dhcp_clients", return_value=[dhcp_client]),
            patch.object(
                app_module,
                "get_wifi_clients",
                return_value={dhcp_client["mac"], wifi_only_mac},
            ),
        ):
            response = self.client.get("/clients")

        self.assertEqual(response.status_code, 200)
        clients = {client["mac"]: client for client in response.get_json()}
        self.assertEqual(len(clients), 2)
        self.assertTrue(clients[wifi_only_mac]["online"])
        self.assertIsNone(clients[wifi_only_mac]["ip"])
        self.assertEqual(clients[wifi_only_mac]["name"], wifi_only_mac)

    def test_clients_merge_wifi_and_dhcp_entries_by_mac(self):
        dhcp_client = {
            "mac": "CA:EF:D8:95:11:B5",
            "ip": "192.168.50.10",
            "name": "phone",
        }

        with (
            patch.object(app_module, "get_dhcp_clients", return_value=[dhcp_client]),
            patch.object(
                app_module,
                "get_wifi_clients",
                return_value={"ca:ef:d8:95:11:b5"},
            ),
        ):
            response = self.client.get("/clients")

        clients = response.get_json()
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["mac"], "ca:ef:d8:95:11:b5")
        self.assertTrue(clients[0]["online"])

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
            response = self.client.delete(
                f"/devices/{self.device_id}",
                headers=self.auth_headers,
            )

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

    def test_write_requests_require_valid_token(self):
        missing = self.client.post("/users", json={"name": "Blocked"})
        wrong = self.client.post(
            "/users",
            headers={"X-API-Token": "wrong"},
            json={"name": "Blocked"},
        )
        allowed = self.client.post(
            "/users",
            headers=self.auth_headers,
            json={"name": "Allowed"},
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(allowed.status_code, 200)

    def test_write_requests_fail_closed_without_server_token(self):
        app_module.app.config["API_TOKEN"] = ""

        response = self.client.post("/users", json={"name": "Blocked"})
        status_response = self.client.get("/status")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(status_response.status_code, 503)
        self.assertFalse(status_response.get_json()["write_auth"]["configured"])


if __name__ == "__main__":
    unittest.main()
