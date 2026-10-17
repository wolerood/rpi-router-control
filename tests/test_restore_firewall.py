import sqlite3
import unittest
from unittest.mock import patch

import restore_firewall


class RestoreFirewallTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript(
            """
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY,
                mac TEXT NOT NULL
            );
            CREATE TABLE device_state (
                mac TEXT PRIMARY KEY,
                action TEXT NOT NULL
            );
            """
        )

    def tearDown(self):
        self.conn.close()

    def test_only_registered_blocked_devices_are_restored(self):
        self.conn.executemany(
            "INSERT INTO devices(id, mac) VALUES (?, ?)",
            [
                (1, "AA:BB:CC:DD:EE:01"),
                (2, "aa:bb:cc:dd:ee:02"),
            ],
        )
        self.conn.executemany(
            "INSERT INTO device_state(mac, action) VALUES (?, ?)",
            [
                ("aa:bb:cc:dd:ee:01", "BLOCK"),
                ("aa:bb:cc:dd:ee:02", "ALLOW"),
                ("aa:bb:cc:dd:ee:03", "BLOCK"),
            ],
        )

        result = restore_firewall.get_last_blocked_macs(self.conn.cursor())

        self.assertEqual(result, {"aa:bb:cc:dd:ee:01"})

    @patch("restore_firewall.block_mac")
    @patch("restore_firewall.get_blocked_macs")
    @patch("restore_firewall.get_connection")
    def test_restore_adds_only_missing_macs(
        self,
        get_connection,
        get_blocked_macs,
        block_mac,
    ):
        self.conn.executemany(
            "INSERT INTO devices(id, mac) VALUES (?, ?)",
            [
                (1, "aa:bb:cc:dd:ee:01"),
                (2, "aa:bb:cc:dd:ee:02"),
            ],
        )
        self.conn.executemany(
            "INSERT INTO device_state(mac, action) VALUES (?, 'BLOCK')",
            [
                ("aa:bb:cc:dd:ee:01",),
                ("aa:bb:cc:dd:ee:02",),
            ],
        )
        self.conn.commit()
        get_connection.return_value = self.conn
        get_blocked_macs.return_value = {"aa:bb:cc:dd:ee:01"}

        restored = restore_firewall.restore_firewall()

        self.assertEqual(restored, 1)
        block_mac.assert_called_once_with("aa:bb:cc:dd:ee:02")
