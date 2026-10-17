import json
import unittest

from firewall import parse_blocked_macs


class FirewallParsingTests(unittest.TestCase):
    def test_parses_nft_json_set(self):
        payload = json.dumps({
            "nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {"set": {"elem": ["CA:EF:D8:95:11:B5"]}},
            ]
        })
        self.assertEqual(
            parse_blocked_macs(payload),
            {"ca:ef:d8:95:11:b5"},
        )

    def test_empty_set(self):
        payload = json.dumps({"nftables": [{"set": {"elem": []}}]})
        self.assertEqual(parse_blocked_macs(payload), set())


if __name__ == "__main__":
    unittest.main()
