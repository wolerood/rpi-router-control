import unittest

from access_policy import evaluate_access, is_valid_time, normalize_mac


class NormalizeMacTests(unittest.TestCase):
    def test_normalizes_common_formats(self):
        expected = "ca:ef:d8:95:11:b5"
        self.assertEqual(normalize_mac("CA:EF:D8:95:11:B5"), expected)
        self.assertEqual(normalize_mac("ca-ef-d8-95-11-b5"), expected)
        self.assertEqual(normalize_mac("caef.d895.11b5"), expected)

    def test_rejects_invalid_addresses(self):
        for value in (None, "", "not-a-mac", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_mac(value)


class TimeValidationTests(unittest.TestCase):
    def test_requires_zero_padded_24_hour_time(self):
        for value in ("00:00", "07:05", "23:59"):
            self.assertTrue(is_valid_time(value))

        for value in ("7:05", "24:00", "12:60", None):
            self.assertFalse(is_valid_time(value))


class AccessPolicyTests(unittest.TestCase):
    def test_manual_modes_override_schedules(self):
        schedules = [(1, "08:00", "09:00")]
        self.assertEqual(
            evaluate_access("always_allow", schedules, 1, "23:00"),
            (True, "manual allow"),
        )
        self.assertEqual(
            evaluate_access("always_block", schedules, 1, "08:30"),
            (False, "manual block"),
        )

    def test_regular_interval_includes_both_boundaries(self):
        schedules = [(1, "07:00", "21:00")]
        self.assertTrue(evaluate_access("schedule", schedules, 1, "07:00")[0])
        self.assertTrue(evaluate_access("schedule", schedules, 1, "21:00")[0])
        self.assertFalse(evaluate_access("schedule", schedules, 1, "21:01")[0])

    def test_overnight_interval_on_starting_day(self):
        schedules = [(5, "22:00", "07:00")]
        self.assertTrue(evaluate_access("schedule", schedules, 5, "23:30")[0])

    def test_overnight_interval_on_following_day(self):
        schedules = [(5, "22:00", "07:00")]
        self.assertTrue(evaluate_access("schedule", schedules, 6, "06:59")[0])
        self.assertFalse(evaluate_access("schedule", schedules, 6, "07:01")[0])

    def test_overnight_interval_wraps_sunday_to_monday(self):
        schedules = [(7, "22:00", "07:00")]
        self.assertTrue(evaluate_access("schedule", schedules, 1, "06:30")[0])

    def test_empty_schedule_blocks(self):
        self.assertEqual(
            evaluate_access("schedule", [], 3, "12:00"),
            (False, "outside schedule"),
        )

    def test_invalid_data_does_not_change_firewall_decision(self):
        self.assertEqual(
            evaluate_access("unexpected", [], 3, "12:00"),
            (None, "invalid access_mode: unexpected"),
        )
        self.assertEqual(
            evaluate_access("schedule", [(3, "99:00", "12:00")], 3, "11:00"),
            (None, "invalid schedule data"),
        )


if __name__ == "__main__":
    unittest.main()
