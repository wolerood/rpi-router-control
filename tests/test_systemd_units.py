import unittest
from pathlib import Path


class SystemdTimerTests(unittest.TestCase):
    def test_schedule_timer_has_guaranteed_first_and_recurring_runs(self):
        project_root = Path(__file__).resolve().parents[1]
        timer = (
            project_root / "deploy" / "systemd" / "rpi-schedule-engine.timer"
        ).read_text(encoding="utf-8")

        self.assertIn("OnActiveSec=5s", timer)
        self.assertIn("OnUnitActiveSec=60s", timer)
        self.assertNotIn("OnBootSec=", timer)
        self.assertNotIn("OnUnitInactiveSec=", timer)
        self.assertNotIn("Persistent=", timer)


if __name__ == "__main__":
    unittest.main()
