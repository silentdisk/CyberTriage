"""Unit tests for the event simulator."""

import unittest

from src.events.models import SecurityEvent
from src.events.simulator import EventSimulator


class TestEventSimulator(unittest.TestCase):
    """Test suite for synthetic event generation."""

    def setUp(self) -> None:
        self.sim = EventSimulator()

    def test_all_events_labeled_as_simulated(self) -> None:
        """Requirement test: verify all generated events are explicitly labeled as simulated."""
        events = self.sim.generate_scenario("all")
        self.assertTrue(len(events) > 0)
        for ev in events:
            self.assertIsInstance(ev, SecurityEvent)
            self.assertTrue(
                ev.is_simulated,
                f"Event {ev.event_id} must have is_simulated=True",
            )

    def test_generate_benign(self) -> None:
        """Verify benign event generation contains normal logins and valid fields."""
        events = self.sim.generate_benign(count=10)
        self.assertEqual(len(events), 10)
        for e in events:
            self.assertTrue(e.event_id.startswith("evt_"))
            self.assertIn(e.event_type, ("auth_success", "auth_failure"))
            self.assertTrue(len(e.user) > 0)
            self.assertTrue(len(e.src_ip) > 0)

    def test_generate_brute_force_scenario(self) -> None:
        """Verify brute force generation creates sequential rapid failures."""
        events = self.sim.generate_brute_force(
            target_user="admin",
            attacker_ip="198.51.100.23",
            attempt_count=6,
        )
        self.assertEqual(len(events), 6)
        for i, e in enumerate(events, 1):
            self.assertEqual(e.event_type, "auth_failure")
            self.assertEqual(e.user, "admin")
            self.assertEqual(e.src_ip, "198.51.100.23")
            self.assertEqual(e.details.get("attempt"), i)

    def test_generate_privilege_escalation_scenario(self) -> None:
        """Verify privilege escalation events contain suspicious commands."""
        events = self.sim.generate_privilege_escalation(
            user="alice",
            src_ip="10.0.1.42",
            target_host="workstation-01",
        )
        self.assertTrue(len(events) >= 3)
        commands = [e.details.get("command") for e in events]
        self.assertTrue(any("sudo" in cmd for cmd in commands if cmd))

    def test_generate_suspicious_login(self) -> None:
        """Verify suspicious login has threat intel / anomalous IP flags."""
        events = self.sim.generate_suspicious_login(
            user="svc_backup",
            attacker_ip="203.0.113.99",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "auth_success")
        self.assertEqual(events[0].src_ip, "203.0.113.99")
        self.assertIn("threat_intel", events[0].details)


if __name__ == "__main__":
    unittest.main()
