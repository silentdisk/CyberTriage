"""Unit tests for the rule detection engine."""

import os
import tempfile
import unittest

from src.database.db import Database
from src.detection.engine import DetectionEngine
from src.detection.rules import (
    BruteForceRule,
    PrivilegeEscalationRule,
    SuspiciousLoginRule,
    UnusualAccessRule,
)
from src.events.models import SecurityEvent
from src.events.simulator import EventSimulator


class TestDetectionEngine(unittest.TestCase):
    """Test suite for security rule evaluation and alert creation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_detection.db")
        self.db = Database(self.db_path)
        self.engine = DetectionEngine(self.db)
        self.sim = EventSimulator()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_brute_force_rule_triggers_on_threshold(self) -> None:
        """Verify BruteForceRule triggers when failed attempts reach threshold."""
        rule = BruteForceRule(threshold=5, window_seconds=300)

        # 4 failures -> should not trigger
        events_under = [
            SecurityEvent(
                event_id=f"evt_fail_{i}",
                timestamp=f"2026-11-06T12:0{i}:00Z",
                event_type="auth_failure",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={},
            )
            for i in range(4)
        ]
        alerts_under = rule.evaluate(events_under)
        self.assertEqual(len(alerts_under), 0)

        # 5 failures -> should trigger
        events_over = events_under + [
            SecurityEvent(
                event_id="evt_fail_5",
                timestamp="2026-11-06T12:04:30Z",
                event_type="auth_failure",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={},
            )
        ]
        alerts_over = rule.evaluate(events_over)
        self.assertEqual(len(alerts_over), 1)
        alert = alerts_over[0]
        self.assertEqual(alert.rule_name, "BruteForceLogin")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.entity_user, "admin")
        self.assertEqual(alert.entity_ip, "198.51.100.23")
        self.assertEqual(len(alert.evidence_event_ids), 5)

    def test_privilege_escalation_rule(self) -> None:
        """Verify PrivilegeEscalationRule triggers on escalation events."""
        rule = PrivilegeEscalationRule()
        events = self.sim.generate_privilege_escalation(
            user="alice",
            src_ip="10.0.1.42",
            target_host="workstation-01",
        )
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_name, "PrivilegeEscalationAttempt")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.entity_user, "alice")
        self.assertTrue(len(alert.evidence_event_ids) >= 1)

    def test_suspicious_login_rule(self) -> None:
        """Verify SuspiciousLoginRule flags high-risk IPs."""
        rule = SuspiciousLoginRule()
        events = self.sim.generate_suspicious_login(
            user="svc_backup",
            attacker_ip="203.0.113.99",
        )
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_name, "SuspiciousLoginPattern")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.entity_ip, "203.0.113.99")

    def test_unusual_access_rule(self) -> None:
        """Verify UnusualAccessRule detects sensitive file access."""
        rule = UnusualAccessRule()
        events = self.sim.generate_unusual_access(user="david")
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_name, "UnusualSensitiveAccess")

    def test_engine_deduplication(self) -> None:
        """Requirement test: verify that duplicate alerts are not created on re-runs."""
        events = self.sim.generate_scenario("all")
        self.db.insert_events(events)

        # First run: should detect new alerts
        first_run_alerts = self.engine.run_detection()
        self.assertTrue(len(first_run_alerts) > 0)
        first_count = len(first_run_alerts)

        # Second run: same events, should detect ZERO new alerts (deduplication)
        second_run_alerts = self.engine.run_detection()
        self.assertEqual(
            len(second_run_alerts),
            0,
            "Re-running detection without new events must not generate duplicate alerts",
        )

        # Total alerts stored in database should equal first_count
        db_alerts = self.db.get_alerts()
        self.assertEqual(len(db_alerts), first_count)

    # -------------------------------------------------------------------------
    # Regression Tests: PrivilegeEscalationRule operator precedence bug
    # -------------------------------------------------------------------------

    def test_privilege_escalation_unrelated_events_with_technique_field(self) -> None:
        """Regression test: unrelated events containing a 'technique' key must NOT be classified as privilege escalation."""
        rule = PrivilegeEscalationRule()
        unrelated_events = [
            SecurityEvent(
                event_id="evt_net_01",
                timestamp="2026-11-06T12:00:00Z",
                event_type="network_probe",
                user="external_scanner",
                src_ip="198.51.100.5",
                hostname="bastion-host",
                action="port_scan",
                details={"technique": "T1046_network_service_discovery", "tool": "nmap"},
            ),
            SecurityEvent(
                event_id="evt_file_01",
                timestamp="2026-11-06T12:01:00Z",
                event_type="file_access",
                user="bob",
                src_ip="10.0.1.15",
                hostname="workstation-01",
                action="read_log",
                details={"technique": "T1005_data_from_local_system", "file": "/var/log/syslog"},
            ),
            SecurityEvent(
                event_id="evt_auth_01",
                timestamp="2026-11-06T12:02:00Z",
                event_type="auth_failure",
                user="alice",
                src_ip="10.0.1.42",
                hostname="workstation-01",
                action="ssh_login",
                details={"technique": "T1110_brute_force"},
            ),
        ]
        alerts = rule.evaluate(unrelated_events)
        self.assertEqual(
            len(alerts),
            0,
            "Unrelated events with a 'technique' field must not trigger PrivilegeEscalationRule",
        )

    def test_privilege_escalation_supported_action_without_evidence_ignored(self) -> None:
        """Verify that supported actions without valid elevation evidence do not trigger an alert."""
        rule = PrivilegeEscalationRule()
        benign_sudo = [
            SecurityEvent(
                event_id="evt_sudo_01",
                timestamp="2026-11-06T12:00:00Z",
                event_type="process_exec",
                user="alice",
                src_ip="10.0.1.42",
                hostname="workstation-01",
                action="sudo_exec",
                details={},  # No elevation_type or technique evidence
            )
        ]
        alerts = rule.evaluate(benign_sudo)
        self.assertEqual(len(alerts), 0)

    def test_privilege_escalation_supported_action_with_evidence_triggers(self) -> None:
        """Verify that supported actions with elevation evidence properly trigger an alert."""
        rule = PrivilegeEscalationRule()
        valid_escalation = [
            SecurityEvent(
                event_id="evt_sudo_valid",
                timestamp="2026-11-06T12:00:00Z",
                event_type="process_exec",
                user="alice",
                src_ip="10.0.1.42",
                hostname="workstation-01",
                action="sudo_exec",
                details={"command": "sudo -i", "elevation_type": "interactive_root_shell"},
            )
        ]
        alerts = rule.evaluate(valid_escalation)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertEqual(alerts[0].entity_user, "alice")

    # -------------------------------------------------------------------------
    # Regression Tests: SuspiciousLoginRule temporal correlation & window
    # -------------------------------------------------------------------------

    def test_suspicious_login_failed_before_success_escalates_to_critical(self) -> None:
        """Regression test: failed login occurring BEFORE success within 300s window escalates alert to CRITICAL."""
        rule = SuspiciousLoginRule(failure_window_seconds=300)
        events = [
            # Failure at T=12:00:00 from suspicious IP
            SecurityEvent(
                event_id="evt_fail_prior",
                timestamp="2026-11-06T12:00:00Z",
                event_type="auth_failure",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "failure"},
            ),
            # Success at T=12:02:00 (120s later, within 300s window) from same IP
            SecurityEvent(
                event_id="evt_success_after",
                timestamp="2026-11-06T12:02:00Z",
                event_type="auth_success",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "success"},
            ),
        ]
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertTrue(alert.details.get("followed_failures"))
        self.assertIn("following previous authentication failures", alert.description)

    def test_suspicious_login_failed_after_success_never_escalates(self) -> None:
        """Regression test: future failed logins must NEVER escalate a past successful login."""
        rule = SuspiciousLoginRule(failure_window_seconds=300)
        events = [
            # Success at T=12:00:00 from suspicious IP
            SecurityEvent(
                event_id="evt_success_first",
                timestamp="2026-11-06T12:00:00Z",
                event_type="auth_success",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "success"},
            ),
            # Failed login at T=12:02:00 (FUTURE failure, 120s after success!)
            SecurityEvent(
                event_id="evt_fail_future",
                timestamp="2026-11-06T12:02:00Z",
                event_type="auth_failure",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "failure"},
            ),
        ]
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        # Must NOT be escalated to CRITICAL
        self.assertEqual(
            alert.severity,
            "HIGH",
            "A past successful login must not be escalated to CRITICAL by a future failed login",
        )
        self.assertFalse(alert.details.get("followed_failures"))
        self.assertNotIn("following previous authentication failures", alert.description)

    def test_suspicious_login_failed_outside_300s_window_does_not_escalate(self) -> None:
        """Regression test: failed login occurring outside the 300-second window must NOT escalate alert."""
        rule = SuspiciousLoginRule(failure_window_seconds=300)
        events = [
            # Failure at T=12:00:00
            SecurityEvent(
                event_id="evt_fail_old",
                timestamp="2026-11-06T12:00:00Z",
                event_type="auth_failure",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "failure"},
            ),
            # Success at T=12:06:00 (360 seconds later, > 300s window)
            SecurityEvent(
                event_id="evt_success_late",
                timestamp="2026-11-06T12:06:00Z",
                event_type="auth_success",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "success"},
            ),
        ]
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        # Diff is 360s > 300s, so it must NOT escalate to CRITICAL
        self.assertEqual(
            alert.severity,
            "HIGH",
            "Failed login outside 300s window must not escalate suspicious login to CRITICAL",
        )
        self.assertFalse(alert.details.get("followed_failures"))

    def test_suspicious_login_different_ip_does_not_escalate(self) -> None:
        """Regression test: failed login from a different IP must not correlate."""
        rule = SuspiciousLoginRule(failure_window_seconds=300)
        events = [
            # Failure at T=12:00:00 from IP 10.0.1.99
            SecurityEvent(
                event_id="evt_fail_diff_ip",
                timestamp="2026-11-06T12:00:00Z",
                event_type="auth_failure",
                user="admin",
                src_ip="10.0.1.99",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "failure"},
            ),
            # Success at T=12:01:00 from suspicious IP 198.51.100.23
            SecurityEvent(
                event_id="evt_success_diff_ip",
                timestamp="2026-11-06T12:01:00Z",
                event_type="auth_success",
                user="admin",
                src_ip="198.51.100.23",
                hostname="bastion-host",
                action="ssh_login",
                details={"status": "success"},
            ),
        ]
        alerts = rule.evaluate(events)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.severity, "HIGH")
        self.assertFalse(alert.details.get("followed_failures"))


if __name__ == "__main__":
    unittest.main()
