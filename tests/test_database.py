"""Unit tests for the SQLite database layer."""

import os
import tempfile
import unittest

from src.database.db import Database
from src.database.models import Alert
from src.events.models import SecurityEvent


class TestDatabase(unittest.TestCase):
    """Test suite for SQLite operations."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_cybertriage.db")
        self.db = Database(self.db_path)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_tables_created_on_startup(self) -> None:
        """Verify events and alerts tables are created on initialization."""
        with self.db._connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row["name"] for row in cursor.fetchall()}
            self.assertIn("events", tables)
            self.assertIn("alerts", tables)

    def test_insert_and_get_event(self) -> None:
        """Verify inserting an event and fetching it by ID."""
        event = SecurityEvent(
            event_id="evt_test001",
            timestamp="2026-11-06T12:00:00Z",
            event_type="auth_failure",
            user="admin",
            src_ip="198.51.100.23",
            hostname="bastion-host",
            action="ssh_login",
            details={"reason": "bad_password"},
            is_simulated=True,
        )
        self.db.insert_event(event)

        retrieved = self.db.get_event("evt_test001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.event_id, "evt_test001")
        self.assertEqual(retrieved.user, "admin")
        self.assertEqual(retrieved.src_ip, "198.51.100.23")
        self.assertEqual(retrieved.details.get("reason"), "bad_password")
        self.assertTrue(retrieved.is_simulated)

    def test_insert_events_batch_and_filtering(self) -> None:
        """Verify batch inserting events and querying with filters."""
        events = [
            SecurityEvent(
                event_id=f"evt_batch_{i}",
                timestamp=f"2026-11-06T12:0{i}:00Z",
                event_type="auth_failure" if i < 3 else "auth_success",
                user="alice" if i % 2 == 0 else "bob",
                src_ip="10.0.1.15",
                hostname="workstation-01",
                action="ssh_login",
                details={},
                is_simulated=True,
            )
            for i in range(5)
        ]
        inserted = self.db.insert_events(events)
        self.assertEqual(inserted, 5)

        # Filter by event_type
        failures = self.db.get_events(event_type="auth_failure")
        self.assertEqual(len(failures), 3)

        # Filter by user
        alice_events = self.db.get_events(user="alice")
        self.assertEqual(len(alice_events), 3)

    def test_insert_and_get_alert(self) -> None:
        """Verify inserting and querying alerts."""
        alert = Alert(
            alert_id="alt_test001",
            rule_name="BruteForceLogin",
            severity="HIGH",
            title="Brute Force Detected",
            description="5 failed logins from 198.51.100.23",
            timestamp="2026-11-06T12:05:00Z",
            evidence_event_ids=["evt_01", "evt_02"],
            entity_user="admin",
            entity_ip="198.51.100.23",
            entity_host="bastion-host",
            status="NEW",
            details={"attempts": 5},
        )
        self.db.insert_alert(alert)

        retrieved = self.db.get_alert("alt_test001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.alert_id, "alt_test001")
        self.assertEqual(retrieved.severity, "HIGH")
        self.assertEqual(retrieved.evidence_event_ids, ["evt_01", "evt_02"])

    def test_alert_exists_with_evidence_deduplication(self) -> None:
        """Verify that duplicate evidence detection identifies existing alerts."""
        alert = Alert(
            alert_id="alt_dedup_01",
            rule_name="BruteForceLogin",
            severity="HIGH",
            title="Brute Force",
            description="Testing deduplication",
            timestamp="2026-11-06T12:00:00Z",
            evidence_event_ids=["evt_a", "evt_b", "evt_c"],
        )
        self.db.insert_alert(alert)

        # Exact overlap
        self.assertTrue(
            self.db.alert_exists_with_evidence("BruteForceLogin", ["evt_a", "evt_b"])
        )
        # Partial overlap
        self.assertTrue(
            self.db.alert_exists_with_evidence("BruteForceLogin", ["evt_c", "evt_x"])
        )
        # No overlap
        self.assertFalse(
            self.db.alert_exists_with_evidence("BruteForceLogin", ["evt_x", "evt_y"])
        )
        # Different rule name
        self.assertFalse(
            self.db.alert_exists_with_evidence("PrivilegeEscalation", ["evt_a", "evt_b"])
        )


if __name__ == "__main__":
    unittest.main()
