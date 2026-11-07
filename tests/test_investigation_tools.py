"""Unit tests for controlled Python investigation tools in CyberTriage.

Verifies parameterized evidence retrieval, strict input validation, bounds checking,
explicit simulation labeling, and tool execution dispatch against SQLite.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from src.agents.investigation_tools import (
    DEFAULT_EVIDENCE_LIMIT,
    DEFAULT_SEARCH_LIMIT,
    MAX_ALERT_ID_LENGTH,
    MAX_EVIDENCE_LIMIT,
    MAX_SEARCH_LIMIT,
    execute_tool,
    get_alert,
    get_alert_evidence,
    list_alerts,
    search_events,
    validate_alert_id,
)
from src.database.db import Database
from src.database.models import Alert
from src.events.models import SecurityEvent


class TestInvestigationTools(unittest.TestCase):
    """Test suite for controlled SOC investigation tools."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_soc.db")
        self.db = Database(self.db_path)

        # Seed database with sample telemetry and alerts
        self._seed_database()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _seed_database(self) -> None:
        # Seed 3 events
        self.event1 = SecurityEvent(
            event_id="evt_001",
            timestamp="2026-11-06T10:00:00Z",
            event_type="auth_failure",
            src_ip="198.51.100.50",
            user="attacker",
            hostname="web-prod-01",
            action="login",
            details={"port": 22},
        )
        self.event2 = SecurityEvent(
            event_id="evt_002",
            timestamp="2026-11-06T10:01:00Z",
            event_type="auth_failure",
            src_ip="198.51.100.50",
            user="attacker",
            hostname="web-prod-01",
            action="login",
            details={"port": 22},
        )
        self.event3 = SecurityEvent(
            event_id="evt_003",
            timestamp="2026-11-06T10:05:00Z",
            event_type="privilege_escalation",
            src_ip="198.51.100.50",
            user="root",
            hostname="bastion-internal",
            action="sudo",
            details={"command": "/bin/bash"},
        )
        self.db.insert_event(self.event1)
        self.db.insert_event(self.event2)
        self.db.insert_event(self.event3)

        # Seed 2 alerts
        self.alert1 = Alert(
            alert_id="alt_bf_01",
            rule_name="Brute Force Authentication",
            severity="HIGH",
            title="SSH Brute Force",
            description="Multiple failed logins from 198.51.100.50",
            timestamp="2026-11-06T10:02:00Z",
            evidence_event_ids=["evt_001", "evt_002"],
            entity_user="attacker",
            entity_ip="198.51.100.50",
            entity_host="web-prod-01",
            status="NEW",
        )
        self.alert2 = Alert(
            alert_id="alt_priv_01",
            rule_name="Privilege Escalation Detected",
            severity="CRITICAL",
            title="Root Privilege Escalation",
            description="Root escalation detected on bastion",
            timestamp="2026-11-06T10:06:00Z",
            evidence_event_ids=["evt_003"],
            entity_user="root",
            entity_ip="198.51.100.50",
            entity_host="bastion-internal",
            status="INVESTIGATING",
        )
        self.db.insert_alert(self.alert1)
        self.db.insert_alert(self.alert2)

    # --- validate_alert_id tests ---

    def test_validate_alert_id_valid_and_invalid(self) -> None:
        """Verify alert ID sanitizer allows safe patterns and rejects malicious/oversized inputs."""
        self.assertEqual(validate_alert_id("alt_123"), "alt_123")
        self.assertEqual(validate_alert_id("ALERT-999_test"), "ALERT-999_test")

        # Invalid: empty or non-string
        self.assertIsNone(validate_alert_id(""))
        self.assertIsNone(validate_alert_id("   "))
        self.assertIsNone(validate_alert_id(None))
        self.assertIsNone(validate_alert_id(12345))

        # Invalid: SQL injection characters and spaces
        self.assertIsNone(validate_alert_id("alt_01'; DROP TABLE alerts; --"))
        self.assertIsNone(validate_alert_id("alt 01"))
        self.assertIsNone(validate_alert_id("alt$01"))
        self.assertIsNone(validate_alert_id("alt<script>"))

        # Invalid: oversized string
        long_id = "a" * (MAX_ALERT_ID_LENGTH + 1)
        self.assertIsNone(validate_alert_id(long_id))

    # --- get_alert tests ---

    def test_get_alert_found(self) -> None:
        """Verify retrieving an existing alert returns serializable dict with simulation flag."""
        res = get_alert("alt_bf_01", db=self.db)
        self.assertEqual(res["status_code"], "success")
        self.assertEqual(res["alert_id"], "alt_bf_01")
        self.assertEqual(res["rule_name"], "Brute Force Authentication")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["evidence_event_ids"], ["evt_001", "evt_002"])
        self.assertTrue(res["is_simulated"])

    def test_get_alert_not_found(self) -> None:
        """Verify non-existent alert returns clear error and simulation flag."""
        res = get_alert("alt_missing_999", db=self.db)
        self.assertEqual(res["status"], "not_found")
        self.assertIn("not found", res["error"])
        self.assertTrue(res["is_simulated"])

    def test_get_alert_invalid_id(self) -> None:
        """Verify malformed or injection alert ID returns validation error."""
        res = get_alert("alt_01; SELECT * FROM events;", db=self.db)
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid alert_id", res["error"])
        self.assertTrue(res["is_simulated"])

    # --- get_alert_evidence tests ---

    def test_get_alert_evidence_found(self) -> None:
        """Verify retrieving evidence returns verified events with is_simulated on every event."""
        res = get_alert_evidence("alt_bf_01", db=self.db)
        self.assertEqual(res["status_code"], "success")
        self.assertEqual(res["alert_id"], "alt_bf_01")
        self.assertEqual(res["count"], 2)
        self.assertTrue(res["is_simulated"])

        events = res["evidence_events"]
        self.assertEqual(len(events), 2)
        for ev in events:
            self.assertTrue(ev["is_simulated"])
            self.assertIn(ev["event_id"], ["evt_001", "evt_002"])

    def test_get_alert_evidence_respects_limit(self) -> None:
        """Verify limit parameter bounds returned evidence count."""
        res = get_alert_evidence("alt_bf_01", limit=1, db=self.db)
        self.assertEqual(res["count"], 1)
        self.assertEqual(len(res["evidence_events"]), 1)
        self.assertEqual(res["evidence_events"][0]["event_id"], "evt_001")

    def test_get_alert_evidence_not_found(self) -> None:
        """Verify evidence request for unknown alert returns not_found error."""
        res = get_alert_evidence("alt_unknown_404", db=self.db)
        self.assertEqual(res["status"], "not_found")
        self.assertEqual(res["events"], [])
        self.assertTrue(res["is_simulated"])

    def test_get_alert_evidence_invalid_id(self) -> None:
        """Verify evidence request with invalid ID returns error."""
        res = get_alert_evidence("invalid id with spaces", db=self.db)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["events"], [])

    # --- search_events tests ---

    def test_search_events_by_ip(self) -> None:
        """Verify searching historical events by IP."""
        res = search_events(ip="198.51.100.50", db=self.db)
        self.assertEqual(res["status_code"], "success")
        self.assertEqual(res["count"], 3)
        self.assertTrue(res["is_simulated"])
        for ev in res["events"]:
            self.assertEqual(ev["src_ip"], "198.51.100.50")
            self.assertTrue(ev["is_simulated"])

    def test_search_events_by_user(self) -> None:
        """Verify searching events by username."""
        res = search_events(user="root", db=self.db)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["events"][0]["user"], "root")
        self.assertEqual(res["events"][0]["event_id"], "evt_003")

    def test_search_events_by_hostname(self) -> None:
        """Verify searching events by hostname."""
        res = search_events(hostname="bastion-internal", db=self.db)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["events"][0]["hostname"], "bastion-internal")

    def test_search_events_by_event_type(self) -> None:
        """Verify searching events by event_type."""
        res = search_events(event_type="auth_failure", db=self.db)
        self.assertEqual(res["count"], 2)

    def test_search_events_limit_bounded(self) -> None:
        """Verify search_events limits results within MAX_SEARCH_LIMIT."""
        res = search_events(ip="198.51.100.50", limit=2, db=self.db)
        self.assertEqual(res["count"], 2)
        self.assertEqual(len(res["events"]), 2)

    # --- list_alerts tests ---

    def test_list_alerts_all(self) -> None:
        """Verify listing alerts returns all seeded alerts."""
        res = list_alerts(db=self.db)
        self.assertEqual(res["status_code"], "success")
        self.assertEqual(res["count"], 2)
        for a in res["alerts"]:
            self.assertTrue(a["is_simulated"])

    def test_list_alerts_filter_by_severity(self) -> None:
        """Verify filtering alerts by severity (case-insensitive)."""
        res_crit = list_alerts(severity="critical", db=self.db)
        self.assertEqual(res_crit["count"], 1)
        self.assertEqual(res_crit["alerts"][0]["alert_id"], "alt_priv_01")
        self.assertEqual(res_crit["alerts"][0]["severity"], "CRITICAL")

        res_high = list_alerts(severity="HIGH", db=self.db)
        self.assertEqual(res_high["count"], 1)
        self.assertEqual(res_high["alerts"][0]["alert_id"], "alt_bf_01")

    def test_list_alerts_filter_by_status(self) -> None:
        """Verify filtering alerts by status."""
        res = list_alerts(status="INVESTIGATING", db=self.db)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["alerts"][0]["alert_id"], "alt_priv_01")

    # --- execute_tool dispatch router tests ---

    def test_execute_tool_dispatch(self) -> None:
        """Verify execute_tool dispatches correctly to each registered function."""
        # 1. get_alert
        r1 = execute_tool("get_alert", {"alert_id": "alt_bf_01"}, db=self.db)
        self.assertEqual(r1["alert_id"], "alt_bf_01")

        # 2. get_alert_evidence
        r2 = execute_tool("get_alert_evidence", {"alert_id": "alt_bf_01"}, db=self.db)
        self.assertEqual(r2["count"], 2)

        # 3. search_events
        r3 = execute_tool("search_events", {"user": "root"}, db=self.db)
        self.assertEqual(r3["count"], 1)

        # 4. list_alerts
        r4 = execute_tool("list_alerts", {"severity": "HIGH"}, db=self.db)
        self.assertEqual(r4["count"], 1)

    def test_execute_tool_unknown_tool(self) -> None:
        """Verify execute_tool handles unknown tool name safely."""
        res = execute_tool("drop_database", {"table": "all"}, db=self.db)
        self.assertEqual(res["status"], "error")
        self.assertIn("Unknown tool", res["error"])
        self.assertTrue(res["is_simulated"])


if __name__ == "__main__":
    unittest.main()
