"""Unit tests for Gemini AI Investigation Engine in CyberTriage.

Tests multi-turn function calling, tool dispatch, graceful fallback to deterministic
IncidentAnalyzer on error/unavailable API, and query handling with mocked Gemini Client.
All tests run completely offline without making external network calls.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.agents.analyzer import IncidentAnalyzer
from src.agents.gemini_investigator import GeminiInvestigator
from src.agents.investigation_tools import get_gemini_tool_declarations
from src.database.db import Database
from src.database.models import Alert
from src.events.models import SecurityEvent


class TestGeminiInvestigator(unittest.TestCase):
    """Test suite for Gemini AI Investigation Engine with mocked Google GenAI client."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_gemini_soc.db")
        self.db = Database(self.db_path)
        self.fallback = IncidentAnalyzer(self.db)

        # Seed database with sample telemetry and alert
        self._seed_database()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _seed_database(self) -> None:
        now = "2026-11-06T12:00:00Z"
        event = SecurityEvent(
            event_id="evt_gemini_01",
            timestamp=now,
            event_type="auth_failure",
            src_ip="203.0.113.88",
            user="victim_user",
            hostname="auth-server",
            action="login",
            details={"service": "ssh"},
        )
        self.db.insert_event(event)

        alert = Alert(
            alert_id="alt_gemini_01",
            rule_name="Credential Stuffing Alert",
            severity="HIGH",
            title="Credential Stuffing Attack",
            description="Repeated credential failures from 203.0.113.88",
            timestamp=now,
            evidence_event_ids=["evt_gemini_01"],
            entity_user="victim_user",
            entity_ip="203.0.113.88",
            entity_host="auth-server",
            status="NEW",
        )
        self.db.insert_alert(alert)

    def test_tool_declarations_schema(self) -> None:
        """Verify Gemini tool declarations contain all four required investigation tools."""
        tool_decl = get_gemini_tool_declarations()
        self.assertIsNotNone(tool_decl)
        function_declarations = getattr(tool_decl, "function_declarations", [])
        declared_names = [fn.name for fn in function_declarations]
        self.assertIn("get_alert", declared_names)
        self.assertIn("get_alert_evidence", declared_names)
        self.assertIn("search_events", declared_names)
        self.assertIn("list_alerts", declared_names)

    def test_fallback_when_api_key_missing(self) -> None:
        """Verify engine immediately falls back to IncidentAnalyzer when no API key is provided."""
        with patch("src.agents.gemini_investigator._load_api_key", return_value=None):
            investigator = GeminiInvestigator(
                db=self.db,
                api_key="",
                fallback_analyzer=self.fallback,
            )
            self.assertFalse(investigator.available)
            self.assertIsNone(investigator.client)

            # Query should be handled cleanly by fallback analyzer
            reply = investigator.handle_message("investigate alt_gemini_01")
            self.assertIsNotNone(reply)
            self.assertIn("CyberTriage Incident Investigation: alt_gemini_01", reply)
            self.assertIn("Credential Stuffing Alert", reply)

    def test_fallback_when_gemini_raises_exception(self) -> None:
        """Verify engine catches API errors (timeouts, network issues) and falls back to IncidentAnalyzer."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = RuntimeError("API connection timeout")

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        reply = investigator.handle_message("investigate alt_gemini_01")
        self.assertIsNotNone(reply)
        self.assertIn("CyberTriage Incident Investigation: alt_gemini_01", reply)

    def test_handle_empty_or_invalid_messages(self) -> None:
        """Verify handling empty or non-string messages returns None."""
        investigator = GeminiInvestigator(db=self.db, fallback_analyzer=self.fallback)
        self.assertIsNone(investigator.handle_message(""))
        self.assertIsNone(investigator.handle_message(None))  # type: ignore

    def test_multi_turn_function_calling_investigate(self) -> None:
        """Verify full multi-turn function calling: tool call requested -> executed against DB -> final report returned."""
        mock_client = MagicMock()

        # Step 1: Model requests get_alert and get_alert_evidence
        fc_alert = MagicMock()
        fc_alert.name = "get_alert"
        fc_alert.args = {"alert_id": "alt_gemini_01"}
        fc_alert.id = "call_alert_01"

        fc_evidence = MagicMock()
        fc_evidence.name = "get_alert_evidence"
        fc_evidence.args = {"alert_id": "alt_gemini_01"}
        fc_evidence.id = "call_evidence_01"

        step1_response = MagicMock()
        step1_response.function_calls = [fc_alert, fc_evidence]
        step1_response.candidates = [MagicMock()]
        step1_response.text = None

        # Step 2: Model returns the final Markdown investigation report
        expected_report = (
            "🚨 [SIMULATED] **SOC Incident Investigation Report: alt_gemini_01**\n"
            "- Severity: HIGH (Simulation-only telemetry)\n"
            "- Threat: Credential Stuffing Attack\n"
            "- Source IP: 203.0.113.88\n"
            "- Target User: victim_user on auth-server\n"
            "- Evidence: evt_gemini_01 confirmed."
        )
        step2_response = MagicMock()
        step2_response.function_calls = []
        step2_response.candidates = [MagicMock()]
        step2_response.text = expected_report

        mock_client.models.generate_content.side_effect = [step1_response, step2_response]

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        reply = investigator.handle_message("investigate alt_gemini_01", sender="analyst_test")

        self.assertEqual(reply, expected_report)
        self.assertEqual(mock_client.models.generate_content.call_count, 2)

    def test_natural_language_query_tool_calling(self) -> None:
        """Verify natural language queries trigger appropriate tools (e.g., list_alerts)."""
        mock_client = MagicMock()

        fc_list = MagicMock()
        fc_list.name = "list_alerts"
        fc_list.args = {"severity": "HIGH", "limit": 5}
        fc_list.id = "call_list_01"

        step1_response = MagicMock()
        step1_response.function_calls = [fc_list]
        step1_response.candidates = [MagicMock()]
        step1_response.text = None

        step2_response = MagicMock()
        step2_response.function_calls = []
        step2_response.text = "🚨 Found 1 active HIGH severity alert: alt_gemini_01 (Credential Stuffing)."

        mock_client.models.generate_content.side_effect = [step1_response, step2_response]

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        reply = investigator.handle_message("Show me the latest high severity alerts", sender="analyst_bob")
        self.assertIn("alt_gemini_01", reply)
        self.assertEqual(mock_client.models.generate_content.call_count, 2)

    def test_gemini_investigation_success_logging(self) -> None:
        """Verify INFO logs for Gemini start, model, tool requests, tool execution, and final report."""
        mock_client = MagicMock()

        fc_alert = MagicMock()
        fc_alert.name = "get_alert"
        fc_alert.args = {"alert_id": "alt_gemini_01"}
        fc_alert.id = "call_alert_01"

        step1_response = MagicMock()
        step1_response.function_calls = [fc_alert]
        step1_response.candidates = [MagicMock()]
        step1_response.text = None

        step2_response = MagicMock()
        step2_response.function_calls = []
        step2_response.candidates = [MagicMock()]
        step2_response.text = "Investigation complete."

        mock_client.models.generate_content.side_effect = [step1_response, step2_response]

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        with self.assertLogs("src.agents.gemini_investigator", level="INFO") as log_ctx:
            reply = investigator.handle_message("investigate alt_gemini_01", sender="soc_lead")

        self.assertEqual(reply, "Investigation complete.")
        log_messages = "\n".join(log_ctx.output)

        self.assertIn("Starting Gemini investigation for sender 'soc_lead' using model 'gemini-3.5-flash-lite'.", log_messages)
        self.assertIn("Gemini step 0 requested 1 function call(s): ['get_alert']", log_messages)
        self.assertIn("Executing Python tool 'get_alert'.", log_messages)
        self.assertIn("Python tool 'get_alert' executed successfully (status: success).", log_messages)
        self.assertIn("Gemini generated final investigation report (23 characters).", log_messages)

    def test_tool_execution_failure_logging(self) -> None:
        """Verify WARNING log when a requested Python tool execution fails."""
        mock_client = MagicMock()

        fc_unknown = MagicMock()
        fc_unknown.name = "unknown_tool"
        fc_unknown.args = {}
        fc_unknown.id = "call_unknown_01"

        step1_response = MagicMock()
        step1_response.function_calls = [fc_unknown]
        step1_response.candidates = [MagicMock()]
        step1_response.text = None

        step2_response = MagicMock()
        step2_response.function_calls = []
        step2_response.candidates = [MagicMock()]
        step2_response.text = "Could not find tool."

        mock_client.models.generate_content.side_effect = [step1_response, step2_response]

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        with self.assertLogs("src.agents.gemini_investigator", level="INFO") as log_ctx:
            investigator.handle_message("run unknown tool", sender="soc_lead")

        log_messages = "\n".join(log_ctx.output)
        self.assertIn("Executing Python tool 'unknown_tool'.", log_messages)
        self.assertIn("WARNING:src.agents.gemini_investigator:Python tool 'unknown_tool' execution failed", log_messages)

    def test_fallback_logging_when_unconfigured(self) -> None:
        """Verify INFO log with explicit reason when fallback analyzer activates due to unconfigured Gemini."""
        with patch("src.agents.gemini_investigator._load_api_key", return_value=None):
            investigator = GeminiInvestigator(
                db=self.db,
                api_key="",
                fallback_analyzer=self.fallback,
            )
            with self.assertLogs("src.agents.gemini_investigator", level="INFO") as log_ctx:
                investigator.handle_message("investigate alt_gemini_01", sender="analyst")

            log_messages = "\n".join(log_ctx.output)
            self.assertIn(
                "Deterministic fallback analyzer activated (reason: Gemini AI unavailable or unconfigured).",
                log_messages,
            )

    def test_fallback_logging_on_gemini_exception(self) -> None:
        """Verify WARNING log with explicit error reason when fallback analyzer activates due to an API error."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = ConnectionResetError("Remote server closed connection")

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        with self.assertLogs("src.agents.gemini_investigator", level="INFO") as log_ctx:
            investigator.handle_message("investigate alt_gemini_01", sender="analyst")

        log_messages = "\n".join(log_ctx.output)
        self.assertIn(
            "Deterministic fallback analyzer activated (reason: Gemini AI investigation error - ConnectionResetError: Remote server closed connection).",
            log_messages,
        )

    def test_fallback_logging_on_empty_text_output(self) -> None:
        """Verify INFO log with explicit reason when fallback analyzer activates due to empty final text from Gemini."""
        mock_client = MagicMock()

        empty_response = MagicMock()
        empty_response.function_calls = []
        empty_response.candidates = []
        empty_response.text = ""

        mock_client.models.generate_content.return_value = empty_response

        investigator = GeminiInvestigator(
            db=self.db,
            api_key="mock_key",
            fallback_analyzer=self.fallback,
        )
        investigator.client = mock_client
        investigator.available = True

        with self.assertLogs("src.agents.gemini_investigator", level="INFO") as log_ctx:
            reply = investigator.handle_message("investigate alt_gemini_01", sender="analyst")

        self.assertIn("alt_gemini_01", reply)
        log_messages = "\n".join(log_ctx.output)
        self.assertIn(
            "Deterministic fallback analyzer activated (reason: Gemini function-calling loop returned empty text).",
            log_messages,
        )


if __name__ == "__main__":
    unittest.main()
