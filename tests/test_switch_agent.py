"""Unit tests for Switch Core Agent Bridge integration in CyberTriage."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse
import uuid

import requests

from src.agents.analyzer import IncidentAnalyzer
from src.agents.switch_agent import (
    AuthenticationError,
    DEFAULT_SWITCH_CORE_URL,
    EvictedError,
    MAX_SAFE_INTEGER,
    RegistrationError,
    SwitchAgent,
    SwitchCredentials,
    is_valid_position,
    merge_positions,
)
from src.database.db import Database
from src.database.models import Alert
from src.events.models import SecurityEvent


class TestSwitchAgentIntegration(unittest.TestCase):
    """Test suite for Switch Core Agent Bridge integration and protocol compliance."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_cybertriage.db")
        self.creds_path = str(Path(self.temp_dir.name) / ".test_credentials.json")
        self.db = Database(self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_merge_positions_join_semilattice(self) -> None:
        """Verify position merging follows the join-semilattice protocol (never moves backward)."""
        current = {"s": 5, "r:room_a": 10}
        incoming = {"s": 8, "r:room_a": 7, "r:room_b": 3}

        merged = merge_positions(current, incoming)
        self.assertEqual(merged["s"], 8)
        self.assertEqual(merged["r:room_a"], 10)  # Preserved higher sequence
        self.assertEqual(merged["r:room_b"], 3)   # Added new source

    def test_credentials_atomic_save_and_permissions(self) -> None:
        """Verify credentials are saved atomically with restricted 0o600 permissions."""
        creds = SwitchCredentials(
            agent_id="agt_test_01",
            agent_api_key="secret_key_123",
            connection_id="conn_uuid_456",
            generation=2,
            position={"s": 15},
        )
        creds.save(self.creds_path)

        # Check file exists and permissions are 0o600
        path = Path(self.creds_path)
        self.assertTrue(path.exists())
        file_mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(file_mode, 0o600)

        # Verify clean loading
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.agent_id, "agt_test_01")
        self.assertEqual(loaded.agent_api_key, "secret_key_123")
        self.assertEqual(loaded.connection_id, "conn_uuid_456")
        self.assertEqual(loaded.generation, 2)
        self.assertEqual(loaded.position, {"s": 15})

    def test_corrupted_credentials_raises_error_without_silent_overwrite(self) -> None:
        """Verify corrupted or invalid credentials file raises RuntimeError instead of silent re-register."""
        with open(self.creds_path, "w", encoding="utf-8") as f:
            f.write("corrupted { invalid json")

        with self.assertRaises(RuntimeError):
            SwitchCredentials.load(self.creds_path)

        # Incomplete schema (missing agent_id)
        with open(self.creds_path, "w", encoding="utf-8") as f:
            json.dump({"agent_api_key": "abc", "connection_id": "def"}, f)

        with self.assertRaises(RuntimeError):
            SwitchCredentials.load(self.creds_path)

    @patch("requests.post")
    def test_registration_request_payload_and_profile(self, mock_post: MagicMock) -> None:
        """Verify registration sends the exact IntegrationProfile and connector_type='external'."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "agt_reg_99",
            "api_key": "test_api_key_xyz",
        }
        mock_post.return_value = mock_response

        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            registration_token="mock_registration_token_secret",
        )

        creds = agent.register()
        self.assertEqual(creds.agent_id, "agt_reg_99")
        self.assertEqual(creds.agent_api_key, "test_api_key_xyz")
        self.assertTrue(Path(self.creds_path).exists())

        # Inspect POST call arguments
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        call_headers = mock_post.call_args[1]["headers"]
        call_json = mock_post.call_args[1]["json"]

        self.assertEqual(call_url, "http://switch.local:8000/agents")
        self.assertEqual(call_headers["Authorization"], "Bearer mock_registration_token_secret")
        self.assertEqual(call_json["name"], "cybertriage")
        self.assertEqual(call_json["connector_type"], "external")
        self.assertEqual(call_json["overwrite"], False)

        profile = call_json["integration_profile"]
        self.assertEqual(profile["connection_model"], "always_on")
        self.assertEqual(profile["message_exchange"], True)
        self.assertEqual(profile["pre_invocation_mediation"], [])
        self.assertEqual(profile["post_invocation_mediation"], [])
        self.assertEqual(profile["event_reporting"], [])
        self.assertEqual(
            profile["command_capabilities"],
            {"reset": "unsupported", "compact": "unsupported", "interrupt": "unsupported"},
        )

    def test_build_websocket_url_first_connect(self) -> None:
        """Verify initial WebSocket URL uses start_at=head, scope=all, and filter=addressed."""
        agent = SwitchAgent(
            switch_url="http://127.0.0.1:8000",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_01",
            agent_api_key="key_01",
            connection_id="uuid_fixed_123",
            generation=None,
            position={},
        )

        url = agent.build_websocket_url()
        parsed = urlparse(url)
        self.assertEqual(parsed.scheme, "ws")
        self.assertEqual(parsed.netloc, "127.0.0.1:8000")
        self.assertEqual(parsed.path, "/agents/agt_01/connection/ws")

        params = parse_qs(parsed.query)
        self.assertEqual(params["connection_id"], ["uuid_fixed_123"])
        self.assertEqual(params["scope"], ["all"])
        self.assertEqual(params["filter"], ["addressed"])
        self.assertEqual(params["start_at"], ["head"])
        self.assertNotIn("expected_generation", params)

    def test_build_websocket_url_position_resume_and_generation(self) -> None:
        """Verify reconnect URL includes exact JSON-encoded position and expected_generation."""
        agent = SwitchAgent(
            switch_url="https://secure.switch.io",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_02",
            agent_api_key="key_02",
            connection_id="uuid_conn_789",
            generation=4,
            position={"s": 14, "r:room_alerts": 92},
        )

        url = agent.build_websocket_url()
        parsed = urlparse(url)
        self.assertEqual(parsed.scheme, "wss")
        self.assertEqual(parsed.path, "/agents/agt_02/connection/ws")

        params = parse_qs(parsed.query)
        self.assertEqual(params["connection_id"], ["uuid_conn_789"])
        self.assertEqual(params["expected_generation"], ["4"])

        start_at_str = params["start_at"][0]
        parsed_position = json.loads(start_at_str)
        self.assertEqual(parsed_position, {"s": 14, "r:room_alerts": 92})

    @patch("requests.post")
    def test_messages_received_during_disconnection_not_skipped(self, mock_post: MagicMock) -> None:
        """Verify position updates merge properly so reconnected stream resumes without skipping events."""
        mock_resp = MagicMock(status_code=200)
        mock_post.return_value = mock_resp

        agent = SwitchAgent(
            switch_url="http://localhost:8000",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_resume",
            agent_api_key="key_resume",
            connection_id="conn_resume",
            generation=1,
            position={"s": 10},
        )

        mock_ws = AsyncMock()

        # Simulate receiving message 1 with position s: 15
        msg_frame_1 = json.dumps({
            "event": "message",
            "data": {
                "room_id": "room_soc",
                "payload": {"body": "ping", "sender": "bob"},
                "position": {"s": 15, "r:room_soc": 50},
            },
        })
        asyncio.run(agent.process_frame(mock_ws, msg_frame_1))

        # Position should now be s: 15, r:room_soc: 50
        self.assertEqual(agent.credentials.position["s"], 15)
        self.assertEqual(agent.credentials.position["r:room_soc"], 50)

        # Simulate receiving message 2 with position s: 16
        msg_frame_2 = json.dumps({
            "event": "message",
            "data": {
                "room_id": "room_soc",
                "payload": {"body": "ping 2", "sender": "bob"},
                "position": {"s": 16},
            },
        })
        asyncio.run(agent.process_frame(mock_ws, msg_frame_2))

        # Advance to s: 16 while keeping r:room_soc: 50
        self.assertEqual(agent.credentials.position["s"], 16)
        self.assertEqual(agent.credentials.position["r:room_soc"], 50)

        # Now disconnect and verify resume URL queries with s:16, r:room_soc:50
        reconnect_url = agent.build_websocket_url()
        params = parse_qs(urlparse(reconnect_url).query)
        resume_pos = json.loads(params["start_at"][0])

        self.assertEqual(resume_pos["s"], 16)
        self.assertEqual(resume_pos["r:room_soc"], 50)

    def test_heartbeat_ping_responds_with_pong(self) -> None:
        """Verify incoming ping frame triggers an immediate pong response with cursor and position."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = SwitchCredentials(
            agent_id="agt_hb", agent_api_key="k", connection_id="c"
        )
        mock_ws = AsyncMock()

        ping_frame = json.dumps({"event": "ping", "data": {}})
        asyncio.run(agent.process_frame(mock_ws, ping_frame))

        expected_payload = {
            "type": "pong",
            "cursor": 0,
            "position": {},
        }
        mock_ws.send.assert_awaited_once_with(json.dumps(expected_payload))

    def test_heartbeat_ping_with_custom_sequence_cursor_and_position(self) -> None:
        """Verify ping responds with credentials cursor and position without modifying them."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = SwitchCredentials(
            agent_id="agt_hb2", agent_api_key="k", connection_id="c"
        )
        initial_position = {"s": 42, "r:room_soc": 100}
        agent.credentials.position = dict(initial_position)
        mock_ws = AsyncMock()

        ping_frame = json.dumps({"event": "ping", "data": {}})
        asyncio.run(agent.process_frame(mock_ws, ping_frame))

        expected_payload = {
            "type": "pong",
            "cursor": 42,
            "position": {"s": 42, "r:room_soc": 100},
        }
        mock_ws.send.assert_awaited_once_with(json.dumps(expected_payload))
        self.assertEqual(agent.credentials.position, initial_position)

    def test_heartbeat_ping_without_credentials(self) -> None:
        """Verify ping response safely defaults cursor to 0 and position to {} when credentials are None."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = None
        mock_ws = AsyncMock()

        ping_frame = json.dumps({"event": "ping", "data": {}})
        asyncio.run(agent.process_frame(mock_ws, ping_frame))

        expected_payload = {
            "type": "pong",
            "cursor": 0,
            "position": {},
        }
        mock_ws.send.assert_awaited_once_with(json.dumps(expected_payload))

    def test_heartbeat_ping_with_position_without_s_cursor(self) -> None:
        """Verify ping response defaults cursor to 0 when position has room keys but no 's' key."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = SwitchCredentials(
            agent_id="agt_hb3", agent_api_key="k", connection_id="c"
        )
        initial_position = {"r:room_sec": 7}
        agent.credentials.position = dict(initial_position)
        mock_ws = AsyncMock()

        ping_frame = json.dumps({"event": "ping", "data": {}})
        asyncio.run(agent.process_frame(mock_ws, ping_frame))

        expected_payload = {
            "type": "pong",
            "cursor": 0,
            "position": {"r:room_sec": 7},
        }
        mock_ws.send.assert_awaited_once_with(json.dumps(expected_payload))
        self.assertEqual(agent.credentials.position, initial_position)

    def test_connection_state_updates_generation_and_position(self) -> None:
        """Verify connection_state event updates generation and position."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = SwitchCredentials(
            agent_id="agt_cs", agent_api_key="k", connection_id="c"
        )
        mock_ws = AsyncMock()

        state_frame = json.dumps({
            "event": "connection_state",
            "data": {
                "generation": 3,
                "position": {"s": 42},
            },
        })
        asyncio.run(agent.process_frame(mock_ws, state_frame))

        self.assertEqual(agent.credentials.generation, 3)
        self.assertEqual(agent.credentials.position, {"s": 42})

    def test_evicted_taken_over_raises_evicted_error(self) -> None:
        """Verify session eviction terminates cleanly with EvictedError and does not loop."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = SwitchCredentials(
            agent_id="agt_ev", agent_api_key="k", connection_id="c"
        )
        mock_ws = AsyncMock()

        evicted_frame = json.dumps({
            "event": "evicted",
            "data": {
                "code": "taken_over",
                "reason": "Connection displaced by supervisor",
            },
        })

        with self.assertRaises(EvictedError) as ctx:
            asyncio.run(agent.process_frame(mock_ws, evicted_frame))

        self.assertIn("taken_over", str(ctx.exception))

    @patch("requests.post")
    def test_investigate_alert_found_flow(self, mock_post: MagicMock) -> None:
        """Verify investigate <alert_id> fetches evidence from DB and dispatches incident report."""
        # Seed an event and an alert in the database
        ev1 = SecurityEvent(
            event_id="evt_test_01",
            timestamp="2026-11-06T12:00:00Z",
            event_type="auth_failure",
            user="admin",
            src_ip="198.51.100.14",
            hostname="bastion-host",
            action="login_failed",
            details={"service": "sshd"},
        )
        self.db.insert_event(ev1)

        alert = Alert(
            alert_id="alt_bf_01",
            rule_name="BruteForceRule",
            severity="HIGH",
            title="SSH Brute Force Attack",
            description="Repeated failed authentications detected.",
            timestamp="2026-11-06T12:05:00Z",
            evidence_event_ids=["evt_test_01"],
            entity_user="admin",
            entity_ip="198.51.100.14",
            entity_host="bastion-host",
            status="NEW",
        )
        self.db.insert_alert(alert)

        # Mock outbound message response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_inv",
            agent_api_key="key_inv",
            connection_id="conn_inv",
        )

        mock_ws = AsyncMock()
        message_frame = json.dumps({
            "event": "message",
            "data": {
                "room_id": "!room_soc:switch.local",
                "payload": {
                    "body": "@cybertriage investigate alt_bf_01",
                    "sender": "analyst_alice",
                    "sender_name": "Alice",
                },
                "position": {"s": 30},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, message_frame))

        # Verify POST /agents/{agent_id}/message was called
        mock_post.assert_called_once()
        url = mock_post.call_args[0][0]
        self.assertEqual(url, "http://switch.local:8000/agents/agt_inv/message")

        payload = mock_post.call_args[1]["json"]
        self.assertEqual(payload["room_id"], "!room_soc:switch.local")
        content = payload["content"]

        self.assertIn("CyberTriage Incident Investigation: alt_bf_01", content)
        self.assertIn("SSH Brute Force Attack", content)
        self.assertIn("evt_test_01", content)
        self.assertIn("198.51.100.14", content)
        self.assertIn("HIGH", content)

    @patch("requests.post")
    def test_process_frame_with_gemini_investigator(self, mock_post: MagicMock) -> None:
        """Verify process_frame properly delegates to GeminiInvestigator and sends response."""
        mock_resp = MagicMock(status_code=200)
        mock_post.return_value = mock_resp

        mock_investigator = MagicMock()
        mock_investigator.handle_message.return_value = "🚨 [SIMULATED] AI Incident Report: Suspicious activity confirmed."

        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=mock_investigator,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_gemini",
            agent_api_key="key_gemini",
            connection_id="conn_gemini",
        )

        mock_ws = AsyncMock()
        message_frame = json.dumps({
            "event": "message",
            "data": {
                "room_id": "!soc:switch.local",
                "payload": {
                    "body": "Show me recent critical alerts",
                    "sender": "analyst_carol",
                },
            },
        })

        asyncio.run(agent.process_frame(mock_ws, message_frame))

        mock_investigator.handle_message.assert_called_once_with(
            "Show me recent critical alerts", sender="analyst_carol"
        )
        mock_post.assert_called_once()
        content = mock_post.call_args[1]["json"]["content"]
        self.assertIn("AI Incident Report", content)

    @patch("requests.post")
    def test_investigate_alert_missing_flow(self, mock_post: MagicMock) -> None:
        """Verify investigate with unknown alert ID replies with clean error message."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_missing",
            agent_api_key="key_missing",
            connection_id="conn_missing",
        )

        mock_ws = AsyncMock()
        message_frame = json.dumps({
            "event": "message",
            "data": {
                "room_id": "!room_soc:switch.local",
                "payload": {
                    "body": "investigate alt_nonexistent_99",
                    "sender": "analyst_bob",
                },
            },
        })

        asyncio.run(agent.process_frame(mock_ws, message_frame))

        mock_post.assert_called_once()
        content = mock_post.call_args[1]["json"]["content"]
        self.assertIn("Incident Investigation Error", content)
        self.assertIn("alt_nonexistent_99", content)

    @patch("requests.post")
    def test_outbound_http_errors_resilience(self, mock_post: MagicMock) -> None:
        """Verify HTTP 403, 404, 429 are safely caught without crashing the agent."""
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_err",
            agent_api_key="key_err",
            connection_id="conn_err",
        )

        # 403 Forbidden (not in room roster)
        mock_resp = MagicMock(status_code=403)
        mock_post.return_value = mock_resp
        success = asyncio.run(agent.send_message("room_forbidden", "test"))
        self.assertFalse(success)

        # 404 Room Not Found
        mock_resp = MagicMock(status_code=404)
        mock_post.return_value = mock_resp
        success = asyncio.run(agent.send_message("room_missing", "test"))
        self.assertFalse(success)

        # 429 Budget Exceeded
        mock_resp = MagicMock(status_code=429)
        mock_post.return_value = mock_resp
        success = asyncio.run(agent.send_message("room_rate_limited", "test"))
        self.assertFalse(success)

        # 401 Unauthorized raises AuthenticationError
        mock_resp = MagicMock(status_code=401)
        mock_post.return_value = mock_resp
        with self.assertRaises(AuthenticationError):
            asyncio.run(agent.send_message("room_auth_fail", "test"))

    @patch("requests.post")
    def test_legacy_cursor_fallback_missing_data_position_with_frame_id(self, mock_post: MagicMock) -> None:
        """Verify missing data.position falls back to top-level frame.id and updates position."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_legacy_1",
            agent_api_key="key_legacy_1",
            connection_id="conn_legacy_1",
            position={},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        frame = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "room_id": "room_soc",
                "payload": {"body": "hello", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame))

        # Position should update to {"s": 42}
        self.assertEqual(agent.credentials.position, {"s": 42})

        # Verify credentials saved to disk with updated position
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, {"s": 42})

        # Also test with invalid data.position (non-dict) falling back to frame.id
        frame_invalid_pos = json.dumps({
            "event": "message",
            "id": "45",
            "data": {
                "room_id": "room_soc",
                "payload": {"body": "hello 2", "sender": "user1"},
                "position": "invalid_not_a_dict",
            },
        })
        asyncio.run(agent.process_frame(mock_ws, frame_invalid_pos))
        self.assertEqual(agent.credentials.position, {"s": 45})

    @patch("requests.post")
    def test_legacy_cursor_fallback_preserves_room_cursors(self, mock_post: MagicMock) -> None:
        """Verify legacy frame.id fallback preserves all existing room cursors."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_legacy_2",
            agent_api_key="key_legacy_2",
            connection_id="conn_legacy_2",
            position={"s": 10, "r:room_soc": 55, "r:room_alerts": 100},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        frame = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "room_id": "room_soc",
                "payload": {"body": "test message", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame))

        # "s" is updated to 42, room cursors "r:room_soc" and "r:room_alerts" are strictly preserved
        expected = {"s": 42, "r:room_soc": 55, "r:room_alerts": 100}
        self.assertEqual(agent.credentials.position, expected)

        # Verify disk persistence preserves room cursors
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, expected)

    @patch("requests.post")
    def test_legacy_cursor_fallback_invalid_or_non_numeric_id_ignored_safely(self, mock_post: MagicMock) -> None:
        """Verify invalid, negative, or non-numeric frame.id is ignored safely without modifying position."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        initial_position = {"s": 10, "r:room_soc": 55}
        agent.credentials = SwitchCredentials(
            agent_id="agt_legacy_3",
            agent_api_key="key_legacy_3",
            connection_id="conn_legacy_3",
            position=dict(initial_position),
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()

        invalid_ids = ["not-a-number", "-5", "", "12.34", "NaN", None, "   "]
        for inv_id in invalid_ids:
            frame_dict = {
                "event": "message",
                "data": {
                    "room_id": "room_soc",
                    "payload": {"body": "test", "sender": "user1"},
                },
            }
            if inv_id is not None:
                frame_dict["id"] = inv_id

            frame = json.dumps(frame_dict)
            asyncio.run(agent.process_frame(mock_ws, frame))

            # Position must remain completely unchanged
            self.assertEqual(agent.credentials.position, initial_position)

        # Check credentials on disk were not corrupted
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, initial_position)

    @patch("requests.post")
    def test_legacy_cursor_fallback_valid_data_position_takes_precedence(self, mock_post: MagicMock) -> None:
        """Verify valid data.position takes precedence over top-level frame.id."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_legacy_4",
            agent_api_key="key_legacy_4",
            connection_id="conn_legacy_4",
            position={"s": 10},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        # Frame has BOTH frame.id="99" and data.position={"s": 25, "r:room_soc": 10}
        frame = json.dumps({
            "event": "message",
            "id": "99",
            "data": {
                "position": {"s": 25, "r:room_soc": 10},
                "room_id": "room_soc",
                "payload": {"body": "test precedence", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame))

        # data.position takes precedence: s should be 25, NOT 99
        expected = {"s": 25, "r:room_soc": 10}
        self.assertEqual(agent.credentials.position, expected)

        # Check disk persistence
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, expected)

    def test_is_valid_position_readposition_spec(self) -> None:
        """Verify is_valid_position strictly adheres to Switch's TypeScript readPosition() behavior."""
        # 1. Accepts empty dictionary
        self.assertTrue(is_valid_position({}))

        # 2. Accepts valid position dicts
        self.assertTrue(is_valid_position({"s": 0}))
        self.assertTrue(is_valid_position({"s": 100, "r:soc": 50}))
        self.assertTrue(is_valid_position({"s": MAX_SAFE_INTEGER}))

        # 3. Explicitly rejects boolean values
        self.assertFalse(is_valid_position({"s": True}))
        self.assertFalse(is_valid_position({"s": False}))
        self.assertFalse(is_valid_position({"s": 10, "r:soc": True}))

        # 4. Rejects negative values
        self.assertFalse(is_valid_position({"s": -1}))
        self.assertFalse(is_valid_position({"s": 10, "r:soc": -50}))

        # 5. Rejects values above safe integer limit
        self.assertFalse(is_valid_position({"s": MAX_SAFE_INTEGER + 1}))
        self.assertFalse(is_valid_position({"s": 2**64}))

        # 6. Rejects non-string keys and non-integer values
        self.assertFalse(is_valid_position({123: 10}))  # type: ignore
        self.assertFalse(is_valid_position({"s": "10"}))
        self.assertFalse(is_valid_position({"s": 12.34}))
        self.assertFalse(is_valid_position({"s": None}))

        # 7. Rejects non-dict types
        self.assertFalse(is_valid_position(None))
        self.assertFalse(is_valid_position("not_a_dict"))
        self.assertFalse(is_valid_position([1, 2]))
        self.assertFalse(is_valid_position(123))

    @patch("requests.post")
    def test_position_empty_dictionary_accepted_and_prevents_fallback(self, mock_post: MagicMock) -> None:
        """Verify empty dictionary {} is accepted as valid position and does NOT fall back to frame.id."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_empty_pos",
            agent_api_key="key_empty_pos",
            connection_id="conn_empty_pos",
            position={"s": 10, "r:room_soc": 25},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        # Frame has BOTH valid empty position {} and top-level frame.id="42"
        frame = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "position": {},
                "room_id": "room_soc",
                "payload": {"body": "test empty pos", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame))

        # Empty dict is valid, so position is preserved and does NOT fall back to frame.id (s should remain 10, not 42)
        expected = {"s": 10, "r:room_soc": 25}
        self.assertEqual(agent.credentials.position, expected)

        # Check disk persistence
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, expected)

    @patch("requests.post")
    def test_position_boolean_value_rejected_and_falls_back_to_frame_id(self, mock_post: MagicMock) -> None:
        """Verify position with boolean value is rejected and falls back to frame.id."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_bool_pos",
            agent_api_key="key_bool_pos",
            connection_id="conn_bool_pos",
            position={"s": 10, "r:room_soc": 25},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        # Frame has invalid boolean position {"s": True} and top-level frame.id="42"
        frame = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "position": {"s": True},
                "room_id": "room_soc",
                "payload": {"body": "test bool pos", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame))

        # Boolean position is invalid -> falls back to frame.id="42" while preserving room cursors
        expected = {"s": 42, "r:room_soc": 25}
        self.assertEqual(agent.credentials.position, expected)

        # Check disk persistence
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, expected)

    @patch("requests.post")
    def test_position_negative_value_rejected_and_falls_back_to_frame_id(self, mock_post: MagicMock) -> None:
        """Verify position with negative integer is rejected and falls back to frame.id."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_neg_pos",
            agent_api_key="key_neg_pos",
            connection_id="conn_neg_pos",
            position={"s": 10, "r:room_soc": 25},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        # Frame has invalid negative position {"s": -1} and top-level frame.id="42"
        frame = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "position": {"s": -1},
                "room_id": "room_soc",
                "payload": {"body": "test neg pos", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame))

        # Negative position is invalid -> falls back to frame.id="42" while preserving room cursors
        expected = {"s": 42, "r:room_soc": 25}
        self.assertEqual(agent.credentials.position, expected)

        # Check disk persistence
        loaded = SwitchCredentials.load(self.creds_path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.position, expected)

    @patch("requests.post")
    def test_position_above_safe_integer_rejected_and_falls_back_to_frame_id(self, mock_post: MagicMock) -> None:
        """Verify position with value exceeding safe-integer limit is rejected and falls back to frame.id."""
        mock_post.return_value = MagicMock(status_code=200)
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_safe_pos",
            agent_api_key="key_safe_pos",
            connection_id="conn_safe_pos",
            position={"s": 10, "r:room_soc": 25},
        )
        agent.credentials.save(self.creds_path)

        mock_ws = AsyncMock()
        # Frame has value above MAX_SAFE_INTEGER and top-level frame.id="42"
        frame_above = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "position": {"s": MAX_SAFE_INTEGER + 1},
                "room_id": "room_soc",
                "payload": {"body": "test above safe pos", "sender": "user1"},
            },
        })

        asyncio.run(agent.process_frame(mock_ws, frame_above))

        # Exceeding safe integer is invalid -> falls back to frame.id="42"
        expected = {"s": 42, "r:room_soc": 25}
        self.assertEqual(agent.credentials.position, expected)

        # Conversely, at exactly MAX_SAFE_INTEGER, it is valid and does NOT fall back to frame.id
        frame_at_limit = json.dumps({
            "event": "message",
            "id": "42",
            "data": {
                "position": {"s": MAX_SAFE_INTEGER},
                "room_id": "room_soc",
                "payload": {"body": "test at limit pos", "sender": "user1"},
            },
        })
        asyncio.run(agent.process_frame(mock_ws, frame_at_limit))
        expected_limit = {"s": MAX_SAFE_INTEGER, "r:room_soc": 25}
        self.assertEqual(agent.credentials.position, expected_limit)

    @patch("requests.post")
    def test_send_message_http_200_success(self, mock_post: MagicMock) -> None:
        """Verify send_message handles HTTP 200 with verified event_id, correct payload, headers, and flags."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"event_id": "evt_msg_200_ok"}
        mock_post.return_value = mock_resp

        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_send_200",
            agent_api_key="key_secret_200",
            connection_id="conn_send_200",
        )

        success = asyncio.run(agent.send_message("!room_test:switch.local", "Incident report content"))
        self.assertTrue(success)

        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        call_kwargs = mock_post.call_args[1]

        # Verify endpoint URL
        self.assertEqual(call_url, "http://switch.local:8000/agents/agt_send_200/message")

        # Verify payload contains strictly room_id and content, without metadata
        payload = call_kwargs["json"]
        self.assertEqual(payload, {
            "room_id": "!room_test:switch.local",
            "content": "Incident report content",
        })
        self.assertNotIn("metadata", payload)

        # Verify headers include Authorization, Content-Type, and Accept: application/json
        headers = call_kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Bearer key_secret_200")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Accept"], "application/json")

        # Verify 30-second timeout and manual redirect (allow_redirects=False)
        self.assertEqual(call_kwargs["timeout"], 30)
        self.assertFalse(call_kwargs["allow_redirects"])

    @patch("requests.post")
    def test_send_message_http_201_success(self, mock_post: MagicMock) -> None:
        """Verify send_message accepts successful HTTP 201 Created responses."""
        mock_resp = MagicMock(status_code=201)
        mock_resp.json.return_value = {"event_id": "evt_msg_201_created"}
        mock_post.return_value = mock_resp

        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_send_201",
            agent_api_key="key_secret_201",
            connection_id="conn_send_201",
        )

        success = asyncio.run(agent.send_message("!room_test:switch.local", "Created content"))
        self.assertTrue(success)

    @patch("requests.post")
    def test_send_message_response_parsing_missing_or_invalid_event_id(self, mock_post: MagicMock) -> None:
        """Verify send_message fails if response JSON lacks a valid event_id field."""
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_parse_err",
            agent_api_key="key_parse_err",
            connection_id="conn_parse_err",
        )

        # 1. Missing event_id key
        mock_resp1 = MagicMock(status_code=200)
        mock_resp1.json.return_value = {"status": "ok"}
        mock_post.return_value = mock_resp1
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # 2. event_id is None
        mock_resp2 = MagicMock(status_code=200)
        mock_resp2.json.return_value = {"event_id": None}
        mock_post.return_value = mock_resp2
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # 3. event_id is empty string
        mock_resp3 = MagicMock(status_code=200)
        mock_resp3.json.return_value = {"event_id": ""}
        mock_post.return_value = mock_resp3
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # 4. Response is not valid JSON
        mock_resp4 = MagicMock(status_code=200)
        mock_resp4.json.side_effect = ValueError("Invalid JSON string")
        mock_post.return_value = mock_resp4
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # 5. Response JSON is a list, not a dict
        mock_resp5 = MagicMock(status_code=200)
        mock_resp5.json.return_value = ["not", "a", "dict"]
        mock_post.return_value = mock_resp5
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

    @patch("requests.post")
    def test_send_message_unsuccessful_http_responses(self, mock_post: MagicMock) -> None:
        """Verify send_message handles various unsuccessful HTTP statuses and network errors."""
        agent = SwitchAgent(
            switch_url="http://switch.local:8000",
            db=self.db,
            credentials_path=self.creds_path,
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_unsuccessful",
            agent_api_key="key_unsuccessful",
            connection_id="conn_unsuccessful",
        )

        # HTTP 400 Bad Request
        mock_post.return_value = MagicMock(status_code=400, text="Bad Request")
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # HTTP 500 Internal Server Error
        mock_post.return_value = MagicMock(status_code=500, text="Internal Server Error")
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # HTTP 302 Found (Manual redirect rejected)
        mock_post.return_value = MagicMock(status_code=302, text="Redirected")
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

        # Network Exception
        mock_post.side_effect = requests.RequestException("Connection refused")
        self.assertFalse(asyncio.run(agent.send_message("room_1", "test")))

    def test_process_frame_diagnostic_logging_event_name(self) -> None:
        """Verify process_frame logs top-level WebSocket event name at INFO level."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        mock_ws = AsyncMock()
        frame = json.dumps({"event": "custom_probe_event", "data": {}})

        with self.assertLogs("src.agents.switch_agent", level="INFO") as cm:
            asyncio.run(agent.process_frame(mock_ws, frame))

        self.assertTrue(any("Received WebSocket frame event: custom_probe_event" in log for log in cm.output))

    @patch("requests.post")
    def test_process_frame_diagnostic_logging_message_structure(self, mock_post: MagicMock) -> None:
        """Verify process_frame logs message frame keys, data keys, payload keys, has_room_id, and has_body."""
        mock_post.return_value = MagicMock(status_code=200)
        mock_post.return_value.json.return_value = {"event_id": "evt_diag_1"}
        agent = SwitchAgent(
            db=self.db,
            credentials_path=self.creds_path,
            investigator=IncidentAnalyzer(self.db),
        )
        agent.credentials = SwitchCredentials(
            agent_id="agt_diag",
            agent_api_key="key_diag",
            connection_id="conn_diag",
        )
        mock_ws = AsyncMock()
        frame = json.dumps({
            "event": "message",
            "id": "100",
            "data": {
                "room_id": "!room_soc:switch.local",
                "payload": {"body": "hello", "sender": "alice"},
            },
        })

        with self.assertLogs("src.agents.switch_agent", level="INFO") as cm:
            asyncio.run(agent.process_frame(mock_ws, frame))

        output_str = " ".join(cm.output)
        self.assertIn("Received WebSocket frame event: message", output_str)
        self.assertIn("frame_keys=['data', 'event', 'id']", output_str)
        self.assertIn("data_keys=['payload', 'room_id']", output_str)
        self.assertIn("payload_keys=['body', 'sender']", output_str)
        self.assertIn("has_room_id=True", output_str)
        self.assertIn("has_body=True", output_str)
        # Ensure credentials / API keys are not in the logs
        self.assertNotIn("key_diag", output_str)

    def test_process_frame_diagnostic_logging_unexpected_structure(self) -> None:
        """Verify process_frame logs diagnostic info even when message structure is unexpected/incomplete."""
        agent = SwitchAgent(db=self.db, credentials_path=self.creds_path)
        agent.credentials = SwitchCredentials(
            agent_id="agt_diag2",
            agent_api_key="key_diag2",
            connection_id="conn_diag2",
        )
        mock_ws = AsyncMock()
        frame = json.dumps({
            "event": "message",
            "id": "101",
            "data": {
                "unexpected_field": "val",
            },
        })

        with self.assertLogs("src.agents.switch_agent", level="INFO") as cm:
            asyncio.run(agent.process_frame(mock_ws, frame))

        output_str = " ".join(cm.output)
        self.assertIn("Received WebSocket frame event: message", output_str)
        self.assertIn("data_keys=['unexpected_field']", output_str)
        self.assertIn("payload_keys=[]", output_str)
        self.assertIn("has_room_id=False", output_str)
        self.assertIn("has_body=False", output_str)


if __name__ == "__main__":
    unittest.main()
