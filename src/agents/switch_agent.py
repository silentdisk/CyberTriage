"""Switch Core Agent Bridge integration for CyberTriage."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import json
import logging
import os
from pathlib import Path
import random
import re
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse, urlunparse
import uuid

import requests
import websockets

from src.agents.analyzer import IncidentAnalyzer
from src.agents.gemini_investigator import GeminiInvestigator
from src.database.db import Database

logger = logging.getLogger(__name__)

DEFAULT_CREDENTIALS_PATH = ".switch_credentials.json"
DEFAULT_SWITCH_CORE_URL = "http://localhost:8000"


class SwitchAgentError(Exception):
    """Base exception for Switch Agent Bridge integration."""


class AuthenticationError(SwitchAgentError):
    """Raised when authentication fails (token rejected, key revoked)."""


class EvictedError(SwitchAgentError):
    """Raised when the session is evicted or taken over (terminal close)."""


class RegistrationError(SwitchAgentError):
    """Raised when registration with Switch Core fails."""


MAX_SAFE_INTEGER = 9007199254740991


def is_valid_position(pos: Any) -> bool:
    """Validate position dictionary matching Switch's TypeScript readPosition() behavior.

    Requirements:
    - Must be a dictionary (including an empty dictionary).
    - Every key must be a string.
    - Every value must be an integer, explicitly rejecting booleans.
    - Values must be between 0 and 9007199254740991 (inclusive).
    """
    if not isinstance(pos, dict):
        return False
    for k, v in pos.items():
        if not isinstance(k, str):
            return False
        if isinstance(v, bool) or not isinstance(v, int):
            return False
        if not (0 <= v <= MAX_SAFE_INTEGER):
            return False
    return True


def merge_positions(current: dict[str, int], incoming: dict[str, int]) -> dict[str, int]:
    """Merge incoming event positions into current position using join-semilattice logic.

    Matches the Switch Core protocol: each source advances to the highest sequence number,
    never moving backwards.
    """
    merged = dict(current)
    for source, seq in incoming.items():
        if isinstance(seq, int) and not isinstance(seq, bool) and seq > merged.get(source, -1):
            merged[source] = seq
    return merged


@dataclass
class SwitchCredentials:
    """Persistent runtime credentials and stream position for Switch Core."""

    agent_id: str
    agent_api_key: str
    connection_id: str
    generation: Optional[int] = None
    position: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SwitchCredentials":
        agent_id = data.get("agent_id")
        agent_api_key = data.get("agent_api_key")
        connection_id = data.get("connection_id")

        if not agent_id or not agent_api_key or not connection_id:
            raise RuntimeError(
                "Invalid or corrupted credentials file: missing required keys (agent_id, agent_api_key, connection_id)"
            )

        generation = data.get("generation")
        if generation is not None:
            try:
                generation = int(generation)
            except (ValueError, TypeError):
                generation = None

        raw_pos = data.get("position", {})
        position: dict[str, int] = {}
        if isinstance(raw_pos, dict):
            for k, v in raw_pos.items():
                if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE_INTEGER:
                    position[k] = v

        return cls(
            agent_id=str(agent_id),
            agent_api_key=str(agent_api_key),
            connection_id=str(connection_id),
            generation=generation,
            position=position,
        )

    def save(self, path: Path | str) -> None:
        """Atomically persist credentials to disk with 0o600 file permissions."""
        file_path = Path(path).resolve()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = file_path.with_suffix(".tmp")

        try:
            # Write to temporary file with restricted permissions
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(str(tmp_path), flags, 0o600)
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2)

            # Ensure 0o600 on file before replacement
            os.chmod(str(tmp_path), 0o600)
            os.replace(str(tmp_path), str(file_path))
            logger.debug("Credentials successfully saved to %s", file_path)
        except Exception as e:
            logger.error("Failed to atomically save credentials to %s: %s", file_path, e)
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

    @classmethod
    def load(cls, path: Path | str) -> Optional["SwitchCredentials"]:
        """Load credentials from disk if present, validating integrity."""
        file_path = Path(path).resolve()
        if not file_path.exists():
            return None

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Credentials file {file_path} is corrupted JSON: {e}") from e
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Error loading credentials from {file_path}: {e}") from e


class SwitchAgent:
    """Always-on CyberTriage agent connected to Switch Core Agent Bridge."""

    def __init__(
        self,
        switch_url: str = DEFAULT_SWITCH_CORE_URL,
        db: Optional[Database] = None,
        credentials_path: str = DEFAULT_CREDENTIALS_PATH,
        registration_token: Optional[str] = None,
        investigator: Optional[Any] = None,
    ) -> None:
        self.switch_url = switch_url.rstrip("/")
        self.db = db or Database()
        self.analyzer = IncidentAnalyzer(self.db)
        self.investigator = investigator or GeminiInvestigator(
            db=self.db, fallback_analyzer=self.analyzer
        )
        self.credentials_path = Path(credentials_path)
        self.registration_token = registration_token or os.environ.get("AGENT_REGISTRATION_TOKEN")
        self.credentials: Optional[SwitchCredentials] = None
        self._running = False

    def register(self) -> SwitchCredentials:
        """Register agent with Switch Core using POST /agents and save credentials."""
        token = self.registration_token or os.environ.get("AGENT_REGISTRATION_TOKEN")
        if not token:
            raise RegistrationError(
                "AGENT_REGISTRATION_TOKEN is required for agent registration but is not set."
            )

        url = f"{self.switch_url}/agents"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        payload = {
            "name": "cybertriage",
            "description": "CyberTriage automated incident triage and investigation agent",
            "connector_type": "external",
            "integration_profile": {
                "connection_model": "always_on",
                "message_exchange": True,
                "pre_invocation_mediation": [],
                "post_invocation_mediation": [],
                "event_reporting": [],
                "command_capabilities": {
                    "reset": "unsupported",
                    "compact": "unsupported",
                    "interrupt": "unsupported",
                },
            },
            "tools": [],
            "models": [],
            "metadata": {"version": "0.1.0"},
            "overwrite": False,
        }

        logger.info("Registering CyberTriage agent with Switch Core at %s...", self.switch_url)
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
        except requests.RequestException as e:
            raise RegistrationError(f"HTTP request to {url} failed: {e}") from e

        if resp.status_code == 401:
            raise AuthenticationError("Switch Core registration token was rejected (401 Unauthorized).")
        elif resp.status_code == 409:
            raise RegistrationError(
                "Agent 'cybertriage' already exists in Switch. Set overwrite=True or reuse existing credentials."
            )
        elif resp.status_code >= 400:
            raise RegistrationError(
                f"Registration failed with HTTP {resp.status_code}: {resp.text}"
            )

        data = resp.json()
        agent_id = data.get("id")
        api_key = data.get("api_key")

        if not agent_id or not api_key:
            raise RegistrationError(f"Invalid registration response from Switch Core: {data}")

        conn_id = str(uuid.uuid4())
        credentials = SwitchCredentials(
            agent_id=agent_id,
            agent_api_key=api_key,
            connection_id=conn_id,
            generation=None,
            position={},
        )
        credentials.save(self.credentials_path)
        self.credentials = credentials
        logger.info("Successfully registered agent (agent_id=%s). Saved credentials.", agent_id)
        return credentials

    def ensure_credentials(self) -> SwitchCredentials:
        """Load existing credentials or register a new agent session."""
        if self.credentials:
            return self.credentials

        existing = SwitchCredentials.load(self.credentials_path)
        if existing:
            logger.info(
                "Loaded existing credentials for agent_id=%s (connection_id=%s).",
                existing.agent_id,
                existing.connection_id,
            )
            self.credentials = existing
            return existing

        # If not present, perform clean registration
        return self.register()

    def build_websocket_url(self) -> str:
        """Construct the Switch Core WebSocket connection URL with protocol query parameters."""
        creds = self.ensure_credentials()
        parsed = urlparse(self.switch_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"

        path = f"/agents/{creds.agent_id}/connection/ws"
        query_params: dict[str, str] = {
            "connection_id": creds.connection_id,
            "scope": "all",
            "filter": "addressed",
        }

        # Position-based resume mechanism
        if creds.position:
            query_params["start_at"] = json.dumps(creds.position)
        else:
            query_params["start_at"] = "head"

        if creds.generation is not None:
            query_params["expected_generation"] = str(creds.generation)

        ws_url = urlunparse((
            ws_scheme,
            parsed.netloc,
            path,
            "",
            urlencode(query_params),
            "",
        ))
        return ws_url

    async def send_message(self, room_id: str, content: str) -> bool:
        """Send an incident report or reply back to the originating room via HTTP POST."""
        creds = self.ensure_credentials()
        url = f"{self.switch_url}/agents/{creds.agent_id}/message"
        headers = {
            "Authorization": f"Bearer {creds.agent_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "room_id": room_id,
            "content": content,
        }

        try:
            # Run requests in thread pool to not block asyncio event loop
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=30,
                    allow_redirects=False,
                ),
            )
        except Exception as e:
            logger.error("Network error sending message to room %s: %s", room_id, e)
            return False

        if 200 <= resp.status_code < 300:
            try:
                data = resp.json()
            except Exception as e:
                logger.warning("Failed to parse JSON response from room %s: %s", room_id, e)
                return False

            event_id = None
            if isinstance(data, dict):
                event_id = data.get("event_id")
            elif hasattr(data, "get"):
                event_id = data.get("event_id")

            if not event_id:
                logger.warning(
                    "Switch response missing expected 'event_id' for room %s: %s",
                    room_id,
                    data,
                )
                return False

            logger.info(
                "Successfully delivered message to room %s (event_id=%s)",
                room_id,
                event_id,
            )
            return True
        elif resp.status_code == 401:
            logger.error("Authentication failed posting message: API key rejected.")
            raise AuthenticationError("Agent API key rejected by Switch Core (401 Unauthorized).")
        elif resp.status_code == 403:
            logger.warning(
                "Cannot post to room %s: Agent is not a member or lack permissions (403 Forbidden).",
                room_id,
            )
            return False
        elif resp.status_code == 404:
            logger.warning("Cannot post to room %s: Room not found (404 Not Found).", room_id)
            return False
        elif resp.status_code == 429:
            logger.warning("Posting to room %s refused: Token budget exceeded (429).", room_id)
            return False
        else:
            logger.warning("Unexpected status %d posting to room %s: %s", resp.status_code, room_id, resp.text)
            return False

    async def process_frame(self, ws: Any, frame_raw: str | bytes) -> None:
        """Handle incoming WebSocket JSON frames according to Switch Agent Protocol."""
        if isinstance(frame_raw, bytes):
            frame_raw = frame_raw.decode("utf-8")

        try:
            frame = json.loads(frame_raw)
        except json.JSONDecodeError:
            logger.warning("Received invalid non-JSON WebSocket frame: %r", frame_raw)
            return

        if not isinstance(frame, dict):
            return

        event = frame.get("event")
        data = frame.get("data", {})
        if not isinstance(data, dict):
            data = {}

        logger.info("Received WebSocket frame event: %s", event)

        # 1. Heartbeat ping
        if event == "ping":
            logger.debug("Received ping from Switch Core; sending pong.")
            pos = (
                self.credentials.position
                if self.credentials and isinstance(self.credentials.position, dict)
                else {}
            )
            cursor = pos.get("s", 0) if isinstance(pos, dict) else 0
            if cursor is None or isinstance(cursor, bool) or not isinstance(cursor, int):
                cursor = 0
            pong_payload = {
                "type": "pong",
                "cursor": cursor,
                "position": pos,
            }
            await ws.send(json.dumps(pong_payload))
            return

        # 2. Connection state
        if event == "connection_state":
            generation = data.get("generation")
            if generation is not None:
                try:
                    self.credentials.generation = int(generation)
                except (ValueError, TypeError):
                    pass

            raw_pos = data.get("position")
            if is_valid_position(raw_pos):
                self.credentials.position = merge_positions(self.credentials.position, raw_pos)

            self.credentials.save(self.credentials_path)
            logger.info(
                "Connected to Switch Core. Generation=%s, position=%s",
                self.credentials.generation,
                self.credentials.position,
            )
            return

        # 3. Eviction
        if event == "evicted":
            code = data.get("code")
            reason = data.get("reason", "No reason provided")
            logger.warning("Received eviction frame from Switch Core (code=%s): %s", code, reason)
            # Terminal eviction codes: do not reconnect
            if code in ("taken_over", "launch_superseded", "closed"):
                raise EvictedError(f"Session evicted by Switch Core ({code}): {reason}")
            return

        # 4. Message events
        if event == "message":
            frame_keys = sorted(list(frame.keys()))
            data_keys = sorted(list(data.keys())) if isinstance(data, dict) else []
            payload_obj = data.get("payload") if isinstance(data, dict) else None
            payload_keys = sorted(list(payload_obj.keys())) if isinstance(payload_obj, dict) else []
            has_room_id = bool(data.get("room_id")) if isinstance(data, dict) else False
            has_body = bool(isinstance(payload_obj, dict) and payload_obj.get("body"))

            logger.info(
                "Processing message frame: frame_keys=%s, data_keys=%s, payload_keys=%s, has_room_id=%s, has_body=%s",
                frame_keys,
                data_keys,
                payload_keys,
                has_room_id,
                has_body,
            )

            # Update reading position with legacy frame.id cursor fallback
            pos = data.get("position")
            if is_valid_position(pos):
                if self.credentials:
                    self.credentials.position = merge_positions(self.credentials.position, pos)
                    self.credentials.save(self.credentials_path)
            else:
                frame_id = frame.get("id")
                fallback_seq: Optional[int] = None
                if isinstance(frame_id, str):
                    s = frame_id.strip()
                    if s.isascii() and s.isdigit():
                        try:
                            val = int(s)
                            if 0 <= val <= MAX_SAFE_INTEGER:
                                fallback_seq = val
                        except ValueError:
                            pass
                elif isinstance(frame_id, int) and not isinstance(frame_id, bool):
                    if 0 <= frame_id <= MAX_SAFE_INTEGER:
                        fallback_seq = frame_id

                if fallback_seq is not None and self.credentials:
                    self.credentials.position = merge_positions(
                        self.credentials.position, {"s": fallback_seq}
                    )
                    self.credentials.save(self.credentials_path)

            room_id = data.get("room_id")
            payload = data.get("payload", {})
            if not isinstance(payload, dict):
                return

            body = payload.get("body", "")
            sender = payload.get("sender_name") or payload.get("sender", "user")

            if not body or not room_id:
                return

            logger.info("Received addressed message in room %s from %s: %s", room_id, sender, body)
            loop = asyncio.get_running_loop()
            reply = await loop.run_in_executor(
                None, lambda: self.investigator.handle_message(body, sender=str(sender))
            )
            if reply:
                await self.send_message(room_id, reply)

    async def run(self) -> None:
        """Run the agent connection loop with bounded exponential backoff reconnection."""
        self.ensure_credentials()
        self._running = True

        backoff_delay = 1.0
        max_delay = 30.0
        backoff_factor = 2.0

        while self._running:
            ws_url = self.build_websocket_url()
            headers = {"Authorization": f"Bearer {self.credentials.agent_api_key}"}

            logger.info("Connecting to Switch WebSocket: %s", ws_url)
            try:
                # websockets.connect with headers
                async with websockets.connect(ws_url, additional_headers=headers) as ws:
                    logger.info("WebSocket connection established with Switch Core.")
                    backoff_delay = 1.0  # Reset backoff on successful connection

                    async for message in ws:
                        if not self._running:
                            break
                        await self.process_frame(ws, message)

            except (EvictedError, AuthenticationError) as e:
                logger.error("Terminal session error: %s. Terminating connection loop.", e)
                self._running = False
                raise
            except asyncio.CancelledError:
                logger.info("Agent run loop cancelled. Closing connection.")
                self._running = False
                break
            except Exception as e:
                if not self._running:
                    break
                # Bounded exponential backoff with jitter
                jitter = random.uniform(-0.2, 0.2) * backoff_delay
                sleep_time = max(0.5, min(max_delay, backoff_delay + jitter))
                logger.warning(
                    "WebSocket disconnected or failed (%s). Reconnecting in %.1fs...",
                    e,
                    sleep_time,
                )
                await asyncio.sleep(sleep_time)
                backoff_delay = min(max_delay, backoff_delay * backoff_factor)

    def stop(self) -> None:
        """Stop the running agent loop."""
        self._running = False
