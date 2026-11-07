"""Gemini AI Investigation Engine for CyberTriage.

Implements autonomous, tool-grounded SOC incident investigation using Google GenAI SDK
and function calling against the local SQLite evidence database.
Gracefully falls back to deterministic rule analysis when Gemini is unavailable or fails.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import dotenv_values

from src.agents.analyzer import IncidentAnalyzer
from src.agents.investigation_tools import execute_tool, get_gemini_tool_declarations
from src.database.db import Database

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"
MAX_TOOL_CALL_ROUNDS = 5

SYSTEM_INSTRUCTION = """You are CyberTriage AI, an expert Tier-2 SOC Incident Investigation Analyst.
You operate in a STRICTLY SIMULATED SOC ENVIRONMENT. All security events and alerts are simulated telemetry.

CRITICAL RULES:
1. EVIDENCE GROUNDING: You must ONLY state facts and conclusions directly supported by evidence retrieved through your investigation tools. NEVER fabricate, hallucinate, or assume event IDs, timestamps, usernames, IP addresses, hostnames, or attack details that are not in the tool results.
2. TOOL USAGE: Actively use the provided investigation tools to query the database:
   - get_alert(alert_id): Retrieve details for a specific alert by ID.
   - get_alert_evidence(alert_id, limit): Retrieve verified raw evidence events linked to an alert.
   - search_events(ip, user, hostname, event_type, limit): Search historical telemetry for correlated activity.
   - list_alerts(severity, status, limit): List recent alerts filtered by severity or status.
3. SIMULATION LABELING: Explicitly label all telemetry, findings, and alerts as simulated (e.g., 'Simulation-only telemetry').
4. STRUCTURED REPORTS: When asked to investigate an alert, format your response cleanly in Markdown:
   - 🚨 Incident Investigation Summary & Severity
   - Key Entities (User, Source IP, Target Host)
   - Verified Evidence Timeline (cite specific Event IDs and timestamps)
   - Correlated Telemetry & Root Cause Assessment
   - Triage Guidance (simulation-only next steps for the SOC analyst)
5. CONVERSATIONAL QUERIES: If the analyst asks conversational questions (e.g., 'show latest high severity alerts', 'are there failed logins from IP X?'), use tools directly and answer concisely based on verified results.
"""


def _load_api_key() -> Optional[str]:
    """Securely resolve Gemini API key without leaking into logs or terminal."""
    # 1. Environment variable
    key = os.environ.get("GEMINI_API_KEY")
    if key and key.strip():
        return key.strip()

    # 2. Local .env file
    env_path = Path(".env")
    if env_path.exists():
        try:
            values = dotenv_values(str(env_path))
            key = values.get("GEMINI_API_KEY")
            if key and key.strip():
                return key.strip()
        except Exception:
            pass

    return None


class GeminiInvestigator:
    """Orchestrates Gemini AI function calling for SOC incident investigation."""

    def __init__(
        self,
        db: Optional[Database] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        fallback_analyzer: Optional[IncidentAnalyzer] = None,
        max_iterations: int = MAX_TOOL_CALL_ROUNDS,
    ) -> None:
        self.db = db or Database()
        self.model = model or os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
        self.max_iterations = max_iterations
        self.fallback_analyzer = fallback_analyzer or IncidentAnalyzer(self.db)

        self.api_key = api_key or _load_api_key()
        self.client: Any = None
        self.available = False

        if self.api_key:
            try:
                from google.genai import Client

                self.client = Client(api_key=self.api_key)
                self.available = True
                logger.info("GeminiInvestigator initialized with model '%s'.", self.model)
            except Exception as e:
                logger.warning(
                    "Failed to initialize Google GenAI Client: %s. Fallback analyzer enabled.",
                    e,
                )
                self.available = False
        else:
            logger.info("No GEMINI_API_KEY detected. Using deterministic fallback analyzer.")

    def handle_message(self, message_body: str, sender: str = "user") -> Optional[str]:
        """Process incoming chat messages using Gemini AI with function calling.

        Gracefully falls back to IncidentAnalyzer if Gemini is unavailable or errors occur.
        """
        if not message_body or not isinstance(message_body, str):
            return None

        # If Gemini is not configured, immediately use deterministic analyzer
        if not self.available or not self.client:
            logger.info(
                "Deterministic fallback analyzer activated (reason: Gemini AI unavailable or unconfigured)."
            )
            return self.fallback_analyzer.handle_message(message_body, sender=sender)

        try:
            return self._investigate_with_gemini(message_body, sender=sender)
        except Exception as e:
            logger.warning(
                "Deterministic fallback analyzer activated (reason: Gemini AI investigation error - %s: %s).",
                type(e).__name__,
                e,
            )
            # Safe deterministic fallback
            return self.fallback_analyzer.handle_message(message_body, sender=sender)

    def _investigate_with_gemini(self, message_body: str, sender: str) -> str:
        """Run the multi-turn Gemini function-calling loop against SQLite tools."""
        from google.genai import types

        logger.info(
            "Starting Gemini investigation for sender '%s' using model '%s'.",
            sender,
            self.model,
        )

        tool_definition = get_gemini_tool_declarations()
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=[tool_definition],
            temperature=0.1,  # Low temperature for strict factual grounding
        )

        user_content = f"Analyst ({sender}): {message_body.strip()}"
        messages: List[Any] = [
            types.Content(role="user", parts=[types.Part(text=user_content)])
        ]

        final_response_text = ""

        for step in range(self.max_iterations):
            response = self.client.models.generate_content(
                model=self.model,
                contents=messages,
                config=config,
            )

            # Check if Gemini requested function calls
            if response.function_calls:
                tool_names = [fc.name for fc in response.function_calls]
                logger.info(
                    "Gemini step %d requested %d function call(s): %s",
                    step,
                    len(response.function_calls),
                    tool_names,
                )

                # Append the model's tool request candidate
                if response.candidates and response.candidates[0].content:
                    messages.append(response.candidates[0].content)

                # Execute requested tools in Python and format responses
                response_parts: List[Any] = []
                for fc in response.function_calls:
                    call_name = fc.name
                    call_args = dict(fc.args or {})
                    logger.info("Executing Python tool '%s'.", call_name)
                    tool_result = execute_tool(call_name, call_args, db=self.db)

                    is_error = isinstance(tool_result, dict) and (
                        "error" in tool_result or tool_result.get("status") == "error"
                    )
                    if is_error:
                        logger.warning(
                            "Python tool '%s' execution failed: %s",
                            call_name,
                            tool_result.get("error", "Unknown error"),
                        )
                    else:
                        logger.info(
                            "Python tool '%s' executed successfully (status: %s).",
                            call_name,
                            tool_result.get("status_code")
                            or tool_result.get("status")
                            or "success",
                        )

                    # Build function response part with matching call ID if present
                    f_resp = types.FunctionResponse(
                        name=call_name,
                        id=fc.id,
                        response={"result": tool_result},
                    )
                    response_parts.append(types.Part(function_response=f_resp))

                # Return tool results back to the model as user role
                messages.append(types.Content(role="user", parts=response_parts))

            else:
                # No more function calls requested; extract text
                if response.text:
                    final_response_text = response.text
                elif response.candidates and response.candidates[0].content:
                    text_parts = [
                        p.text
                        for p in response.candidates[0].content.parts
                        if getattr(p, "text", None)
                    ]
                    final_response_text = "".join(text_parts)
                break

        if not final_response_text:
            # If function calling did not produce text, invoke fallback
            logger.info(
                "Deterministic fallback analyzer activated (reason: Gemini function-calling loop returned empty text)."
            )
            fallback_res = self.fallback_analyzer.handle_message(message_body, sender=sender)
            return fallback_res or "CyberTriage: Investigation completed with no output."

        logger.info(
            "Gemini generated final investigation report (%d characters).",
            len(final_response_text),
        )
        return final_response_text
