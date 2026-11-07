"""Controlled Python investigation tools for CyberTriage SOC agent.

Provides secure, parameterized evidence retrieval tools for Gemini AI function calling
and automated incident investigation against the local SQLite evidence database.
Raw SQL execution and unrestricted database access are strictly forbidden.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from src.database.db import Database
from src.database.models import Alert
from src.events.models import SecurityEvent

logger = logging.getLogger(__name__)

# Security boundaries
MAX_ALERT_ID_LENGTH = 128
ALERT_ID_REGEX = re.compile(r"^[A-Za-z0-9_\-]+$")
MAX_SEARCH_LIMIT = 50
DEFAULT_SEARCH_LIMIT = 20
MAX_EVIDENCE_LIMIT = 100
DEFAULT_EVIDENCE_LIMIT = 50
MAX_PARAM_LENGTH = 128


def validate_alert_id(alert_id: Any) -> Optional[str]:
    """Validate alert ID string for safe querying.

    Returns:
        Cleaned alert_id string if valid, None otherwise.
    """
    if not isinstance(alert_id, str):
        return None
    cleaned = alert_id.strip()
    if not cleaned or len(cleaned) > MAX_ALERT_ID_LENGTH:
        return None
    if not ALERT_ID_REGEX.match(cleaned):
        return None
    return cleaned


def _sanitize_string(val: Any) -> Optional[str]:
    """Sanitize and validate a filter parameter string."""
    if val is None:
        return None
    if not isinstance(val, str):
        val = str(val)
    cleaned = val.strip()
    if not cleaned or len(cleaned) > MAX_PARAM_LENGTH:
        return None
    return cleaned


def get_alert(alert_id: str, db: Optional[Database] = None) -> Dict[str, Any]:
    """Retrieve details for a single security alert by its alert ID.

    Args:
        alert_id: The unique identifier of the alert (e.g., 'alt_12345').
        db: Optional Database instance. Defaults to standard Database().

    Returns:
        JSON-serializable dictionary with alert details, or an error dictionary.
    """
    cleaned_id = validate_alert_id(alert_id)
    if not cleaned_id:
        return {
            "error": f"Invalid alert_id '{alert_id}'. Alert ID must be a non-empty string containing only alphanumeric characters, hyphens, and underscores (max 128 chars).",
            "status": "error",
            "is_simulated": True,
        }

    database = db or Database()
    alert: Optional[Alert] = database.get_alert(cleaned_id)
    if alert is None:
        return {
            "error": f"Alert '{cleaned_id}' was not found in the CyberTriage evidence database.",
            "status": "not_found",
            "alert_id": cleaned_id,
            "is_simulated": True,
        }

    alert_dict = alert.to_dict()
    alert_dict["is_simulated"] = True
    alert_dict["status_code"] = "success"
    return alert_dict


def get_alert_evidence(
    alert_id: str,
    limit: Optional[int] = DEFAULT_EVIDENCE_LIMIT,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """Retrieve verified raw security evidence events linked to a specific alert.

    Args:
        alert_id: The unique identifier of the alert.
        limit: Maximum number of evidence events to return (1-100, default 50).
        db: Optional Database instance. Defaults to standard Database().

    Returns:
        JSON-serializable dictionary with verified evidence events.
    """
    cleaned_id = validate_alert_id(alert_id)
    if not cleaned_id:
        return {
            "error": f"Invalid alert_id '{alert_id}'. Alert ID must be a non-empty string containing only alphanumeric characters, hyphens, and underscores.",
            "status": "error",
            "events": [],
            "evidence_events": [],
            "is_simulated": True,
        }

    database = db or Database()
    alert: Optional[Alert] = database.get_alert(cleaned_id)
    if alert is None:
        return {
            "error": f"Alert '{cleaned_id}' was not found in the CyberTriage evidence database.",
            "status": "not_found",
            "alert_id": cleaned_id,
            "events": [],
            "evidence_events": [],
            "is_simulated": True,
        }

    # Bounded limit check
    effective_limit = DEFAULT_EVIDENCE_LIMIT
    if isinstance(limit, int) and limit > 0:
        effective_limit = min(limit, MAX_EVIDENCE_LIMIT)

    evidence_ids = alert.evidence_event_ids or []
    target_ids = evidence_ids[:effective_limit]

    events: List[SecurityEvent] = database.get_events_by_ids(target_ids) if target_ids else []

    event_dicts = []
    for ev in events:
        ev_dict = ev.to_dict()
        # Guarantee explicit simulated label on every event result
        ev_dict["is_simulated"] = True
        event_dicts.append(ev_dict)

    return {
        "alert_id": cleaned_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "evidence_events": event_dicts,
        "events": event_dicts,  # Alias for convenience
        "count": len(event_dicts),
        "total_evidence_ids": len(evidence_ids),
        "is_simulated": True,
        "status_code": "success",
    }


def search_events(
    ip: Optional[str] = None,
    user: Optional[str] = None,
    hostname: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: Optional[int] = DEFAULT_SEARCH_LIMIT,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """Search related security telemetry events by IP, user, hostname, or event type.

    Args:
        ip: Optional source IP filter.
        user: Optional target username filter.
        hostname: Optional target host filter.
        event_type: Optional event type filter (e.g., 'auth_failure', 'auth_success', 'privilege_escalation').
        limit: Maximum number of events to return (1-50, default 20).
        db: Optional Database instance. Defaults to standard Database().

    Returns:
        JSON-serializable dictionary with matching events.
    """
    database = db or Database()

    # Sanitize inputs
    clean_ip = _sanitize_string(ip)
    clean_user = _sanitize_string(user)
    clean_host = _sanitize_string(hostname)
    clean_type = _sanitize_string(event_type)

    effective_limit = DEFAULT_SEARCH_LIMIT
    if isinstance(limit, int) and limit > 0:
        effective_limit = min(limit, MAX_SEARCH_LIMIT)

    # Use database get_events with safety parameters
    # If hostname filter is requested, fetch a slightly larger window to post-filter cleanly
    fetch_limit = min(effective_limit * 3, 100) if clean_host else effective_limit
    raw_events: List[SecurityEvent] = database.get_events(
        limit=fetch_limit,
        event_type=clean_type,
        user=clean_user,
        ip=clean_ip,
    )

    if clean_host:
        filtered = [e for e in raw_events if e.hostname.lower() == clean_host.lower()]
    else:
        filtered = raw_events

    final_events = filtered[:effective_limit]
    event_dicts = []
    for ev in final_events:
        ev_dict = ev.to_dict()
        ev_dict["is_simulated"] = True
        event_dicts.append(ev_dict)

    return {
        "query": {
            "ip": clean_ip,
            "user": clean_user,
            "hostname": clean_host,
            "event_type": clean_type,
        },
        "events": event_dicts,
        "count": len(event_dicts),
        "limit": effective_limit,
        "is_simulated": True,
        "status_code": "success",
    }


def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = 10,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """List recent security alerts filtered by severity or status.

    Args:
        severity: Optional severity filter ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        status: Optional alert status filter ('NEW', 'INVESTIGATING', 'CLOSED').
        limit: Maximum number of alerts to return (1-50, default 10).
        db: Optional Database instance. Defaults to standard Database().

    Returns:
        JSON-serializable dictionary with alerts list.
    """
    database = db or Database()

    clean_severity = _sanitize_string(severity)
    if clean_severity:
        clean_severity = clean_severity.upper()

    clean_status = _sanitize_string(status)
    if clean_status:
        clean_status = clean_status.upper()

    effective_limit = 10
    if isinstance(limit, int) and limit > 0:
        effective_limit = min(limit, MAX_SEARCH_LIMIT)

    alerts: List[Alert] = database.get_alerts(
        limit=effective_limit,
        severity=clean_severity,
        status=clean_status,
    )

    alert_dicts = []
    for a in alerts:
        ad = a.to_dict()
        ad["is_simulated"] = True
        alert_dicts.append(ad)

    return {
        "query": {
            "severity": clean_severity,
            "status": clean_status,
            "limit": effective_limit,
        },
        "alerts": alert_dicts,
        "count": len(alert_dicts),
        "is_simulated": True,
        "status_code": "success",
    }


# Aliases for flexible integration
get_alert_by_id = get_alert
get_evidence_events = get_alert_evidence
get_verified_evidence = get_alert_evidence


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """Secure dispatch router for Gemini tool calls.

    Validates tool names against allowed tools and executes corresponding Python function.
    """
    tool_map = {
        "get_alert": lambda args: get_alert(alert_id=str(args.get("alert_id", "")), db=db),
        "get_alert_evidence": lambda args: get_alert_evidence(
            alert_id=str(args.get("alert_id", "")),
            limit=args.get("limit", DEFAULT_EVIDENCE_LIMIT),
            db=db,
        ),
        "search_events": lambda args: search_events(
            ip=args.get("ip"),
            user=args.get("user"),
            hostname=args.get("hostname"),
            event_type=args.get("event_type"),
            limit=args.get("limit", DEFAULT_SEARCH_LIMIT),
            db=db,
        ),
        "list_alerts": lambda args: list_alerts(
            severity=args.get("severity"),
            status=args.get("status"),
            limit=args.get("limit", 10),
            db=db,
        ),
    }

    if tool_name not in tool_map:
        return {
            "error": f"Unknown tool '{tool_name}'. Available tools: {list(tool_map.keys())}",
            "status": "error",
            "is_simulated": True,
        }

    try:
        return tool_map[tool_name](arguments or {})
    except Exception as e:
        logger.error("Error executing tool '%s' with args %s: %s", tool_name, arguments, e)
        return {
            "error": f"Tool execution failed: {str(e)}",
            "status": "error",
            "is_simulated": True,
        }


def get_gemini_tool_declarations() -> Any:
    """Construct Google GenAI types.Tool definitions for Gemini function calling."""
    from google.genai import types

    func_get_alert = types.FunctionDeclaration(
        name="get_alert",
        description="Retrieve details of a single security detection alert by its alert ID (e.g. 'alt_12345').",
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "alert_id": types.Schema(
                    type=types.Type.STRING,
                    description="The unique alert ID (e.g. 'alt_xxxx').",
                )
            },
            required=["alert_id"],
        ),
    )

    func_get_evidence = types.FunctionDeclaration(
        name="get_alert_evidence",
        description="Retrieve only the verified raw security evidence events linked to a specific alert ID.",
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "alert_id": types.Schema(
                    type=types.Type.STRING,
                    description="The unique alert ID to fetch linked evidence for.",
                ),
                "limit": types.Schema(
                    type=types.Type.INTEGER,
                    description="Maximum number of evidence events to return (default 50, max 100).",
                ),
            },
            required=["alert_id"],
        ),
    )

    func_search_events = types.FunctionDeclaration(
        name="search_events",
        description="Search related simulated security events by source IP, user, hostname, or event type.",
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "ip": types.Schema(
                    type=types.Type.STRING,
                    description="Filter by source IP address (e.g., '198.51.100.23').",
                ),
                "user": types.Schema(
                    type=types.Type.STRING,
                    description="Filter by target username (e.g., 'admin', 'alice').",
                ),
                "hostname": types.Schema(
                    type=types.Type.STRING,
                    description="Filter by host/machine name (e.g., 'bastion-host').",
                ),
                "event_type": types.Schema(
                    type=types.Type.STRING,
                    description="Filter by event type (e.g., 'auth_failure', 'auth_success', 'privilege_escalation').",
                ),
                "limit": types.Schema(
                    type=types.Type.INTEGER,
                    description="Maximum number of events to return (default 20, max 50).",
                ),
            },
        ),
    )

    func_list_alerts = types.FunctionDeclaration(
        name="list_alerts",
        description="List recent security alerts filtered by severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') or status ('NEW', 'INVESTIGATING', 'CLOSED').",
        parameters=types.Schema(
            type=types.Type.OBJECT,
            properties={
                "severity": types.Schema(
                    type=types.Type.STRING,
                    description="Filter by severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').",
                ),
                "status": types.Schema(
                    type=types.Type.STRING,
                    description="Filter by status ('NEW', 'INVESTIGATING', 'CLOSED').",
                ),
                "limit": types.Schema(
                    type=types.Type.INTEGER,
                    description="Maximum number of alerts to return (default 10, max 50).",
                ),
            },
        ),
    )

    return types.Tool(
        function_declarations=[
            func_get_alert,
            func_get_evidence,
            func_search_events,
            func_list_alerts,
        ]
    )
