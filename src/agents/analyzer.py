"""Incident investigation and evidence analysis logic for CyberTriage."""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from src.database.db import Database
from src.database.models import Alert
from src.events.models import SecurityEvent

logger = logging.getLogger(__name__)


class IncidentAnalyzer:
    """Investigates security alerts and formats evidence-based incident reports."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def handle_message(self, message_body: str, sender: str = "user") -> Optional[str]:
        """Parse incoming chat messages and dispatch investigation requests.

        Supports:
            investigate <alert_id>
        """
        if not message_body or not isinstance(message_body, str):
            return None

        # Strictly match 'investigate <alert_id>'
        match = re.search(r"\binvestigate\s+([A-Za-z0-9_\-]+)\b", message_body.strip(), re.IGNORECASE)
        if not match:
            return (
                "CyberTriage SOC Agent: Unrecognized command. "
                "Send `investigate <ALERT_ID>` to retrieve linked incident evidence."
            )

        alert_id = match.group(1).strip()
        return self.investigate_alert(alert_id)

    def investigate_alert(self, alert_id: str) -> str:
        """Retrieve alert details and linked evidence, returning a structured Markdown report."""
        alert: Optional[Alert] = self.db.get_alert(alert_id)
        if alert is None:
            return (
                f"[-] Incident Investigation Error: Alert `{alert_id}` was not found "
                f"in the CyberTriage evidence database."
            )

        evidence_events = self.db.get_events_by_ids(alert.evidence_event_ids)
        return self._format_investigation_report(alert, evidence_events)

    def _format_investigation_report(
        self, alert: Alert, evidence_events: list[SecurityEvent]
    ) -> str:
        """Format an alert and its verified evidence events into an incident report."""
        lines = [
            f"### 🚨 CyberTriage Incident Investigation: {alert.alert_id}",
            f"**Title:** {alert.title}",
            f"**Severity:** {alert.severity.upper()} | **Detection Rule:** `{alert.rule_name}`",
            f"**Detected At:** {alert.timestamp}",
            f"**Entities:** User: `{alert.entity_user or 'N/A'}` | Host: `{alert.entity_host or 'N/A'}` | IP: `{alert.entity_ip or 'N/A'}`",
            f"**Status:** {alert.status}",
            "",
            "#### Summary",
            alert.description or "No description provided.",
            "",
            f"#### Linked Evidence Events ({len(evidence_events)} verified record(s))",
        ]

        if not evidence_events:
            lines.append("  *No raw evidence events found corresponding to evidence IDs.*")
        else:
            for idx, ev in enumerate(evidence_events, 1):
                timestamp_short = ev.timestamp[:19] if ev.timestamp else "N/A"
                details_json = json.dumps(ev.details, separators=(",", ": "))
                lines.append(
                    f"{idx}. **[{ev.event_id}]** `{timestamp_short}` | Type: `{ev.event_type}` | Action: `{ev.action}`\n"
                    f"   *Host:* `{ev.hostname}` | *User:* `{ev.user}` | *Src IP:* `{ev.src_ip}`\n"
                    f"   *Details:* `{details_json}`"
                )

        lines.extend([
            "",
            "#### Triage Guidance (Informational Only)",
            self._generate_recommendation(alert),
        ])

        return "\n".join(lines)

    def _generate_recommendation(self, alert: Alert) -> str:
        """Generate non-automated SOC analyst triage suggestions based on rule."""
        rule = alert.rule_name.lower()
        if "bruteforce" in rule:
            return (
                f"- Review authentication logs for source IP `{alert.entity_ip}` across adjacent services.\n"
                f"- Verify whether account `{alert.entity_user}` shows subsequent successful logins from unexpected locations.\n"
                f"- Consider temporary perimeter firewall containment pending analyst review."
            )
        elif "privilegeescalation" in rule:
            return (
                f"- Audit active processes and recent privilege delegation commands on host `{alert.entity_host}`.\n"
                f"- Inspect `/etc/sudoers` modifications and review user `{alert.entity_user}` session history.\n"
                f"- Coordinate host isolation if unauthorized elevation is confirmed."
            )
        elif "suspiciouslogin" in rule:
            return (
                f"- Verify if source IP `{alert.entity_ip}` belongs to known corporate VPN, egress, or cloud provider.\n"
                f"- Contact user `{alert.entity_user}` for out-of-band verification of the login attempt.\n"
                f"- Recommend session token revocation if unconfirmed."
            )
        else:
            return "- Correlate event telemetry against standard entity baseline activity."
