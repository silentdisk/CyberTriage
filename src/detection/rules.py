"""Detection rules for CyberTriage."""

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
import logging
from typing import Dict, List, Tuple

from src.database.models import Alert
from src.events.models import SecurityEvent

logger = logging.getLogger(__name__)


def parse_iso_timestamp(ts_str: str) -> float:
    """Helper to convert ISO-8601 timestamp string to POSIX seconds float."""
    try:
        # Handles trailing Z or offset
        normalized = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        return dt.timestamp()
    except Exception:
        return 0.0


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    def __init__(self, name: str, description: str, default_severity: str = "MEDIUM") -> None:
        self.name = name
        self.description = description
        self.default_severity = default_severity

    @abstractmethod
    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        """Evaluate a chronologically sorted sequence of security events and return alerts."""
        raise NotImplementedError


class BruteForceRule(BaseRule):
    """Detects brute-force authentication attacks (e.g. >= 5 failed logins within 300 seconds)."""

    def __init__(self, threshold: int = 5, window_seconds: int = 300) -> None:
        super().__init__(
            name="BruteForceLogin",
            description="Detects multiple failed login attempts from a single source within a time window.",
            default_severity="HIGH",
        )
        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        # Filter for auth_failure events
        failures = [e for e in events if e.event_type == "auth_failure"]

        # Group by (src_ip, user)
        grouped: Dict[Tuple[str, str], List[SecurityEvent]] = defaultdict(list)
        for e in failures:
            grouped[(e.src_ip, e.user)].append(e)

        for (ip, user), ev_list in grouped.items():
            if len(ev_list) < self.threshold:
                continue

            # Sliding window over the failures
            n = len(ev_list)
            for i in range(n):
                window_events = [ev_list[i]]
                start_ts = parse_iso_timestamp(ev_list[i].timestamp)

                for j in range(i + 1, n):
                    curr_ts = parse_iso_timestamp(ev_list[j].timestamp)
                    if curr_ts - start_ts <= self.window_seconds:
                        window_events.append(ev_list[j])
                    else:
                        break

                if len(window_events) >= self.threshold:
                    evidence_ids = [e.event_id for e in window_events]
                    hostname = window_events[0].hostname
                    last_ts = window_events[-1].timestamp

                    alert = Alert(
                        rule_name=self.name,
                        severity=self.default_severity,
                        title=f"Brute Force Authentication Attempt ({ip} -> {user})",
                        description=(
                            f"Detected {len(window_events)} failed login attempts from source IP {ip} "
                            f"targeting user '{user}' on {hostname} within {self.window_seconds} seconds."
                        ),
                        timestamp=last_ts,
                        evidence_event_ids=evidence_ids,
                        entity_user=user,
                        entity_ip=ip,
                        entity_host=hostname,
                        details={
                            "attempt_count": len(window_events),
                            "window_seconds": self.window_seconds,
                            "attack_type": "credential_brute_force",
                        },
                    )
                    alerts.append(alert)
                    # Skip to the end of this cluster to avoid sliding-window sub-duplicate alerts
                    break

        return alerts


class SuspiciousLoginRule(BaseRule):
    """Detects suspicious login patterns: logins from known suspicious IPs or service accounts from anomalous hosts."""

    SUSPICIOUS_IP_PREFIXES = ("198.51.100.", "203.0.113.", "192.0.2.")

    def __init__(self, failure_window_seconds: int = 300) -> None:
        super().__init__(
            name="SuspiciousLoginPattern",
            description="Detects successful authentications from anomalous or known high-risk external IP addresses.",
            default_severity="HIGH",
        )
        self.failure_window_seconds = failure_window_seconds

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        successes = [e for e in events if e.event_type == "auth_success"]
        failures = [e for e in events if e.event_type == "auth_failure"]

        for event in successes:
            is_suspicious_ip = any(event.src_ip.startswith(prefix) for prefix in self.SUSPICIOUS_IP_PREFIXES)
            threat_intel = event.details.get("threat_intel") or event.details.get("anomaly")
            is_service_acc = event.user.startswith("svc_")

            # Correlate only with failed logins from the SAME source IP that occurred BEFORE this success event,
            # within a bounded window of 300 seconds. Future failed logins must never escalate a past successful login.
            success_ts = parse_iso_timestamp(event.timestamp)
            prior_failures = [
                f for f in failures
                if f.src_ip == event.src_ip
                and parse_iso_timestamp(f.timestamp) <= success_ts
                and (success_ts - parse_iso_timestamp(f.timestamp)) <= self.failure_window_seconds
                and (
                    parse_iso_timestamp(f.timestamp) < success_ts
                    or events.index(f) < events.index(event)
                )
            ]
            followed_failures = len(prior_failures) > 0

            if is_suspicious_ip or threat_intel or (is_service_acc and is_suspicious_ip):
                severity = "CRITICAL" if followed_failures else self.default_severity
                reasons = []
                if is_suspicious_ip:
                    reasons.append(f"originates from high-risk external network {event.src_ip}")
                if threat_intel:
                    reasons.append(f"threat intelligence indicator: {threat_intel}")
                if followed_failures:
                    reasons.append("login succeeded following previous authentication failures from same IP (potential compromise)")

                reason_str = "; ".join(reasons)
                alert = Alert(
                    rule_name=self.name,
                    severity=severity,
                    title=f"Suspicious Login Activity ({event.user} from {event.src_ip})",
                    description=(
                        f"Successful login for user '{event.user}' on host {event.hostname} flagged as suspicious: {reason_str}."
                    ),
                    timestamp=event.timestamp,
                    evidence_event_ids=[event.event_id],
                    entity_user=event.user,
                    entity_ip=event.src_ip,
                    entity_host=event.hostname,
                    details={
                        "threat_intel": threat_intel,
                        "followed_failures": followed_failures,
                    },
                )
                alerts.append(alert)

        return alerts


class PrivilegeEscalationRule(BaseRule):
    """Detects suspicious privilege escalation attempts (sudo interactive shells, SUID changes, sudoers modifications)."""

    SUPPORTED_ELEVATION_ACTIONS = ("sudo_exec", "chmod_suid")

    def __init__(self) -> None:
        super().__init__(
            name="PrivilegeEscalationAttempt",
            description="Detects execution of administrative commands and privilege escalation indicators.",
            default_severity="CRITICAL",
        )

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        escalation_events = [
            e for e in events
            if e.event_type == "privilege_escalation"
            or (
                e.action in self.SUPPORTED_ELEVATION_ACTIONS
                and bool(e.details.get("elevation_type") or e.details.get("technique"))
            )
        ]

        # Group by (hostname, user) to consolidate multi-step escalation sequences
        grouped: Dict[Tuple[str, str], List[SecurityEvent]] = defaultdict(list)
        for e in escalation_events:
            grouped[(e.hostname, e.user)].append(e)

        for (host, user), ev_list in grouped.items():
            evidence_ids = [e.event_id for e in ev_list]
            commands = [e.details.get("command", e.action) for e in ev_list]
            cmd_summary = ", ".join(f"'{c}'" for c in commands[:3])

            alert = Alert(
                rule_name=self.name,
                severity=self.default_severity,
                title=f"Privilege Escalation Detected ({user} on {host})",
                description=(
                    f"User '{user}' performed {len(ev_list)} suspicious privilege escalation actions on {host}. "
                    f"Commands observed: {cmd_summary}."
                ),
                timestamp=ev_list[-1].timestamp,
                evidence_event_ids=evidence_ids,
                entity_user=user,
                entity_ip=ev_list[0].src_ip,
                entity_host=host,
                details={
                    "commands": commands,
                    "escalation_count": len(ev_list),
                    "target_user": "root",
                },
            )
            alerts.append(alert)

        return alerts


class UnusualAccessRule(BaseRule):
    """Detects unusual or unauthorized access to sensitive critical files/endpoints."""

    SENSITIVE_TARGETS = ("/etc/shadow", "/root/.ssh", ".ssh/id_rsa", "/var/run/docker.sock")

    def __init__(self) -> None:
        super().__init__(
            name="UnusualSensitiveAccess",
            description="Detects attempts to access sensitive system files or credentials.",
            default_severity="HIGH",
        )

    def evaluate(self, events: List[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        unusual_events = [e for e in events if e.event_type == "unusual_access"]

        for event in unusual_events:
            resource = event.details.get("resource", "unknown_resource")
            alert = Alert(
                rule_name=self.name,
                severity=self.default_severity,
                title=f"Unusual Sensitive Resource Access ({event.user} -> {resource})",
                description=(
                    f"User '{event.user}' on {event.hostname} attempted unauthorized access to sensitive resource '{resource}'."
                ),
                timestamp=event.timestamp,
                evidence_event_ids=[event.event_id],
                entity_user=event.user,
                entity_ip=event.src_ip,
                entity_host=event.hostname,
                details=event.details,
            )
            alerts.append(alert)

        return alerts
