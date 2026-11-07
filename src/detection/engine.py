"""Detection engine orchestrator for CyberTriage."""

import logging
from typing import List, Optional

from src.database.db import Database
from src.database.models import Alert
from src.detection.rules import (
    BaseRule,
    BruteForceRule,
    PrivilegeEscalationRule,
    SuspiciousLoginRule,
    UnusualAccessRule,
)
from src.events.models import SecurityEvent

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Evaluates security rules against telemetry events and manages alert creation and deduplication."""

    def __init__(self, db: Database, rules: Optional[List[BaseRule]] = None) -> None:
        self.db = db
        self.rules: List[BaseRule] = rules or [
            BruteForceRule(),
            SuspiciousLoginRule(),
            PrivilegeEscalationRule(),
            UnusualAccessRule(),
        ]

    def add_rule(self, rule: BaseRule) -> None:
        """Register a new detection rule."""
        self.rules.append(rule)
        logger.debug("Registered rule: %s", rule.name)

    def run_detection(self, events: Optional[List[SecurityEvent]] = None) -> List[Alert]:
        """
        Run all registered rules against events and insert non-duplicate alerts.
        If events is None, fetches all events from the database.
        """
        if events is None:
            events = self.db.get_all_events()

        if not events:
            logger.info("No security events to analyze.")
            return []

        # Ensure events are ordered chronologically by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        new_alerts: List[Alert] = []

        logger.info("Evaluating %d events against %d rules...", len(sorted_events), len(self.rules))

        for rule in self.rules:
            try:
                candidate_alerts = rule.evaluate(sorted_events)
                for alert in candidate_alerts:
                    # Deduplication check: check if an alert for this rule already references these evidence IDs
                    if self.db.alert_exists_with_evidence(alert.rule_name, alert.evidence_event_ids):
                        logger.debug(
                            "Skipping duplicate alert '%s' for evidence %s",
                            alert.title,
                            alert.evidence_event_ids,
                        )
                        continue

                    # Insert new alert
                    self.db.insert_alert(alert)
                    new_alerts.append(alert)
                    logger.warning("🚨 [ALERT DETECTED] %s - %s", alert.severity, alert.title)
            except Exception as e:
                logger.error("Error evaluating rule '%s': %s", rule.name, e, exc_info=True)

        logger.info("Detection cycle complete: %d new alerts generated.", len(new_alerts))
        return new_alerts
