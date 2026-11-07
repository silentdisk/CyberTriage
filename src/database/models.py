"""Database models for CyberTriage."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class Alert:
    """Represents a structured security detection alert."""

    alert_id: str = field(default_factory=lambda: f"alt_{uuid.uuid4().hex[:12]}")
    rule_name: str = "UnknownRule"
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    title: str = "Security Alert"
    description: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence_event_ids: List[str] = field(default_factory=list)
    entity_user: Optional[str] = None
    entity_ip: Optional[str] = None
    entity_host: Optional[str] = None
    status: str = "NEW"  # NEW, INVESTIGATING, CLOSED
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the Alert to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Create an Alert instance from a dictionary."""
        evidence_ids = data.get("evidence_event_ids", [])
        if isinstance(evidence_ids, str):
            try:
                evidence_ids = json.loads(evidence_ids)
            except (json.JSONDecodeError, TypeError):
                evidence_ids = [evidence_ids] if evidence_ids else []

        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (json.JSONDecodeError, TypeError):
                details = {"raw": details}

        return cls(
            alert_id=str(data.get("alert_id", f"alt_{uuid.uuid4().hex[:12]}")),
            rule_name=str(data.get("rule_name", "UnknownRule")),
            severity=str(data.get("severity", "MEDIUM")).upper(),
            title=str(data.get("title", "Security Alert")),
            description=str(data.get("description", "")),
            timestamp=str(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            evidence_event_ids=list(evidence_ids) if isinstance(evidence_ids, (list, tuple)) else [],
            entity_user=data.get("entity_user"),
            entity_ip=data.get("entity_ip"),
            entity_host=data.get("entity_host"),
            status=str(data.get("status", "NEW")),
            details=details if isinstance(details, dict) else {},
        )
