"""Security event data models for CyberTriage."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict
import uuid


@dataclass
class SecurityEvent:
    """Represents a simulated security telemetry event."""

    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = "auth_success"  # auth_success, auth_failure, privilege_escalation, unusual_access, process_exec
    user: str = "unknown"
    src_ip: str = "127.0.0.1"
    hostname: str = "host-01"
    action: str = "login"
    details: Dict[str, Any] = field(default_factory=dict)
    is_simulated: bool = True  # Explicitly labels all events as simulated

    def to_dict(self) -> Dict[str, Any]:
        """Convert the SecurityEvent to a dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize event to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Create a SecurityEvent instance from a dictionary."""
        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (json.JSONDecodeError, TypeError):
                details = {"raw": details}

        return cls(
            event_id=str(data.get("event_id", f"evt_{uuid.uuid4().hex[:12]}")),
            timestamp=str(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            event_type=str(data.get("event_type", "unknown")),
            user=str(data.get("user", "unknown")),
            src_ip=str(data.get("src_ip", "127.0.0.1")),
            hostname=str(data.get("hostname", "host-01")),
            action=str(data.get("action", "unknown")),
            details=details if isinstance(details, dict) else {},
            is_simulated=bool(data.get("is_simulated", True)),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SecurityEvent":
        """Deserialize event from a JSON string."""
        return cls.from_dict(json.loads(json_str))
