"""Simulated security event generator for CyberTriage."""

from datetime import datetime, timedelta, timezone
import random
from typing import Any, Dict, List, Optional
import uuid

from src.events.models import SecurityEvent


class EventSimulator:
    """Generates synthetic, labeled security events for detection and triage."""

    BENIGN_USERS = ["alice", "bob", "charlie", "david", "svc_deploy"]
    PRIVILEGED_USERS = ["admin", "root", "secops"]
    SERVICE_ACCOUNTS = ["svc_backup", "svc_monitoring", "svc_database"]

    INTERNAL_IPS = [
        "10.0.1.15",
        "10.0.1.42",
        "10.0.2.100",
        "192.168.1.55",
        "192.168.1.80",
    ]
    SUSPICIOUS_IPS = [
        "198.51.100.23",
        "203.0.113.45",
        "203.0.113.99",
        "192.0.2.105",
    ]
    HOSTNAMES = [
        "workstation-eng-01",
        "corp-auth-srv",
        "finance-app-02",
        "bastion-host",
        "db-prod-01",
    ]

    def __init__(self, base_time: Optional[datetime] = None) -> None:
        self.base_time = base_time or datetime.now(timezone.utc)
        self._current_time = self.base_time

    def _tick(self, seconds_min: int = 1, seconds_max: int = 15) -> datetime:
        """Advance the simulated internal clock."""
        delta = timedelta(seconds=random.randint(seconds_min, seconds_max))
        self._current_time += delta
        return self._current_time

    def generate_benign(self, count: int = 10) -> List[SecurityEvent]:
        """Generate realistic benign background security events."""
        events: List[SecurityEvent] = []
        for _ in range(count):
            t = self._tick(5, 60)
            user = random.choice(self.BENIGN_USERS + self.PRIVILEGED_USERS)
            src_ip = random.choice(self.INTERNAL_IPS)
            hostname = random.choice(self.HOSTNAMES)

            # 90% successful routine events, 10% isolated mistyped passwords
            if random.random() < 0.90:
                action = random.choice(["ssh_login", "web_auth", "service_check", "sudo_auth"])
                event = SecurityEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=t.isoformat(),
                    event_type="auth_success",
                    user=user,
                    src_ip=src_ip,
                    hostname=hostname,
                    action=action,
                    details={"status": "success", "protocol": "SSH-2.0", "session_id": uuid.uuid4().hex[:8]},
                    is_simulated=True,
                )
            else:
                event = SecurityEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=t.isoformat(),
                    event_type="auth_failure",
                    user=user,
                    src_ip=src_ip,
                    hostname=hostname,
                    action="ssh_login",
                    details={"status": "failure", "reason": "bad_password", "isolated_mistype": True},
                    is_simulated=True,
                )
            events.append(event)
        return events

    def generate_brute_force(
        self,
        target_user: str = "admin",
        attacker_ip: str = "198.51.100.23",
        target_host: str = "bastion-host",
        attempt_count: int = 7,
    ) -> List[SecurityEvent]:
        """Generate a brute-force attack scenario: rapid repeated auth failures from a single IP."""
        events: List[SecurityEvent] = []
        for i in range(1, attempt_count + 1):
            t = self._tick(2, 8)  # Rapid attempts
            events.append(
                SecurityEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=t.isoformat(),
                    event_type="auth_failure",
                    user=target_user,
                    src_ip=attacker_ip,
                    hostname=target_host,
                    action="ssh_login",
                    details={
                        "status": "failure",
                        "reason": "invalid_credentials",
                        "attempt": i,
                        "attack_pattern": "credential_guessing",
                    },
                    is_simulated=True,
                )
            )
        return events

    def generate_suspicious_login(
        self,
        user: str = "svc_backup",
        attacker_ip: str = "203.0.113.99",
        target_host: str = "db-prod-01",
    ) -> List[SecurityEvent]:
        """Generate a suspicious login from an anomalous/external IP address."""
        t = self._tick(10, 30)
        return [
            SecurityEvent(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                timestamp=t.isoformat(),
                event_type="auth_success",
                user=user,
                src_ip=attacker_ip,
                hostname=target_host,
                action="ssh_login",
                details={
                    "status": "success",
                    "threat_intel": "unrecognized_asn",
                    "anomaly": "external_service_account_login",
                    "geo": "unknown_region",
                },
                is_simulated=True,
            )
        ]

    def generate_privilege_escalation(
        self,
        user: str = "alice",
        src_ip: str = "10.0.1.42",
        target_host: str = "workstation-eng-01",
    ) -> List[SecurityEvent]:
        """Generate suspicious privilege escalation telemetry."""
        events: List[SecurityEvent] = []

        suspicious_commands = [
            ("sudo_exec", "sudo -i", {"elevation_type": "interactive_root_shell"}),
            ("privilege_escalation", "chmod +s /tmp/escalate", {"technique": "suid_modification"}),
            ("privilege_escalation", "usermod -aG sudo alice", {"technique": "group_membership_tampering"}),
        ]

        for action, cmd, extra in suspicious_commands:
            t = self._tick(5, 15)
            details: Dict[str, Any] = {
                "command": cmd,
                "parent_process": "bash",
                "target_user": "root",
            }
            details.update(extra)

            events.append(
                SecurityEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=t.isoformat(),
                    event_type="privilege_escalation",
                    user=user,
                    src_ip=src_ip,
                    hostname=target_host,
                    action=action,
                    details=details,
                    is_simulated=True,
                )
            )
        return events

    def generate_unusual_access(
        self,
        user: str = "david",
        src_ip: str = "10.0.2.100",
        target_host: str = "finance-app-02",
    ) -> List[SecurityEvent]:
        """Generate unauthorized or unusual access to sensitive files/resources."""
        t = self._tick(10, 20)
        return [
            SecurityEvent(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                timestamp=t.isoformat(),
                event_type="unusual_access",
                user=user,
                src_ip=src_ip,
                hostname=target_host,
                action="file_access",
                details={
                    "resource": "/etc/shadow",
                    "operation": "read",
                    "status": "unauthorized_attempt",
                    "process": "cat",
                },
                is_simulated=True,
            )
        ]

    def generate_scenario(self, scenario_name: str) -> List[SecurityEvent]:
        """Generate a complete pre-packaged scenario."""
        scenario = scenario_name.lower().strip()

        if scenario == "benign":
            return self.generate_benign(count=15)
        elif scenario == "brute_force":
            benign_before = self.generate_benign(count=5)
            attack = self.generate_brute_force(
                target_user="admin",
                attacker_ip="198.51.100.23",
                attempt_count=8,
            )
            benign_after = self.generate_benign(count=3)
            return benign_before + attack + benign_after
        elif scenario in ("privesc", "privilege_escalation"):
            benign_before = self.generate_benign(count=4)
            attack = self.generate_privilege_escalation(
                user="alice",
                src_ip="10.0.1.42",
                target_host="workstation-eng-01",
            )
            benign_after = self.generate_benign(count=2)
            return benign_before + attack + benign_after
        elif scenario in ("suspicious_login", "suspicious_ip"):
            benign_before = self.generate_benign(count=4)
            attack = self.generate_suspicious_login(
                user="svc_backup",
                attacker_ip="203.0.113.99",
                target_host="db-prod-01",
            )
            benign_after = self.generate_benign(count=3)
            return benign_before + attack + benign_after
        elif scenario in ("all", "mixed", "mixed_incident"):
            # Multi-stage security incident
            events: List[SecurityEvent] = []
            events.extend(self.generate_benign(count=5))
            # Phase 1: SSH Brute force
            events.extend(
                self.generate_brute_force(
                    target_user="admin",
                    attacker_ip="198.51.100.23",
                    attempt_count=6,
                )
            )
            # Phase 2: Brute force successful compromise
            t = self._tick(2, 5)
            events.append(
                SecurityEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=t.isoformat(),
                    event_type="auth_success",
                    user="admin",
                    src_ip="198.51.100.23",
                    hostname="bastion-host",
                    action="ssh_login",
                    details={"status": "success", "flag": "compromised_session"},
                    is_simulated=True,
                )
            )
            # Phase 3: Unusual file access
            events.extend(
                self.generate_unusual_access(
                    user="admin",
                    src_ip="198.51.100.23",
                    target_host="bastion-host",
                )
            )
            # Phase 4: Privilege escalation
            events.extend(
                self.generate_privilege_escalation(
                    user="admin",
                    src_ip="198.51.100.23",
                    target_host="bastion-host",
                )
            )
            # Phase 5: Normal traffic continues elsewhere
            events.extend(self.generate_benign(count=5))
            return events
        else:
            raise ValueError(
                f"Unknown scenario: '{scenario_name}'. "
                "Supported: 'benign', 'brute_force', 'privesc', 'suspicious_login', 'all'"
            )
