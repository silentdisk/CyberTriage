"""SQLite database layer for CyberTriage."""

from contextlib import contextmanager
import json
import logging
from pathlib import Path
import sqlite3
from typing import Generator, List, Optional

from src.database.models import Alert
from src.events.models import SecurityEvent

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "cybertriage.db"


class Database:
    """Manages SQLite persistence for security events and alerts."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = str(db_path)
        # Ensure parent directory exists if a custom path is used
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable foreign keys and WAL mode for reliability on disk
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    @contextmanager
    def _connection_context(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for safe connection acquisition and transaction commit."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Database operation failed, rolled back: %s", e)
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create database tables automatically on startup."""
        with self._connection_context() as conn:
            cursor = conn.cursor()

            # Security Events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    user TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    is_simulated INTEGER NOT NULL DEFAULT 1
                );
                """
            )

            # Indexes for fast querying
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")

            # Structured Alerts table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    evidence_event_ids TEXT NOT NULL,
                    entity_user TEXT,
                    entity_ip TEXT,
                    entity_host TEXT,
                    status TEXT NOT NULL DEFAULT 'NEW',
                    details TEXT NOT NULL
                );
                """
            )

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_name);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")

        logger.debug("Database initialized at %s", self.db_path)

    def insert_event(self, event: SecurityEvent) -> str:
        """Insert a single security event using parameterized SQL."""
        query = """
            INSERT OR REPLACE INTO events (
                event_id, timestamp, event_type, user, src_ip,
                hostname, action, details, is_simulated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._connection_context() as conn:
            conn.execute(
                query,
                (
                    event.event_id,
                    event.timestamp,
                    event.event_type,
                    event.user,
                    event.src_ip,
                    event.hostname,
                    event.action,
                    json.dumps(event.details),
                    1 if event.is_simulated else 0,
                ),
            )
        return event.event_id

    def insert_events(self, events: List[SecurityEvent]) -> int:
        """Insert multiple events in a single transaction."""
        if not events:
            return 0

        query = """
            INSERT OR REPLACE INTO events (
                event_id, timestamp, event_type, user, src_ip,
                hostname, action, details, is_simulated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        rows = [
            (
                e.event_id,
                e.timestamp,
                e.event_type,
                e.user,
                e.src_ip,
                e.hostname,
                e.action,
                json.dumps(e.details),
                1 if e.is_simulated else 0,
            )
            for e in events
        ]
        with self._connection_context() as conn:
            conn.executemany(query, rows)
        return len(events)

    def get_event(self, event_id: str) -> Optional[SecurityEvent]:
        """Fetch an event by its ID."""
        query = "SELECT * FROM events WHERE event_id = ?;"
        with self._connection_context() as conn:
            cursor = conn.execute(query, (event_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_event(row)
        return None

    def get_events(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        user: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Fetch events with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: list = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if user:
            query += " AND user = ?"
            params.append(user)
        if ip:
            query += " AND src_ip = ?"
            params.append(ip)

        query += " ORDER BY timestamp ASC LIMIT ?;"
        params.append(limit)

        with self._connection_context() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_event(row) for row in cursor.fetchall()]

    def get_events_by_ids(self, event_ids: List[str]) -> List[SecurityEvent]:
        """Fetch specific events by a list of event IDs."""
        if not event_ids:
            return []

        placeholders = ",".join("?" for _ in event_ids)
        query = f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY timestamp ASC;"
        with self._connection_context() as conn:
            cursor = conn.execute(query, event_ids)
            return [self._row_to_event(row) for row in cursor.fetchall()]

    def get_all_events(self) -> List[SecurityEvent]:
        """Fetch all events ordered chronologically."""
        query = "SELECT * FROM events ORDER BY timestamp ASC;"
        with self._connection_context() as conn:
            cursor = conn.execute(query)
            return [self._row_to_event(row) for row in cursor.fetchall()]

    def insert_alert(self, alert: Alert) -> str:
        """Insert an alert using parameterized SQL."""
        query = """
            INSERT INTO alerts (
                alert_id, rule_name, severity, title, description,
                timestamp, evidence_event_ids, entity_user, entity_ip,
                entity_host, status, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._connection_context() as conn:
            conn.execute(
                query,
                (
                    alert.alert_id,
                    alert.rule_name,
                    alert.severity,
                    alert.title,
                    alert.description,
                    alert.timestamp,
                    json.dumps(alert.evidence_event_ids),
                    alert.entity_user,
                    alert.entity_ip,
                    alert.entity_host,
                    alert.status,
                    json.dumps(alert.details),
                ),
            )
        return alert.alert_id

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Fetch an alert by its ID."""
        query = "SELECT * FROM alerts WHERE alert_id = ?;"
        with self._connection_context() as conn:
            cursor = conn.execute(query, (alert_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_alert(row)
        return None

    def get_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Alert]:
        """Fetch alerts ordered from most recent to oldest."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if status:
            query += " AND status = ?"
            params.append(status.upper())

        query += " ORDER BY timestamp DESC LIMIT ?;"
        params.append(limit)

        with self._connection_context() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_alert(row) for row in cursor.fetchall()]

    def alert_exists_with_evidence(self, rule_name: str, evidence_ids: List[str]) -> bool:
        """Check if an alert for this rule already references any of the given evidence event IDs."""
        if not evidence_ids:
            return False

        # Query all alerts for this rule and compare evidence IDs
        query = "SELECT evidence_event_ids FROM alerts WHERE rule_name = ?;"
        target_set = set(evidence_ids)

        with self._connection_context() as conn:
            cursor = conn.execute(query, (rule_name,))
            for row in cursor.fetchall():
                try:
                    existing_ids = set(json.loads(row["evidence_event_ids"]))
                    if not target_set.isdisjoint(existing_ids):
                        return True
                except (json.JSONDecodeError, TypeError):
                    continue
        return False

    def clear_database(self) -> None:
        """Delete all records from events and alerts tables."""
        with self._connection_context() as conn:
            conn.execute("DELETE FROM alerts;")
            conn.execute("DELETE FROM events;")

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> SecurityEvent:
        """Convert a database row into a SecurityEvent object."""
        try:
            details = json.loads(row["details"])
        except (json.JSONDecodeError, TypeError):
            details = {"raw": row["details"]}

        return SecurityEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            user=row["user"],
            src_ip=row["src_ip"],
            hostname=row["hostname"],
            action=row["action"],
            details=details,
            is_simulated=bool(row["is_simulated"]),
        )

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        """Convert a database row into an Alert object."""
        try:
            evidence_ids = json.loads(row["evidence_event_ids"])
        except (json.JSONDecodeError, TypeError):
            evidence_ids = []

        try:
            details = json.loads(row["details"])
        except (json.JSONDecodeError, TypeError):
            details = {}

        return Alert(
            alert_id=row["alert_id"],
            rule_name=row["rule_name"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            timestamp=row["timestamp"],
            evidence_event_ids=evidence_ids,
            entity_user=row["entity_user"],
            entity_ip=row["entity_ip"],
            entity_host=row["entity_host"],
            status=row["status"],
            details=details,
        )
