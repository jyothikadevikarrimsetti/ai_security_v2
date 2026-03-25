"""CAE-001 -- Immutable Append-Only Hash-Chain Audit Store.

Provides an immutable, append-only audit log backed by SQLite (development) or
PostgreSQL (production).  Every event is linked to its predecessor via a SHA-256
hash chain:

    chain_hash = SHA-256(previous_hash + event_id + canonical_json(event))

Immutability is enforced at the database level through triggers that reject any
UPDATE or DELETE on the ``audit_events`` table.  The public API exposes only
insert and query operations -- no mutation is possible.

Deduplication window: 15 minutes (configurable).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from queryvault.app.models.compliance import AuditEvent

logger = logging.getLogger(__name__)

# Sentinel genesis hash -- the chain starts here
_GENESIS_HASH = "0" * 64


class AuditStore:
    """Thread-safe, append-only audit store with hash-chain integrity.

    Usage::

        store = AuditStore()
        await store.initialize("audit.db")
        stored = await store.append(event)
        valid  = await store.verify_hash_chain()
    """

    def __init__(self) -> None:
        self._conn: Optional[sqlite3.Connection] = None
        self._db_path: str = ":memory:"
        self._lock = threading.Lock()
        self._dedup_window_minutes: int = 15

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(
        self,
        db_path: str = ":memory:",
        *,
        dedup_window_minutes: int = 15,
    ) -> None:
        """Create tables, indices, and immutability triggers.

        Safe to call multiple times (idempotent).
        """
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass

        self._db_path = db_path
        self._dedup_window_minutes = dedup_window_minutes
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        with self._conn:
            self._conn.executescript(_SCHEMA_SQL)

        logger.info("audit_store_initialized db_path=%s", db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError(
                "AuditStore not initialised -- call initialize() first"
            )
        return self._conn

    def _last_chain_hash(self, source_zone: str) -> str:
        """Return the most recent chain_hash for a given source zone."""
        row = self._get_conn().execute(
            "SELECT chain_hash FROM audit_events "
            "WHERE source_zone = ? ORDER BY id DESC LIMIT 1",
            (source_zone,),
        ).fetchone()
        return row["chain_hash"] if row else _GENESIS_HASH

    @staticmethod
    def _compute_chain_hash(prev_hash: str, event: AuditEvent) -> str:
        """Compute SHA-256(prev_hash + event_id + canonical_json)."""
        canonical = json.dumps(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "source_zone": event.source_zone,
                "timestamp": event.timestamp.isoformat(),
                "user_id": event.user_id,
                "request_id": event.request_id,
            },
            sort_keys=True,
        )
        return hashlib.sha256(
            (prev_hash + event.event_id + canonical).encode()
        ).hexdigest()

    def _is_duplicate(self, event_id: str) -> bool:
        """Return True if *event_id* was seen within the dedup window."""
        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(minutes=self._dedup_window_minutes)
        ).isoformat()
        row = self._get_conn().execute(
            "SELECT event_id FROM event_dedup "
            "WHERE event_id = ? AND seen_at > ?",
            (event_id, cutoff),
        ).fetchone()
        return row is not None

    def _record_dedup(self, event_id: str) -> None:
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO event_dedup (event_id, seen_at) VALUES (?, ?)",
            (event_id, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        """Materialise a database row into an ``AuditEvent``."""
        from queryvault.app.models.enums import Severity

        return AuditEvent(
            event_id=row["event_id"],
            event_type=row["event_type"],
            source_zone=row["source_zone"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            request_id=row["request_id"],
            user_id=row["user_id"],
            severity=Severity(row["severity"]),
            btg_active=bool(row["btg_active"]),
            payload=json.loads(row["payload_json"]),
            chain_hash=row["chain_hash"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Append *event* to the immutable audit log.

        Returns the event enriched with its ``chain_hash``.
        Silently skips duplicates within the dedup window.
        """
        conn = self._get_conn()

        with self._lock:
            if self._is_duplicate(event.event_id):
                logger.debug(
                    "duplicate_event_skipped event_id=%s", event.event_id
                )
                return event

            prev_hash = self._last_chain_hash(event.source_zone)
            chain_hash = self._compute_chain_hash(prev_hash, event)
            ingested_at = datetime.now(timezone.utc).isoformat()

            conn.execute(
                """INSERT INTO audit_events
                   (event_id, event_type, source_zone, timestamp, request_id,
                    user_id, severity, btg_active, payload_json,
                    chain_hash, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id,
                    event.event_type,
                    event.source_zone,
                    event.timestamp.isoformat(),
                    event.request_id,
                    event.user_id,
                    event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                    int(event.btg_active),
                    json.dumps(event.payload),
                    chain_hash,
                    ingested_at,
                ),
            )
            conn.commit()

        self._record_dedup(event.event_id)

        # Return enriched copy
        event.chain_hash = chain_hash
        logger.info(
            "event_appended event_id=%s source_zone=%s type=%s",
            event.event_id,
            event.source_zone,
            event.event_type,
        )
        return event

    async def query(
        self,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        filters: Optional[dict[str, Any]] = None,
        *,
        sort_order: str = "desc",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[AuditEvent], int]:
        """Query audit events with optional time range and filters.

        Supported filter keys: ``source_zone``, ``user_id``, ``event_type``,
        ``severity``, ``btg_active``, ``request_id``.

        Returns ``(events, total_count)``.
        """
        filters = filters or {}
        conn = self._get_conn()

        conditions: list[str] = []
        params: list[Any] = []

        if from_time:
            conditions.append("timestamp >= ?")
            params.append(from_time.isoformat())
        if to_time:
            conditions.append("timestamp <= ?")
            params.append(to_time.isoformat())

        for key in ("source_zone", "user_id", "event_type", "severity", "request_id"):
            if key in filters:
                val = filters[key]
                if isinstance(val, list):
                    placeholders = ",".join("?" * len(val))
                    conditions.append(f"{key} IN ({placeholders})")
                    params.extend(val)
                else:
                    conditions.append(f"{key} = ?")
                    params.append(val)

        if "btg_active" in filters:
            conditions.append("btg_active = ?")
            params.append(int(filters["btg_active"]))

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        order = "DESC" if sort_order.lower() == "desc" else "ASC"

        total = conn.execute(
            f"SELECT COUNT(*) FROM audit_events {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM audit_events {where} "
            f"ORDER BY timestamp {order} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

        return [self._row_to_event(r) for r in rows], total

    async def get_by_request_id(self, request_id: str) -> list[AuditEvent]:
        """Return all events for a *request_id* in chronological order."""
        events, _ = await self.query(
            filters={"request_id": request_id},
            sort_order="asc",
            limit=1000,
        )
        return events

    async def verify_hash_chain(
        self,
        source_zone: Optional[str] = None,
    ) -> bool:
        """Re-compute and verify the hash chain.

        If *source_zone* is provided, only that zone's chain is checked.
        Otherwise all zones are verified independently.

        Returns ``True`` if every chain is intact.
        """
        conn = self._get_conn()

        if source_zone:
            zones = [source_zone]
        else:
            rows = conn.execute(
                "SELECT DISTINCT source_zone FROM audit_events"
            ).fetchall()
            zones = [r["source_zone"] for r in rows]

        for zone in zones:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE source_zone = ? ORDER BY id ASC",
                (zone,),
            ).fetchall()

            prev_hash = _GENESIS_HASH
            for row in rows:
                event = self._row_to_event(row)
                expected = self._compute_chain_hash(prev_hash, event)
                if expected != row["chain_hash"]:
                    logger.error(
                        "hash_chain_broken zone=%s event_id=%s "
                        "expected=%s stored=%s",
                        zone,
                        row["event_id"],
                        expected[:16],
                        row["chain_hash"][:16],
                    )
                    return False
                prev_hash = row["chain_hash"]

        logger.info("hash_chain_verified zones=%s", zones)
        return True

    async def count_events(
        self,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        filters: Optional[dict[str, Any]] = None,
    ) -> int:
        """Fast count of events matching the given criteria."""
        _, total = await self.query(
            from_time=from_time,
            to_time=to_time,
            filters=filters,
            limit=1,
        )
        return total


# ── Schema SQL ────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,
    event_type      TEXT    NOT NULL,
    source_zone     TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,
    request_id      TEXT    NOT NULL,
    user_id         TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'INFO',
    btg_active      INTEGER NOT NULL DEFAULT 0,
    payload_json    TEXT    NOT NULL DEFAULT '{}',
    chain_hash      TEXT    NOT NULL,
    ingested_at     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ae_timestamp   ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_ae_user_id     ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_ae_request_id  ON audit_events(request_id);
CREATE INDEX IF NOT EXISTS idx_ae_source_zone ON audit_events(source_zone);
CREATE INDEX IF NOT EXISTS idx_ae_severity    ON audit_events(severity);
CREATE INDEX IF NOT EXISTS idx_ae_event_type  ON audit_events(event_type);

-- Immutability: reject UPDATE
CREATE TRIGGER IF NOT EXISTS trg_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'TAMPER_ALERT: audit_events is append-only');
END;

-- Immutability: reject DELETE
CREATE TRIGGER IF NOT EXISTS trg_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'TAMPER_ALERT: audit_events is append-only');
END;

-- Deduplication window table
CREATE TABLE IF NOT EXISTS event_dedup (
    event_id   TEXT PRIMARY KEY,
    seen_at    TEXT NOT NULL
);

-- Alert persistence (shared with AlertManager)
CREATE TABLE IF NOT EXISTS alerts (
    alert_id         TEXT    PRIMARY KEY,
    anomaly_type     TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    user_id          TEXT    NOT NULL,
    description      TEXT    NOT NULL,
    event_ids_json   TEXT    NOT NULL DEFAULT '[]',
    status           TEXT    NOT NULL DEFAULT 'OPEN',
    created_at       TEXT    NOT NULL,
    acknowledged_at  TEXT,
    resolved_at      TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    dedup_key        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""
