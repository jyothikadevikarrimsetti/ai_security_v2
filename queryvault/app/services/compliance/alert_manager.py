"""CAE-006 -- Alert Lifecycle Manager.

Manages the full lifecycle of anomaly alerts:

  1. **Deduplication** -- If an alert with the same ``dedup_key`` is already
     OPEN within the 15-minute dedup window, the existing alert's
     ``occurrence_count`` is incremented instead of creating a new alert.
  2. **Escalation** -- When ``occurrence_count`` exceeds 5, severity is
     bumped one level:  INFO -> WARNING -> HIGH -> CRITICAL.
  3. **Persistence** -- Alerts are stored in SQLite (dev) via the shared
     ``audit_store`` database connection.
  4. **Dispatch** -- In development, alerts are dispatched via structured
     logging.  In production, webhooks (PagerDuty, Slack, SIEM) are used.

Alert statuses: OPEN -> ACKNOWLEDGED -> RESOLVED
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from queryvault.app.models.enums import AlertStatus, Severity
from queryvault.app.models.threat import AnomalyAlert

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class AlertManager:
    """Alert lifecycle manager: dedup, escalate, persist, dispatch.

    Usage::

        manager = AlertManager(audit_store)
        final_alert = await manager.process(alert)
        await manager.acknowledge(alert_id)
        await manager.resolve(alert_id)
    """

    def __init__(
        self,
        audit_store: Any,
        *,
        dedup_window_minutes: int = 15,
        escalation_threshold: int = 5,
    ) -> None:
        self._store = audit_store
        self._lock = threading.Lock()
        self._dedup_window_minutes = dedup_window_minutes
        self._escalation_threshold = escalation_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def process(self, alert: AnomalyAlert) -> AnomalyAlert:
        """Deduplicate, persist, escalate, and dispatch an alert.

        Returns the final (possibly merged/escalated) alert.
        """
        with self._lock:
            existing = self._load_open_by_dedup_key(alert.dedup_key) if alert.dedup_key else None

            if existing:
                existing.occurrence_count += 1
                existing.event_ids.extend(alert.event_ids)

                if existing.occurrence_count > self._escalation_threshold:
                    existing.severity = self._escalate(existing.severity)
                    existing.description += (
                        f" [ESCALATED: {existing.occurrence_count} occurrences]"
                    )

                self._save_alert(existing)
                self._dispatch(existing)
                return existing

            self._save_alert(alert)
            self._dispatch(alert)
            return alert

    async def acknowledge(
        self,
        alert_id: str,
        *,
        notes: str = "",
    ) -> Optional[AnomalyAlert]:
        """Transition an alert to ACKNOWLEDGED status."""
        conn = self._store._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn.execute(
                "UPDATE alerts SET status = ?, acknowledged_at = ? WHERE alert_id = ?",
                (AlertStatus.ACKNOWLEDGED.value, now, alert_id),
            )
            conn.commit()

        logger.info("alert_acknowledged alert_id=%s notes=%s", alert_id, notes)
        return self._load_by_id(alert_id)

    async def resolve(
        self,
        alert_id: str,
        *,
        notes: str = "",
    ) -> Optional[AnomalyAlert]:
        """Transition an alert to RESOLVED status."""
        conn = self._store._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn.execute(
                "UPDATE alerts SET status = ?, resolved_at = ? WHERE alert_id = ?",
                (AlertStatus.RESOLVED.value, now, alert_id),
            )
            conn.commit()

        logger.info("alert_resolved alert_id=%s notes=%s", alert_id, notes)
        return self._load_by_id(alert_id)

    async def get_alerts(
        self,
        filters: Optional[dict[str, Any]] = None,
        *,
        limit: int = 100,
    ) -> list[AnomalyAlert]:
        """Query persisted alerts with optional filters.

        Supported filter keys: ``status``, ``severity``, ``user_id``,
        ``anomaly_type``.
        """
        filters = filters or {}
        conn = self._store._get_conn()

        conditions: list[str] = []
        params: list[Any] = []

        for key in ("status", "severity", "user_id", "anomaly_type"):
            if key in filters:
                conditions.append(f"{key} = ?")
                params.append(
                    filters[key].value
                    if hasattr(filters[key], "value")
                    else filters[key]
                )

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()

        return [self._row_to_alert(row) for row in rows]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _escalate(severity: Severity) -> Severity:
        """Bump severity one level up.  CRITICAL stays CRITICAL."""
        idx = _SEVERITY_ORDER.index(severity)
        return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]

    def _save_alert(self, alert: AnomalyAlert) -> None:
        """Persist (insert or update) an alert to SQLite."""
        conn = self._store._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO alerts
               (alert_id, anomaly_type, severity, user_id, description,
                event_ids_json, status, created_at, acknowledged_at, resolved_at,
                occurrence_count, dedup_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                alert.alert_id,
                alert.anomaly_type,
                alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                alert.user_id,
                alert.description,
                json.dumps(alert.event_ids),
                alert.status.value if hasattr(alert.status, "value") else str(alert.status),
                datetime.now(timezone.utc).isoformat(),
                None,
                None,
                alert.occurrence_count,
                alert.dedup_key,
            ),
        )
        conn.commit()

    def _load_open_by_dedup_key(self, dedup_key: str) -> Optional[AnomalyAlert]:
        """Find an OPEN alert with matching dedup_key within the window."""
        conn = self._store._get_conn()
        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(minutes=self._dedup_window_minutes)
        ).isoformat()

        row = conn.execute(
            """SELECT * FROM alerts
               WHERE dedup_key = ? AND status = ? AND created_at >= ?
               ORDER BY created_at DESC LIMIT 1""",
            (dedup_key, AlertStatus.OPEN.value, cutoff),
        ).fetchone()

        if not row:
            return None
        return self._row_to_alert(row)

    def _load_by_id(self, alert_id: str) -> Optional[AnomalyAlert]:
        """Load a single alert by ID."""
        conn = self._store._get_conn()
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_alert(row)

    @staticmethod
    def _row_to_alert(row: Any) -> AnomalyAlert:
        """Convert a database row to an ``AnomalyAlert``."""
        return AnomalyAlert(
            alert_id=row["alert_id"],
            anomaly_type=row["anomaly_type"],
            severity=Severity(row["severity"]),
            user_id=row["user_id"],
            description=row["description"],
            event_ids=json.loads(row["event_ids_json"]),
            status=AlertStatus(row["status"]),
            occurrence_count=row["occurrence_count"],
            dedup_key=row["dedup_key"],
        )

    @staticmethod
    def _dispatch(alert: AnomalyAlert) -> None:
        """Dispatch alert to configured channels (structured logging in dev)."""
        log_fn = {
            Severity.INFO: logger.info,
            Severity.LOW: logger.info,
            Severity.MEDIUM: logger.warning,
            Severity.HIGH: logger.warning,
            Severity.CRITICAL: logger.error,
        }.get(alert.severity, logger.warning)

        log_fn(
            "alert_dispatched alert_id=%s type=%s severity=%s user=%s "
            "occurrences=%d desc=%s",
            alert.alert_id,
            alert.anomaly_type,
            alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            alert.user_id,
            alert.occurrence_count,
            alert.description[:120],
        )
