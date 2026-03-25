"""CAE-004 -- Anomaly Detection Engine (Statistical and Rule-Based).

Implements six anomaly detection models that analyse each audit event in
real time and surface ``AnomalyAlert`` instances when thresholds are breached:

  1. Volume anomaly       -- Z-score vs 7-day per-user hourly baseline
                             (z_high=3.0, z_critical=5.0)
  2. Temporal anomaly     -- Off-hours access (19:00-07:00 UTC)
  3. Validation block     -- >= 3 validation blocks within 1 hour
     spike
  4. Sanitisation spike   -- >= 10 PII masking hits on the same column
                             within 1 hour
  5. BTG duration         -- Break-the-Glass sessions exceeding 4 hours
  6. Sensitivity          -- Increasing average sensitivity level over a
     escalation             4-hour sliding window

Per-user hourly counts are stored in a 168-slot ring buffer (7 days x 24h).
"""

from __future__ import annotations

import logging
import math
import threading
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from queryvault.app.models.compliance import AuditEvent
from queryvault.app.models.enums import Severity
from queryvault.app.models.threat import AnomalyAlert

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Stateful anomaly detection engine.

    Maintains per-user ring buffers and sliding windows in memory.
    Thread-safe for concurrent event processing.

    Usage::

        detector = AnomalyDetector()
        alerts = detector.analyze(event)
        for alert in alerts:
            await alert_manager.process(alert)
    """

    def __init__(
        self,
        *,
        z_high: float = 3.0,
        z_critical: float = 5.0,
        work_start: int = 7,
        work_end: int = 19,
        block_threshold: int = 3,
        sanitization_threshold: int = 10,
        btg_duration_hours: float = 4.0,
        sensitivity_window_hours: float = 4.0,
    ) -> None:
        self._lock = threading.Lock()

        # Configuration
        self._z_high = z_high
        self._z_critical = z_critical
        self._work_start = work_start
        self._work_end = work_end
        self._block_threshold = block_threshold
        self._sanitization_threshold = sanitization_threshold
        self._btg_duration_hours = btg_duration_hours
        self._sensitivity_window_hours = sensitivity_window_hours

        # Per-user hourly ring buffer: user_id -> deque of counts (168 slots)
        self._user_hourly_counts: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=168)
        )
        # Current-hour tracker: user_id -> {"bucket": int, "count": int}
        self._user_current_hour: dict[str, dict[str, Any]] = {}

        # Validation block tracking: user_id -> deque of timestamps
        self._user_block_times: dict[str, deque[datetime]] = defaultdict(deque)

        # Sanitisation spike tracking: column -> deque of timestamps
        self._sanitization_times: dict[str, deque[datetime]] = defaultdict(deque)

        # Active BTG sessions: user_id -> {"start": datetime, "records": int}
        self._active_btg: dict[str, dict[str, Any]] = {}

        # Sensitivity level history: user_id -> deque of (datetime, level)
        self._sensitivity_history: dict[str, deque[tuple[datetime, int]]] = defaultdict(
            lambda: deque(maxlen=200)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, event: AuditEvent) -> list[AnomalyAlert]:
        """Run all anomaly detectors on *event*.

        Returns a (possibly empty) list of alerts.
        """
        alerts: list[AnomalyAlert] = []

        detectors = [
            self._volume_anomaly,
            self._temporal_anomaly,
            self._validation_block_spike,
            self._sanitization_spike,
            self._btg_duration,
            self._sensitivity_escalation,
        ]

        for detector in detectors:
            try:
                result = detector(event)
                if result is not None:
                    alerts.append(result)
                    logger.warning(
                        "anomaly_detected type=%s severity=%s user=%s",
                        result.anomaly_type,
                        result.severity.value,
                        event.user_id,
                    )
            except Exception as exc:
                logger.error(
                    "anomaly_detector_error detector=%s error=%s",
                    detector.__name__,
                    str(exc),
                )

        return alerts

    def reset_state(self) -> None:
        """Clear all in-memory state (for testing)."""
        with self._lock:
            self._user_hourly_counts.clear()
            self._user_current_hour.clear()
            self._user_block_times.clear()
            self._sanitization_times.clear()
            self._active_btg.clear()
            self._sensitivity_history.clear()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _current_hour_bucket() -> int:
        return int(datetime.now(timezone.utc).timestamp() // 3600)

    @staticmethod
    def _z_score(value: float, history: list[float]) -> float:
        """Compute z-score of *value* against *history*."""
        if len(history) < 3:
            return 0.0
        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std = math.sqrt(variance)
        if std == 0:
            return 10.0 if value > mean else 0.0
        return (value - mean) / std

    def _increment_user_count(self, user_id: str, event_time: datetime) -> float:
        """Track per-user hourly query count.  Returns current-hour count."""
        bucket = int(event_time.timestamp() // 3600)
        with self._lock:
            current = self._user_current_hour.get(user_id)
            if current is None or current["bucket"] != bucket:
                if current is not None:
                    self._user_hourly_counts[user_id].append(current["count"])
                self._user_current_hour[user_id] = {"bucket": bucket, "count": 1}
            else:
                self._user_current_hour[user_id]["count"] += 1
            return float(self._user_current_hour[user_id]["count"])

    @staticmethod
    def _make_alert(
        anomaly_type: str,
        severity: Severity,
        user_id: str,
        description: str,
        event_id: str,
        dedup_key: str,
    ) -> AnomalyAlert:
        return AnomalyAlert(
            alert_id=str(uuid.uuid4()),
            anomaly_type=anomaly_type,
            severity=severity,
            user_id=user_id,
            description=description,
            event_ids=[event_id],
            dedup_key=dedup_key,
        )

    # ------------------------------------------------------------------
    # Model 1: Volume anomaly (z-score vs 7-day hourly baseline)
    # ------------------------------------------------------------------

    def _volume_anomaly(self, event: AuditEvent) -> AnomalyAlert | None:
        current_count = self._increment_user_count(event.user_id, event.timestamp)
        history = list(self._user_hourly_counts[event.user_id])
        z = self._z_score(current_count, history)

        if z >= self._z_critical:
            return self._make_alert(
                anomaly_type="VOLUME",
                severity=Severity.CRITICAL,
                user_id=event.user_id,
                description=(
                    f"Critical volume anomaly: {int(current_count)} queries this hour "
                    f"(z-score={z:.1f}, threshold={self._z_critical:.1f})"
                ),
                event_id=event.event_id,
                dedup_key=f"{event.user_id}:VOLUME:{self._current_hour_bucket()}",
            )
        if z >= self._z_high:
            return self._make_alert(
                anomaly_type="VOLUME",
                severity=Severity.HIGH,
                user_id=event.user_id,
                description=(
                    f"Volume anomaly: {int(current_count)} queries this hour "
                    f"(z-score={z:.1f}, threshold={self._z_high:.1f})"
                ),
                event_id=event.event_id,
                dedup_key=f"{event.user_id}:VOLUME:{self._current_hour_bucket()}",
            )
        return None

    # ------------------------------------------------------------------
    # Model 2: Temporal anomaly (off-hours access 19:00 - 07:00)
    # ------------------------------------------------------------------

    def _temporal_anomaly(self, event: AuditEvent) -> AnomalyAlert | None:
        if event.btg_active:
            return None  # BTG sessions are expected off-hours

        hour = event.timestamp.astimezone(timezone.utc).hour
        if self._work_start <= hour < self._work_end:
            return None

        severity = Severity.MEDIUM
        description = (
            f"Off-hours access at {hour:02d}:00 UTC "
            f"(normal window: {self._work_start:02d}:00-{self._work_end:02d}:00)"
        )

        # Escalate for sensitive data access
        if event.severity in (Severity.HIGH, Severity.CRITICAL):
            severity = Severity.HIGH
            description += " with sensitive data access"

        day_bucket = event.timestamp.strftime("%Y-%m-%d")
        return self._make_alert(
            anomaly_type="TEMPORAL",
            severity=severity,
            user_id=event.user_id,
            description=description,
            event_id=event.event_id,
            dedup_key=f"{event.user_id}:TEMPORAL:{day_bucket}:{hour}",
        )

    # ------------------------------------------------------------------
    # Model 3: Validation block spike (>= 3 blocks in 1 hour)
    # ------------------------------------------------------------------

    def _validation_block_spike(self, event: AuditEvent) -> AnomalyAlert | None:
        if event.event_type not in ("VALIDATION_BLOCK", "VALIDATION_BLOCKED"):
            return None

        cutoff = event.timestamp - timedelta(hours=1)
        with self._lock:
            q = self._user_block_times[event.user_id]
            q.append(event.timestamp)
            while q and q[0] < cutoff:
                q.popleft()
            count = len(q)

        if count >= self._block_threshold:
            return self._make_alert(
                anomaly_type="VALIDATION_BLOCK_SPIKE",
                severity=Severity.HIGH,
                user_id=event.user_id,
                description=(
                    f"Repeated validation blocks: {count} blocks in the last hour "
                    f"(threshold={self._block_threshold})"
                ),
                event_id=event.event_id,
                dedup_key=f"{event.user_id}:VALIDATION_BLOCK_SPIKE:{self._current_hour_bucket()}",
            )
        return None

    # ------------------------------------------------------------------
    # Model 4: Sanitisation spike (>= 10 PII hits on same column in 1hr)
    # ------------------------------------------------------------------

    def _sanitization_spike(self, event: AuditEvent) -> AnomalyAlert | None:
        if event.event_type not in ("SANITIZATION_APPLIED", "MASKING_APPLIED"):
            return None

        column = event.payload.get("column", event.payload.get("column_name", "unknown"))
        cutoff = event.timestamp - timedelta(hours=1)

        with self._lock:
            q = self._sanitization_times[column]
            q.append(event.timestamp)
            while q and q[0] < cutoff:
                q.popleft()
            count = len(q)

        if count >= self._sanitization_threshold:
            return self._make_alert(
                anomaly_type="SANITIZATION_SPIKE",
                severity=Severity.HIGH,
                user_id=event.user_id,
                description=(
                    f"Sanitisation spike: column '{column}' triggered {count} PII "
                    f"masking events in the last hour (threshold={self._sanitization_threshold}). "
                    f"Review data classification for this column."
                ),
                event_id=event.event_id,
                dedup_key=f"SANITIZATION_SPIKE:{column}:{self._current_hour_bucket()}",
            )
        return None

    # ------------------------------------------------------------------
    # Model 5: BTG duration (sessions exceeding threshold)
    # ------------------------------------------------------------------

    def _btg_duration(self, event: AuditEvent) -> AnomalyAlert | None:
        user_id = event.user_id

        if event.event_type == "BTG_ACTIVATION":
            with self._lock:
                self._active_btg[user_id] = {
                    "start": event.timestamp,
                    "records": 0,
                }
            return None

        if event.event_type in ("BTG_EXPIRED", "BTG_DEACTIVATION", "SESSION_END"):
            with self._lock:
                session = self._active_btg.pop(user_id, None)
            if session:
                duration_hours = (
                    (event.timestamp - session["start"]).total_seconds() / 3600
                )
                if duration_hours > self._btg_duration_hours:
                    return self._make_alert(
                        anomaly_type="BTG_ABUSE",
                        severity=Severity.HIGH,
                        user_id=user_id,
                        description=(
                            f"BTG session exceeded duration threshold: "
                            f"{duration_hours:.1f} hours "
                            f"(threshold={self._btg_duration_hours} hours, "
                            f"records accessed={session['records']})"
                        ),
                        event_id=event.event_id,
                        dedup_key=f"{user_id}:BTG_DURATION:{event.timestamp.date()}",
                    )
            return None

        # Track records accessed during active BTG
        if event.btg_active and event.event_type == "EXECUTION_COMPLETE":
            with self._lock:
                if user_id in self._active_btg:
                    rows = event.payload.get("rows_returned", 0)
                    self._active_btg[user_id]["records"] += rows

        return None

    # ------------------------------------------------------------------
    # Model 6: Sensitivity escalation (increasing avg sensitivity)
    # ------------------------------------------------------------------

    def _sensitivity_escalation(self, event: AuditEvent) -> AnomalyAlert | None:
        sensitivity = event.payload.get("sensitivity_level")
        if sensitivity is None:
            return None

        try:
            level = int(sensitivity)
        except (TypeError, ValueError):
            return None

        user_id = event.user_id
        cutoff = event.timestamp - timedelta(hours=self._sensitivity_window_hours)

        with self._lock:
            history = self._sensitivity_history[user_id]
            history.append((event.timestamp, level))

            # Filter to window
            in_window = [(ts, lv) for ts, lv in history if ts >= cutoff]

        if len(in_window) < 5:
            return None  # Not enough data points

        # Check for escalating trend: split into halves and compare means
        mid = len(in_window) // 2
        first_half_avg = sum(lv for _, lv in in_window[:mid]) / mid
        second_half_avg = sum(lv for _, lv in in_window[mid:]) / (len(in_window) - mid)

        if second_half_avg > first_half_avg + 0.5 and second_half_avg >= 3.0:
            return self._make_alert(
                anomaly_type="SENSITIVITY_ESCALATION",
                severity=Severity.HIGH,
                user_id=user_id,
                description=(
                    f"Sensitivity escalation detected: average sensitivity increased "
                    f"from {first_half_avg:.1f} to {second_half_avg:.1f} over "
                    f"{self._sensitivity_window_hours}h window "
                    f"({len(in_window)} data points)"
                ),
                event_id=event.event_id,
                dedup_key=f"{user_id}:SENSITIVITY_ESCALATION:{self._current_hour_bucket()}",
            )
        return None
