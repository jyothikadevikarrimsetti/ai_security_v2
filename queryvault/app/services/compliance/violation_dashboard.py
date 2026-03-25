"""CAE-003 -- Real-Time Violation Dashboard Data Aggregation.

Provides aggregated violation and block data for dashboard consumption:
  - Blocks/violations by user, role, department, and time period
  - Most-denied tables and columns
  - Trend analysis at configurable granularity
  - Drill-down to individual query traces via request_id
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ViolationEntry:
    """Single violation/block event with drill-down context."""

    event_id: str
    request_id: str
    user_id: str
    event_type: str
    source_zone: str
    timestamp: datetime
    severity: str
    description: str
    table_name: str = ""
    column_name: str = ""
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrendPoint:
    """A single data point in a time-series trend."""

    bucket: str
    count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)


@dataclass
class TrendData:
    """Time-series trend data at a given granularity."""

    granularity: str
    points: list[TrendPoint] = field(default_factory=list)
    total: int = 0


@dataclass
class DashboardSummary:
    """Aggregated violation summary for the dashboard view."""

    time_range_hours: int = 24
    total_violations: int = 0
    total_blocks: int = 0
    by_user: dict[str, int] = field(default_factory=dict)
    by_role: dict[str, int] = field(default_factory=dict)
    by_department: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_source_zone: dict[str, int] = field(default_factory=dict)
    most_denied_tables: list[tuple[str, int]] = field(default_factory=list)
    most_denied_columns: list[tuple[str, int]] = field(default_factory=list)
    top_violators: list[tuple[str, int]] = field(default_factory=list)


# ── Event types that count as violations/blocks ──────────────────────────────

_VIOLATION_EVENT_TYPES = {
    "VALIDATION_BLOCK",
    "VALIDATION_BLOCKED",
    "POLICY_DENY",
    "POLICY_DENIED",
    "ACCESS_DENIED",
    "INJECTION_BLOCKED",
    "PROBING_BLOCKED",
    "THREAT_BLOCKED",
    "SENSITIVITY_BLOCK",
    "RBAC_DENIED",
    "BTG_EXPIRED",
}


class ViolationDashboard:
    """Aggregates violation data from the audit store for dashboard rendering.

    Usage::

        dashboard = ViolationDashboard(audit_store)
        summary = await dashboard.get_summary(time_range_hours=24)
        violations = await dashboard.get_violations(filters={"user_id": "dr.smith"})
        trends = await dashboard.get_trends(time_range_hours=168, granularity="daily")
    """

    def __init__(self, audit_store: Any) -> None:
        self._store = audit_store

    async def get_summary(
        self,
        time_range_hours: int = 24,
    ) -> DashboardSummary:
        """Return an aggregated violation summary for the given time window."""
        from_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
        to_time = datetime.now(timezone.utc)

        events, total = await self._store.query(
            from_time=from_time,
            to_time=to_time,
            limit=10000,
        )

        summary = DashboardSummary(time_range_hours=time_range_hours)
        table_counts: dict[str, int] = {}
        column_counts: dict[str, int] = {}
        user_counts: dict[str, int] = {}

        for event in events:
            etype = event.event_type
            if etype not in _VIOLATION_EVENT_TYPES:
                continue

            summary.total_violations += 1
            if "BLOCK" in etype or "DENIED" in etype or "DENY" in etype:
                summary.total_blocks += 1

            # By user
            uid = event.user_id
            user_counts[uid] = user_counts.get(uid, 0) + 1
            summary.by_user[uid] = summary.by_user.get(uid, 0) + 1

            # By severity
            sev = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
            summary.by_severity[sev] = summary.by_severity.get(sev, 0) + 1

            # By source zone
            zone = event.source_zone
            summary.by_source_zone[zone] = summary.by_source_zone.get(zone, 0) + 1

            # By role/department from payload
            payload = event.payload or {}
            role = payload.get("role", "")
            dept = payload.get("department", "")
            if role:
                summary.by_role[role] = summary.by_role.get(role, 0) + 1
            if dept:
                summary.by_department[dept] = summary.by_department.get(dept, 0) + 1

            # Table/column tracking
            table = payload.get("table", payload.get("table_name", ""))
            column = payload.get("column", payload.get("column_name", ""))
            if table:
                table_counts[table] = table_counts.get(table, 0) + 1
            if column:
                column_counts[column] = column_counts.get(column, 0) + 1

        # Sort and take top entries
        summary.most_denied_tables = sorted(
            table_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        summary.most_denied_columns = sorted(
            column_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        summary.top_violators = sorted(
            user_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]

        logger.info(
            "dashboard_summary_generated violations=%d blocks=%d hours=%d",
            summary.total_violations,
            summary.total_blocks,
            time_range_hours,
        )
        return summary

    async def get_violations(
        self,
        filters: Optional[dict[str, Any]] = None,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[ViolationEntry]:
        """Return individual violation entries matching the given filters.

        Supported filter keys: ``user_id``, ``source_zone``, ``severity``,
        ``event_type``, ``request_id``.
        """
        filters = filters or {}

        # Default to violation event types if not explicitly filtered
        if "event_type" not in filters:
            filters["event_type"] = list(_VIOLATION_EVENT_TYPES)

        events, _ = await self._store.query(
            filters=filters,
            offset=offset,
            limit=limit,
        )

        violations: list[ViolationEntry] = []
        for event in events:
            payload = event.payload or {}
            violations.append(
                ViolationEntry(
                    event_id=event.event_id,
                    request_id=event.request_id,
                    user_id=event.user_id,
                    event_type=event.event_type,
                    source_zone=event.source_zone,
                    timestamp=event.timestamp,
                    severity=event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                    description=payload.get("reason", payload.get("description", event.event_type)),
                    table_name=payload.get("table", payload.get("table_name", "")),
                    column_name=payload.get("column", payload.get("column_name", "")),
                    payload=payload,
                )
            )

        return violations

    async def get_trends(
        self,
        time_range_hours: int = 168,
        granularity: str = "hourly",
    ) -> TrendData:
        """Return violation trend data at the specified granularity.

        Granularity options: ``hourly``, ``daily``, ``weekly``.
        """
        from_time = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
        to_time = datetime.now(timezone.utc)

        events, _ = await self._store.query(
            from_time=from_time,
            to_time=to_time,
            limit=50000,
        )

        # Bucket events
        buckets: dict[str, dict[str, int]] = {}  # bucket_key -> severity -> count

        for event in events:
            if event.event_type not in _VIOLATION_EVENT_TYPES:
                continue

            bucket_key = self._to_bucket_key(event.timestamp, granularity)
            if bucket_key not in buckets:
                buckets[bucket_key] = {}

            sev = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
            buckets[bucket_key][sev] = buckets[bucket_key].get(sev, 0) + 1

        # Build sorted trend points
        points: list[TrendPoint] = []
        total = 0
        for key in sorted(buckets.keys()):
            breakdown = buckets[key]
            count = sum(breakdown.values())
            total += count
            points.append(
                TrendPoint(bucket=key, count=count, severity_breakdown=breakdown)
            )

        return TrendData(granularity=granularity, points=points, total=total)

    @staticmethod
    def _to_bucket_key(ts: datetime, granularity: str) -> str:
        """Convert a timestamp to a bucket key string."""
        if granularity == "daily":
            return ts.strftime("%Y-%m-%d")
        elif granularity == "weekly":
            return ts.strftime("%Y-W%W")
        else:  # hourly
            return ts.strftime("%Y-%m-%dT%H:00")
