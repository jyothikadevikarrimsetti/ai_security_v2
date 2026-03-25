"""Alert management API routes.

GET  /api/v1/alerts                       -- List alerts with filters
POST /api/v1/alerts/{alert_id}/acknowledge -- Acknowledge an alert
POST /api/v1/alerts/{alert_id}/resolve     -- Resolve an alert
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Query

from queryvault.app.config import get_settings
from queryvault.app.main import get_audit_pool

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["alerts"])
settings = get_settings()


@router.get("/alerts")
async def list_alerts(
    severity: str | None = Query(default=None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)."),
    status: str | None = Query(default=None, description="Filter by status (OPEN, ACKNOWLEDGED, RESOLVED)."),
    user_id: str | None = Query(default=None, description="Filter by user ID."),
    time_range_days: int = Query(default=7, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """List recent security alerts with optional filters."""
    start_date = datetime.now(UTC) - timedelta(days=time_range_days)
    audit_pool = get_audit_pool()
    alerts: list[dict] = []
    total = 0

    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                conditions = ["created_at >= $1"]
                params: list = [start_date]
                idx = 2

                if severity:
                    conditions.append(f"severity = ${idx}")
                    params.append(severity.upper())
                    idx += 1

                if status:
                    conditions.append(f"status = ${idx}")
                    params.append(status.upper())
                    idx += 1

                if user_id:
                    conditions.append(f"user_id = ${idx}")
                    params.append(user_id)
                    idx += 1

                where = " AND ".join(conditions)

                total = await conn.fetchval(
                    f"SELECT COUNT(*) FROM alerts WHERE {where}", *params
                ) or 0

                rows = await conn.fetch(
                    f"SELECT alert_id, severity, status, event_type, user_id, "
                    f"title, description, created_at, acknowledged_at, resolved_at "
                    f"FROM alerts WHERE {where} "
                    f"ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}",
                    *params, limit, offset,
                )
                alerts = [dict(r) for r in rows]
        except Exception as exc:
            logger.warning("list_alerts_failed", error=str(exc))

    return {
        "alerts": alerts,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str) -> dict:
    """Acknowledge a security alert."""
    audit_pool = get_audit_pool()
    now = datetime.now(UTC)

    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                result = await conn.execute(
                    "UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_at = $1 "
                    "WHERE alert_id = $2 AND status = 'OPEN'",
                    now, alert_id,
                )
                if result == "UPDATE 0":
                    return {
                        "status": "not_found",
                        "alert_id": alert_id,
                        "message": "Alert not found or already acknowledged/resolved.",
                    }
        except Exception as exc:
            logger.error("acknowledge_alert_failed", alert_id=alert_id, error=str(exc))
            return {"status": "error", "alert_id": alert_id, "message": str(exc)}

    logger.info("alert_acknowledged", alert_id=alert_id)
    return {
        "status": "acknowledged",
        "alert_id": alert_id,
        "acknowledged_at": now.isoformat(),
    }


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str) -> dict:
    """Resolve a security alert."""
    audit_pool = get_audit_pool()
    now = datetime.now(UTC)

    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                result = await conn.execute(
                    "UPDATE alerts SET status = 'RESOLVED', resolved_at = $1 "
                    "WHERE alert_id = $2 AND status IN ('OPEN', 'ACKNOWLEDGED')",
                    now, alert_id,
                )
                if result == "UPDATE 0":
                    return {
                        "status": "not_found",
                        "alert_id": alert_id,
                        "message": "Alert not found or already resolved.",
                    }
        except Exception as exc:
            logger.error("resolve_alert_failed", alert_id=alert_id, error=str(exc))
            return {"status": "error", "alert_id": alert_id, "message": str(exc)}

    logger.info("alert_resolved", alert_id=alert_id)
    return {
        "status": "resolved",
        "alert_id": alert_id,
        "resolved_at": now.isoformat(),
    }
