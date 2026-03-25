"""Threat analysis API routes.

GET /api/v1/threat/analysis  -- Threat analysis with time range and user filters
GET /api/v1/threat/patterns  -- Attack pattern library statistics
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Query

from queryvault.app.config import get_settings
from queryvault.app.main import get_audit_pool

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["threat"])
settings = get_settings()


@router.get("/threat/analysis")
async def threat_analysis(
    time_range_days: int = Query(default=7, ge=1, le=365),
    user_id: str | None = Query(default=None, description="Filter by user ID."),
) -> dict:
    """Get threat analysis for the specified time range, optionally filtered by user."""
    start_date = datetime.now(UTC) - timedelta(days=time_range_days)

    audit_pool = get_audit_pool()
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_user: dict[str, int] = {}
    timeline: list[dict] = []
    total = 0

    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                base_query = (
                    "SELECT event_type, severity, user_id, payload, created_at "
                    "FROM audit_events "
                    "WHERE created_at >= $1 "
                    "AND event_type IN ('THREAT_BLOCKED', 'VALIDATION_BLOCKED', 'HALLUCINATION_BLOCKED') "
                )
                params: list = [start_date]

                if user_id:
                    base_query += "AND user_id = $2 "
                    params.append(user_id)

                base_query += "ORDER BY created_at DESC LIMIT 1000"

                rows = await conn.fetch(base_query, *params)

                for row in rows:
                    total += 1
                    event_type = row["event_type"]
                    severity = row["severity"]
                    uid = row.get("user_id", "unknown")

                    by_category[event_type] = by_category.get(event_type, 0) + 1
                    by_severity[severity] = by_severity.get(severity, 0) + 1
                    by_user[uid] = by_user.get(uid, 0) + 1

                    if len(timeline) < 50:
                        timeline.append({
                            "event_type": event_type,
                            "severity": severity,
                            "user_id": uid,
                            "timestamp": row["created_at"].isoformat() if row["created_at"] else None,
                        })
        except Exception as exc:
            logger.warning("threat_analysis_query_failed", error=str(exc))

    return {
        "time_range_days": time_range_days,
        "user_id": user_id,
        "total_threats": total,
        "by_category": by_category,
        "by_severity": by_severity,
        "top_users": dict(sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:10]),
        "recent_events": timeline,
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/threat/patterns")
async def attack_pattern_stats() -> dict:
    """Return statistics about the attack pattern library."""
    patterns_file = settings.attack_patterns_file

    # Resolve relative paths from project root
    if not os.path.isabs(patterns_file):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        patterns_file = os.path.join(base_dir, patterns_file)

    try:
        with open(patterns_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"error": "Attack patterns file not found", "path": patterns_file}
    except json.JSONDecodeError:
        return {"error": "Attack patterns file is invalid JSON"}

    patterns = data.get("patterns", [])
    version = data.get("version", "unknown")

    # Aggregate by category
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    enabled_count = 0
    disabled_count = 0

    for p in patterns:
        cat = p.get("category", "UNKNOWN")
        by_category[cat] = by_category.get(cat, 0) + 1

        weight = p.get("severity_weight", 0)
        if weight >= 0.9:
            sev = "CRITICAL"
        elif weight >= 0.7:
            sev = "HIGH"
        elif weight >= 0.4:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        by_severity[sev] = by_severity.get(sev, 0) + 1

        if p.get("enabled", True):
            enabled_count += 1
        else:
            disabled_count += 1

    return {
        "version": version,
        "total_patterns": len(patterns),
        "enabled": enabled_count,
        "disabled": disabled_count,
        "by_category": by_category,
        "by_severity": by_severity,
    }
