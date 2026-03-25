"""Compliance report API routes.

GET /api/v1/compliance/report     -- Generate compliance report
GET /api/v1/compliance/standards  -- List supported standards
GET /api/v1/compliance/dashboard  -- Violation dashboard summary
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Query

from queryvault.app.config import get_settings
from queryvault.app.models.enums import ComplianceStandard
from queryvault.app.main import get_audit_pool

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["compliance"])
settings = get_settings()


@router.get("/compliance/report")
async def generate_report(
    standard: str = Query(
        default="HIPAA_PRIVACY",
        description="Compliance standard to generate report for.",
    ),
    time_range_days: int = Query(
        default=30,
        ge=1,
        le=365,
        description="Number of days to include in the report.",
    ),
) -> dict:
    """Generate a compliance report for a specific regulatory standard.

    Supported standards: HIPAA Privacy, HIPAA Security, 42 CFR Part 2,
    SOX, GDPR, EU AI Act, ISO 42001.
    """
    try:
        std = ComplianceStandard(standard)
    except ValueError:
        return {
            "success": False,
            "error": f"Unsupported standard: {standard}. "
                     f"Valid: {[s.value for s in ComplianceStandard]}",
        }

    start_date = datetime.now(UTC) - timedelta(days=time_range_days)

    audit_pool = get_audit_pool()
    total_queries = 0
    blocked_queries = 0
    violations: list[dict] = []

    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                total_queries = await conn.fetchval(
                    "SELECT COUNT(*) FROM audit_events WHERE created_at >= $1",
                    start_date,
                ) or 0
                blocked_queries = await conn.fetchval(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE created_at >= $1 AND event_type IN "
                    "('THREAT_BLOCKED', 'VALIDATION_BLOCKED', 'HALLUCINATION_BLOCKED')",
                    start_date,
                ) or 0
                rows = await conn.fetch(
                    "SELECT event_type, severity, payload, created_at "
                    "FROM audit_events "
                    "WHERE created_at >= $1 AND event_type LIKE '%BLOCKED%' "
                    "ORDER BY created_at DESC LIMIT 100",
                    start_date,
                )
                violations = [dict(r) for r in rows]
        except Exception as exc:
            logger.warning("compliance_db_query_failed", error=str(exc))

    return {
        "success": True,
        "report": {
            "standard": std.value,
            "generated_at": datetime.now(UTC).isoformat(),
            "time_range_days": time_range_days,
            "start_date": start_date.isoformat(),
            "summary": {
                "total_queries_processed": total_queries,
                "queries_blocked": blocked_queries,
                "block_rate": round(blocked_queries / max(total_queries, 1) * 100, 2),
                "violation_count": len(violations),
            },
            "controls": _standard_controls(std),
            "recent_violations": violations[:20],
        },
    }


@router.get("/compliance/standards")
async def list_standards() -> dict:
    """List all supported compliance standards."""
    return {
        "standards": [
            {
                "id": s.value,
                "name": _standard_display_name(s),
                "description": _standard_description(s),
            }
            for s in ComplianceStandard
        ],
    }


@router.get("/compliance/dashboard")
async def violation_dashboard(
    time_range_days: int = Query(default=7, ge=1, le=365),
) -> dict:
    """Violation dashboard summary with aggregated metrics."""
    start_date = datetime.now(UTC) - timedelta(days=time_range_days)

    audit_pool = get_audit_pool()
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    total = 0

    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT event_type, severity, COUNT(*) as cnt "
                    "FROM audit_events "
                    "WHERE created_at >= $1 AND event_type LIKE '%BLOCKED%' "
                    "GROUP BY event_type, severity",
                    start_date,
                )
                for row in rows:
                    by_type[row["event_type"]] = by_type.get(row["event_type"], 0) + row["cnt"]
                    by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + row["cnt"]
                    total += row["cnt"]
        except Exception as exc:
            logger.warning("dashboard_query_failed", error=str(exc))

    return {
        "time_range_days": time_range_days,
        "total_violations": total,
        "by_type": by_type,
        "by_severity": by_severity,
        "generated_at": datetime.now(UTC).isoformat(),
    }


# ── Helpers ──────────────────────────────────────────────────


def _standard_display_name(std: ComplianceStandard) -> str:
    names = {
        ComplianceStandard.HIPAA_PRIVACY: "HIPAA Privacy Rule",
        ComplianceStandard.HIPAA_SECURITY: "HIPAA Security Rule",
        ComplianceStandard.CFR42_PART2: "42 CFR Part 2",
        ComplianceStandard.SOX: "Sarbanes-Oxley Act",
        ComplianceStandard.GDPR: "General Data Protection Regulation",
        ComplianceStandard.EU_AI_ACT: "EU AI Act",
        ComplianceStandard.ISO_42001: "ISO/IEC 42001",
    }
    return names.get(std, std.value)


def _standard_description(std: ComplianceStandard) -> str:
    desc = {
        ComplianceStandard.HIPAA_PRIVACY: "Protected health information privacy controls.",
        ComplianceStandard.HIPAA_SECURITY: "Electronic PHI security safeguards.",
        ComplianceStandard.CFR42_PART2: "Substance use disorder records confidentiality.",
        ComplianceStandard.SOX: "Financial reporting and internal controls.",
        ComplianceStandard.GDPR: "EU data protection and privacy regulation.",
        ComplianceStandard.EU_AI_ACT: "EU regulation on artificial intelligence systems.",
        ComplianceStandard.ISO_42001: "AI management system standard.",
    }
    return desc.get(std, "")


def _standard_controls(std: ComplianceStandard) -> list[dict]:
    """Return control mapping for a compliance standard."""
    controls_map = {
        ComplianceStandard.HIPAA_PRIVACY: [
            {"control_id": "164.502", "name": "Uses and disclosures", "zone": "PRE_MODEL", "status": "enforced"},
            {"control_id": "164.514", "name": "De-identification", "zone": "POST_MODEL", "status": "enforced"},
            {"control_id": "164.528", "name": "Accounting of disclosures", "zone": "CONTINUOUS", "status": "enforced"},
        ],
        ComplianceStandard.HIPAA_SECURITY: [
            {"control_id": "164.312(a)", "name": "Access control", "zone": "PRE_MODEL", "status": "enforced"},
            {"control_id": "164.312(b)", "name": "Audit controls", "zone": "CONTINUOUS", "status": "enforced"},
            {"control_id": "164.312(c)", "name": "Integrity controls", "zone": "POST_MODEL", "status": "enforced"},
            {"control_id": "164.312(e)", "name": "Transmission security", "zone": "EXECUTION", "status": "enforced"},
        ],
        ComplianceStandard.SOX: [
            {"control_id": "SOX-302", "name": "CEO/CFO certification", "zone": "CONTINUOUS", "status": "enforced"},
            {"control_id": "SOX-404", "name": "Internal controls assessment", "zone": "POST_MODEL", "status": "enforced"},
        ],
        ComplianceStandard.GDPR: [
            {"control_id": "Art.5", "name": "Data processing principles", "zone": "PRE_MODEL", "status": "enforced"},
            {"control_id": "Art.25", "name": "Data protection by design", "zone": "MODEL_BOUNDARY", "status": "enforced"},
            {"control_id": "Art.30", "name": "Records of processing", "zone": "CONTINUOUS", "status": "enforced"},
            {"control_id": "Art.35", "name": "Data protection impact", "zone": "POST_MODEL", "status": "enforced"},
        ],
        ComplianceStandard.EU_AI_ACT: [
            {"control_id": "Art.9", "name": "Risk management system", "zone": "PRE_MODEL", "status": "enforced"},
            {"control_id": "Art.12", "name": "Record-keeping", "zone": "CONTINUOUS", "status": "enforced"},
            {"control_id": "Art.13", "name": "Transparency", "zone": "POST_MODEL", "status": "enforced"},
            {"control_id": "Art.14", "name": "Human oversight", "zone": "EXECUTION", "status": "enforced"},
        ],
        ComplianceStandard.ISO_42001: [
            {"control_id": "6.1", "name": "Actions for risks and opportunities", "zone": "PRE_MODEL", "status": "enforced"},
            {"control_id": "8.4", "name": "AI system impact assessment", "zone": "POST_MODEL", "status": "enforced"},
            {"control_id": "9.1", "name": "Monitoring and measurement", "zone": "CONTINUOUS", "status": "enforced"},
        ],
        ComplianceStandard.CFR42_PART2: [
            {"control_id": "2.13", "name": "Confidentiality restrictions", "zone": "PRE_MODEL", "status": "enforced"},
            {"control_id": "2.16", "name": "Security for records", "zone": "POST_MODEL", "status": "enforced"},
            {"control_id": "2.22", "name": "Audit and evaluation", "zone": "CONTINUOUS", "status": "enforced"},
        ],
    }
    return controls_map.get(std, [])
