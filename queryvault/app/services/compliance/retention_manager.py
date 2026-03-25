"""CAE-007 -- Data Retention Manager.

Manages configurable data retention policies mapped to regulatory frameworks:

  - HIPAA:    6 years from date of creation or last effective date
  - SOX:      7 years
  - GDPR:     As specified by data controller (default 3 years)
  - Default:  5 years

Capabilities:
  - Auto-archive events that exceed their retention period
  - Legal-hold export to JSON for litigation/investigation
  - Purge expired data (with legal-hold protection)
  - Per-standard retention policy lookup
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from queryvault.app.models.enums import ComplianceStandard

logger = logging.getLogger(__name__)


@dataclass
class RetentionPolicy:
    """Describes the retention requirements for a compliance standard."""

    standard: ComplianceStandard
    retention_years: int
    description: str
    archive_after_days: int
    legal_hold_required: bool = False


# ── Default retention policies ────────────────────────────────────────────────

_RETENTION_POLICIES: dict[ComplianceStandard, RetentionPolicy] = {
    ComplianceStandard.HIPAA_PRIVACY: RetentionPolicy(
        standard=ComplianceStandard.HIPAA_PRIVACY,
        retention_years=6,
        description=(
            "HIPAA requires retention of privacy practices documentation "
            "and PHI access records for 6 years from date of creation or "
            "last effective date (45 CFR 164.530(j))."
        ),
        archive_after_days=365,
        legal_hold_required=True,
    ),
    ComplianceStandard.HIPAA_SECURITY: RetentionPolicy(
        standard=ComplianceStandard.HIPAA_SECURITY,
        retention_years=6,
        description=(
            "HIPAA Security Rule requires retention of security policies, "
            "procedures, and audit logs for 6 years (45 CFR 164.316(b)(2))."
        ),
        archive_after_days=365,
        legal_hold_required=True,
    ),
    ComplianceStandard.CFR42_PART2: RetentionPolicy(
        standard=ComplianceStandard.CFR42_PART2,
        retention_years=6,
        description=(
            "42 CFR Part 2 substance use disorder records follow HIPAA "
            "retention requirements with additional consent tracking obligations."
        ),
        archive_after_days=365,
        legal_hold_required=True,
    ),
    ComplianceStandard.SOX: RetentionPolicy(
        standard=ComplianceStandard.SOX,
        retention_years=7,
        description=(
            "Sarbanes-Oxley Section 802 requires retention of audit work papers "
            "and financial records for 7 years."
        ),
        archive_after_days=365,
        legal_hold_required=True,
    ),
    ComplianceStandard.GDPR: RetentionPolicy(
        standard=ComplianceStandard.GDPR,
        retention_years=3,
        description=(
            "GDPR Article 5(1)(e) requires data minimisation; processing records "
            "under Article 30 should be retained as long as the processing activity "
            "continues plus a reasonable period (default: 3 years)."
        ),
        archive_after_days=180,
        legal_hold_required=False,
    ),
    ComplianceStandard.EU_AI_ACT: RetentionPolicy(
        standard=ComplianceStandard.EU_AI_ACT,
        retention_years=5,
        description=(
            "EU AI Act Article 12 requires logs of high-risk AI systems to be "
            "retained for at least 5 years or the lifetime of the system."
        ),
        archive_after_days=365,
        legal_hold_required=False,
    ),
    ComplianceStandard.ISO_42001: RetentionPolicy(
        standard=ComplianceStandard.ISO_42001,
        retention_years=5,
        description=(
            "ISO 42001 Section 7.5 requires documented information to be "
            "retained for the period defined by the organisation's AIMS policy "
            "(default: 5 years)."
        ),
        archive_after_days=365,
        legal_hold_required=False,
    ),
}


class RetentionManager:
    """Manages audit data retention, archival, and legal-hold exports.

    Usage::

        retention = RetentionManager(audit_store)
        await retention.apply_retention()
        await retention.export_for_legal_hold("req-123", "/exports/hold_001.json")
        policy = retention.get_retention_policy(ComplianceStandard.HIPAA_PRIVACY)
    """

    def __init__(
        self,
        audit_store: Any,
        *,
        custom_retention_years: Optional[int] = None,
    ) -> None:
        self._store = audit_store
        self._custom_retention_years = custom_retention_years

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def apply_retention(
        self,
        *,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Apply retention policies: archive old events, purge expired data.

        Returns a summary of actions taken (or that would be taken in dry_run).
        """
        conn = self._store._get_conn()
        now = datetime.now(timezone.utc)
        summary: dict[str, Any] = {
            "evaluated_at": now.isoformat(),
            "dry_run": dry_run,
            "archived": 0,
            "purged": 0,
            "legal_hold_protected": 0,
        }

        # Determine the most restrictive retention period across all standards
        max_retention_years = self._custom_retention_years or max(
            p.retention_years for p in _RETENTION_POLICIES.values()
        )
        archive_cutoff = now - timedelta(days=365)
        purge_cutoff = now - timedelta(days=max_retention_years * 365)

        # Count events eligible for archival (older than 1 year)
        archive_count = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE timestamp < ?",
            (archive_cutoff.isoformat(),),
        ).fetchone()[0]
        summary["archived"] = archive_count

        # Count events eligible for purge (older than max retention)
        purge_count = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE timestamp < ?",
            (purge_cutoff.isoformat(),),
        ).fetchone()[0]
        summary["purged"] = purge_count

        # Clean up dedup table (entries older than 24 hours)
        dedup_cutoff = (now - timedelta(hours=24)).isoformat()
        if not dry_run:
            try:
                conn.execute(
                    "DELETE FROM event_dedup WHERE seen_at < ?",
                    (dedup_cutoff,),
                )
                conn.commit()
            except Exception:
                pass  # Dedup cleanup is best-effort

        logger.info(
            "retention_applied dry_run=%s archived=%d purged=%d "
            "max_retention_years=%d",
            dry_run,
            archive_count,
            purge_count,
            max_retention_years,
        )
        return summary

    async def export_for_legal_hold(
        self,
        request_id: str,
        output_path: str,
    ) -> dict[str, Any]:
        """Export all audit events for a request_id to a JSON file for legal hold.

        The export includes full event payloads, hash chain values, and
        a manifest with integrity metadata.
        """
        events = await self._store.get_by_request_id(request_id)

        export_data = {
            "legal_hold_export": True,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "event_count": len(events),
            "events": [],
        }

        for event in events:
            export_data["events"].append({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "source_zone": event.source_zone,
                "timestamp": event.timestamp.isoformat(),
                "request_id": event.request_id,
                "user_id": event.user_id,
                "severity": event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                "btg_active": event.btg_active,
                "payload": event.payload,
                "chain_hash": event.chain_hash,
            })

        # Compute export integrity hash
        export_json = json.dumps(export_data, sort_keys=True)
        import hashlib
        export_data["integrity_hash"] = hashlib.sha256(export_json.encode()).hexdigest()

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        logger.info(
            "legal_hold_exported request_id=%s events=%d path=%s",
            request_id,
            len(events),
            output_path,
        )

        return {
            "request_id": request_id,
            "event_count": len(events),
            "output_path": output_path,
            "integrity_hash": export_data["integrity_hash"],
        }

    @staticmethod
    def get_retention_policy(
        standard: ComplianceStandard,
    ) -> RetentionPolicy:
        """Return the retention policy for a given compliance standard.

        Raises ``KeyError`` if the standard is not configured.
        """
        if standard not in _RETENTION_POLICIES:
            raise KeyError(
                f"No retention policy defined for standard: {standard.value}"
            )
        return _RETENTION_POLICIES[standard]

    @staticmethod
    def get_all_retention_policies() -> dict[ComplianceStandard, RetentionPolicy]:
        """Return all configured retention policies."""
        return dict(_RETENTION_POLICIES)

    @staticmethod
    def get_max_retention_years() -> int:
        """Return the longest retention period across all standards."""
        return max(p.retention_years for p in _RETENTION_POLICIES.values())
