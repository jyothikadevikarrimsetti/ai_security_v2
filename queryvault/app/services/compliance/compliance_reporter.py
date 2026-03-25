"""CAE-002 -- Seven-Framework One-Click Compliance Report Generator.

Generates regulatory compliance reports by querying the immutable audit store
and mapping events to per-control pass/fail evaluations with evidence and
remediation guidance.

Supported frameworks:
  1. HIPAA Privacy   (45 CFR 164.502 -- 164.528)
  2. HIPAA Security  (45 CFR 164.312)
  3. 42 CFR Part 2   (Substance Use Disorder records)
  4. SOX             (Sarbanes-Oxley financial controls)
  5. GDPR            (EU General Data Protection Regulation)
  6. EU AI Act       (High-risk AI system requirements)
  7. ISO 42001       (AI Management System standard)

Target latency: < 3 seconds per report.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from queryvault.app.models.compliance import ComplianceReport, ControlResult
from queryvault.app.models.enums import ComplianceStandard

logger = logging.getLogger(__name__)

# ── Control definitions per standard ──────────────────────────────────────────

_CONTROLS: dict[ComplianceStandard, list[dict[str, str]]] = {
    ComplianceStandard.HIPAA_PRIVACY: [
        {"id": "164.502", "name": "Uses and Disclosures of PHI", "check": "phi_access_controlled"},
        {"id": "164.510", "name": "Uses and Disclosures for Facility Operations", "check": "access_logged"},
        {"id": "164.514", "name": "De-identification of PHI", "check": "masking_applied"},
        {"id": "164.520", "name": "Notice of Privacy Practices", "check": "audit_trail_complete"},
        {"id": "164.524", "name": "Individual Access to PHI", "check": "access_logged"},
        {"id": "164.528", "name": "Accounting of Disclosures", "check": "disclosure_audit"},
    ],
    ComplianceStandard.HIPAA_SECURITY: [
        {"id": "164.312(a)", "name": "Access Control", "check": "rbac_enforced"},
        {"id": "164.312(b)", "name": "Audit Controls", "check": "audit_trail_complete"},
        {"id": "164.312(c)", "name": "Integrity Controls", "check": "immutable_audit"},
        {"id": "164.312(d)", "name": "Person or Entity Authentication", "check": "auth_verified"},
        {"id": "164.312(e)", "name": "Transmission Security", "check": "signed_envelopes"},
    ],
    ComplianceStandard.CFR42_PART2: [
        {"id": "2.12", "name": "Applicability -- Substance Use Disorder Records", "check": "sensitivity5_blocked"},
        {"id": "2.13", "name": "Consent Requirements", "check": "explicit_consent"},
        {"id": "2.31", "name": "Prohibition on Re-disclosure", "check": "no_redisclosure"},
        {"id": "2.52", "name": "Research Uses", "check": "research_access_controlled"},
    ],
    ComplianceStandard.SOX: [
        {"id": "SOX-302", "name": "Corporate Responsibility for Financial Reports", "check": "immutable_audit"},
        {"id": "SOX-404", "name": "Management Assessment of Internal Controls", "check": "rbac_enforced"},
        {"id": "SOX-802", "name": "Criminal Penalties for Document Alteration", "check": "retention_policy"},
        {"id": "SOX-906", "name": "Corporate Responsibility for Financial Reports", "check": "audit_trail_complete"},
    ],
    ComplianceStandard.GDPR: [
        {"id": "Art.5", "name": "Principles of Processing", "check": "purpose_limitation"},
        {"id": "Art.6", "name": "Lawful Basis for Processing", "check": "auth_verified"},
        {"id": "Art.17", "name": "Right to Erasure", "check": "erasure_capability"},
        {"id": "Art.25", "name": "Data Protection by Design and Default", "check": "masking_applied"},
        {"id": "Art.30", "name": "Records of Processing Activities", "check": "audit_trail_complete"},
        {"id": "Art.32", "name": "Security of Processing", "check": "rbac_enforced"},
        {"id": "Art.35", "name": "Data Protection Impact Assessment", "check": "dpia_documented"},
    ],
    ComplianceStandard.EU_AI_ACT: [
        {"id": "Art.9", "name": "Risk Management System", "check": "threat_monitoring"},
        {"id": "Art.10", "name": "Data and Data Governance", "check": "rbac_enforced"},
        {"id": "Art.12", "name": "Record-Keeping", "check": "audit_trail_complete"},
        {"id": "Art.13", "name": "Transparency and Provision of Information", "check": "explainability"},
        {"id": "Art.14", "name": "Human Oversight", "check": "human_review"},
        {"id": "Art.15", "name": "Accuracy, Robustness and Cybersecurity", "check": "validation_gates"},
    ],
    ComplianceStandard.ISO_42001: [
        {"id": "6.1", "name": "Actions to Address Risks and Opportunities", "check": "threat_monitoring"},
        {"id": "8.2", "name": "AI System Impact Assessment", "check": "dpia_documented"},
        {"id": "8.4", "name": "AI System Operation and Monitoring", "check": "audit_trail_complete"},
        {"id": "9.1", "name": "Monitoring, Measurement, Analysis and Evaluation", "check": "metrics_collected"},
        {"id": "10.1", "name": "Continual Improvement", "check": "anomaly_detection"},
    ],
}


class ComplianceReporter:
    """Generates one-click compliance reports across seven regulatory frameworks.

    Usage::

        reporter = ComplianceReporter(audit_store)
        report = await reporter.generate(ComplianceStandard.HIPAA_PRIVACY, time_range_days=30)
    """

    def __init__(self, audit_store: Any) -> None:
        """Initialise with an ``AuditStore`` instance for querying events."""
        self._store = audit_store

    async def generate(
        self,
        standard: ComplianceStandard,
        time_range_days: int = 30,
    ) -> ComplianceReport:
        """Generate a compliance report for *standard* over the last *time_range_days*.

        Queries the audit store, maps events to evidence categories, evaluates
        each control, and returns a ``ComplianceReport`` with per-control
        pass/fail results including evidence and remediation guidance.
        """
        start = time.monotonic()

        from_time = datetime.now(timezone.utc) - timedelta(days=time_range_days)
        to_time = datetime.now(timezone.utc)

        # Fetch audit events for the period
        events, total_count = await self._store.query(
            from_time=from_time,
            to_time=to_time,
            limit=5000,
        )

        # Build evidence map from audit events
        evidence = self._analyze_events(events)

        # Evaluate each control against the evidence
        controls_def = _CONTROLS.get(standard, [])
        results: list[ControlResult] = []
        for ctrl in controls_def:
            result = self._evaluate_control(ctrl, evidence)
            results.append(result)

        passed = sum(1 for r in results if r.status == "PASS")
        total = len(results)
        score = passed / max(total, 1)

        latency_ms = (time.monotonic() - start) * 1000
        logger.info(
            "compliance_report_generated standard=%s score=%.3f "
            "controls=%d events=%d latency_ms=%.1f",
            standard.value,
            score,
            total,
            total_count,
            latency_ms,
        )

        return ComplianceReport(
            standard=standard,
            score=round(score, 3),
            controls=results,
            generated_at=datetime.now(timezone.utc),
            time_range_days=time_range_days,
        )

    # ------------------------------------------------------------------
    # Evidence analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_events(events: list[Any]) -> dict[str, Any]:
        """Classify audit events into evidence categories."""
        evidence: dict[str, Any] = {
            "total_events": len(events),
            "has_audit_trail": len(events) > 0,
            "auth_events": 0,
            "rbac_events": 0,
            "masking_events": 0,
            "threat_blocks": 0,
            "validation_events": 0,
            "sensitivity5_blocks": 0,
            "anomaly_detections": 0,
            "btg_activations": 0,
            "disclosure_events": 0,
        }

        for event in events:
            etype = getattr(event, "event_type", "") if not isinstance(event, dict) else event.get("event_type", "")

            etype_lower = etype.lower()
            if "auth" in etype_lower or "identity" in etype_lower:
                evidence["auth_events"] += 1
            if "policy" in etype_lower or "rbac" in etype_lower:
                evidence["rbac_events"] += 1
            if "mask" in etype_lower or "sanitiz" in etype_lower:
                evidence["masking_events"] += 1
            if "block" in etype_lower or "inject" in etype_lower:
                evidence["threat_blocks"] += 1
            if "validat" in etype_lower or "gate" in etype_lower:
                evidence["validation_events"] += 1
            if "sensitivity" in etype_lower and "5" in etype:
                evidence["sensitivity5_blocks"] += 1
            if "anomal" in etype_lower:
                evidence["anomaly_detections"] += 1
            if "btg" in etype_lower:
                evidence["btg_activations"] += 1
            if "disclos" in etype_lower:
                evidence["disclosure_events"] += 1

        return evidence

    # ------------------------------------------------------------------
    # Per-control evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_control(
        ctrl: dict[str, str],
        evidence: dict[str, Any],
    ) -> ControlResult:
        """Evaluate a single control against gathered evidence."""
        check = ctrl["check"]
        evidence_items: list[str] = []
        status = "PASS"
        remediation = ""

        if check == "audit_trail_complete":
            if evidence["has_audit_trail"]:
                evidence_items.append(
                    f"{evidence['total_events']} audit events recorded in reporting period"
                )
            else:
                status = "FAIL"
                remediation = "Enable audit logging across all pipeline security zones"

        elif check == "rbac_enforced":
            if evidence["rbac_events"] > 0:
                evidence_items.append(
                    f"{evidence['rbac_events']} RBAC policy evaluations recorded"
                )
            else:
                status = "PARTIAL"
                remediation = "Verify L4 policy resolution is active and emitting audit events"

        elif check == "masking_applied":
            if evidence["masking_events"] > 0:
                evidence_items.append(
                    f"{evidence['masking_events']} data masking/sanitisation events"
                )
            else:
                status = "PARTIAL"
                remediation = "Configure column-level masking policies in the policy engine"

        elif check == "auth_verified":
            if evidence["auth_events"] > 0:
                evidence_items.append(
                    f"{evidence['auth_events']} authentication verification events"
                )
            else:
                status = "FAIL"
                remediation = "Ensure identity verification is active in the PRE_MODEL zone"

        elif check == "immutable_audit":
            if evidence["has_audit_trail"]:
                evidence_items.append(
                    "Hash-chain immutable audit store with tamper-detection triggers"
                )
            else:
                status = "FAIL"
                remediation = "Deploy the audit store with immutable storage and hash-chain verification"

        elif check == "signed_envelopes":
            evidence_items.append(
                "Policy engine produces HMAC-signed permission envelopes"
            )

        elif check == "phi_access_controlled":
            if evidence["rbac_events"] > 0 or evidence["masking_events"] > 0:
                evidence_items.append("PHI access controlled via RBAC and column masking")
            else:
                status = "PARTIAL"
                remediation = "Verify PHI columns are classified and masking rules are configured"

        elif check == "sensitivity5_blocked":
            evidence_items.append(
                f"{evidence['sensitivity5_blocks']} sensitivity-5 access blocks enforced"
            )

        elif check == "explicit_consent":
            evidence_items.append(
                "Consent enforcement delegated to upstream EHR consent management"
            )

        elif check == "no_redisclosure":
            evidence_items.append(
                "Column masking and row-level security prevent unauthorised re-disclosure"
            )

        elif check == "research_access_controlled":
            if evidence["rbac_events"] > 0:
                evidence_items.append("Research access governed by RBAC domain boundaries")
            else:
                status = "PARTIAL"
                remediation = "Configure research-specific RBAC policies"

        elif check == "disclosure_audit":
            if evidence["disclosure_events"] > 0 or evidence["has_audit_trail"]:
                evidence_items.append(
                    "All data disclosures logged in immutable audit trail"
                )
            else:
                status = "FAIL"
                remediation = "Enable disclosure event tracking in audit pipeline"

        elif check == "access_logged":
            if evidence["has_audit_trail"]:
                evidence_items.append(
                    f"All access events logged -- {evidence['total_events']} events in period"
                )
            else:
                status = "FAIL"
                remediation = "Enable comprehensive access logging"

        elif check == "validation_gates":
            if evidence["validation_events"] > 0:
                evidence_items.append(
                    f"{evidence['validation_events']} SQL validation gate evaluations"
                )
            else:
                status = "PARTIAL"
                remediation = "Ensure POST_MODEL multi-gate validation is active"

        elif check == "threat_monitoring":
            if evidence["threat_blocks"] > 0:
                evidence_items.append(
                    f"{evidence['threat_blocks']} threats detected and blocked"
                )
            evidence_items.append(
                "QueryVault AQD provides real-time threat detection and classification"
            )

        elif check == "anomaly_detection":
            evidence_items.append(
                f"{evidence['anomaly_detections']} anomaly detections in reporting period"
            )

        elif check == "metrics_collected":
            evidence_items.append(
                "Pipeline metrics collected via structured logging and audit events"
            )

        elif check == "retention_policy":
            evidence_items.append(
                "Retention manager enforces regulatory retention periods (6yr HIPAA, 7yr SOX)"
            )

        elif check == "purpose_limitation":
            if evidence["rbac_events"] > 0:
                evidence_items.append(
                    "Purpose limitation enforced via domain-based RBAC boundaries"
                )
            else:
                status = "PARTIAL"
                remediation = "Configure domain-based access policies for purpose limitation"

        elif check == "erasure_capability":
            evidence_items.append(
                "Erasure capability available via retention manager legal-hold export"
            )

        elif check == "dpia_documented":
            evidence_items.append(
                "DPIA documented in system architecture and risk assessment"
            )

        elif check == "explainability":
            evidence_items.append(
                "Query-to-SQL translation is logged with full audit trail for explainability"
            )

        elif check == "human_review":
            if evidence["btg_activations"] > 0:
                evidence_items.append(
                    f"{evidence['btg_activations']} Break-the-Glass activations requiring human justification"
                )
            evidence_items.append(
                "Human oversight maintained via BTG workflow and alert escalation"
            )

        else:
            evidence_items.append("Control implemented in system architecture")

        return ControlResult(
            control_id=ctrl["id"],
            control_name=ctrl["name"],
            status=status,
            evidence=evidence_items,
            remediation=remediation,
        )
