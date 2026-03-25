"""SAG-007 -- Violation Reporter.

Produces a structured violation report from the results of all three
validation gates.  Each report includes:
  - Which gate(s) failed
  - Which table / column / pattern caused the violation
  - Which policy was violated
  - A human-readable summary

Reports are suitable for both API responses and audit-trail storage.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ViolationEntry:
    """A single violation for the structured report."""

    gate: str
    violation_type: str
    table: str = ""
    column: str = ""
    description: str = ""
    severity: str = "CRITICAL"
    policy_ref: str = ""


@dataclass
class ViolationReport:
    """Complete violation report across all gates."""

    violations: list[ViolationEntry] = field(default_factory=list)
    summary: str = ""
    blocked: bool = False
    gate_results: dict[str, bool] = field(default_factory=dict)
    timestamp: str = ""
    total_violations: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0


# ---------------------------------------------------------------------------
# Gate result protocol (duck-typed)
# ---------------------------------------------------------------------------
# Each gate returns an object with:
#   .passed: bool
#   .violations: list  (each with .type, .table, .column, .description, .severity)
#   .gate_name: str


# ---------------------------------------------------------------------------
# ViolationReporter
# ---------------------------------------------------------------------------

class ViolationReporter:
    """Aggregates gate results into a structured violation report."""

    # Map violation types to the SAG policy reference
    _POLICY_MAP: dict[str, str] = {
        "UNAUTHORIZED_TABLE": "SAG-001/TABLE_AUTH",
        "UNAUTHORIZED_COLUMN": "SAG-001/COLUMN_AUTH",
        "AGGREGATION_VIOLATION": "SAG-001/AGGREGATION",
        "MISSING_REQUIRED_FILTER": "SAG-001/ROW_FILTER",
        "EXCESSIVE_SUBQUERY_DEPTH": "SAG-001/SUBQUERY_DEPTH",
        "STACKED_QUERIES": "SAG-001/STACKED_QUERIES",
        "WRITE_OPERATION": "SAG-001/WRITE_OP",
        "UNPARSEABLE_SQL": "SAG-001/PARSE_ERROR",
        "SENSITIVITY_EXCEEDED": "SAG-002/SENSITIVITY",
        "UNMASKED_PII_COLUMN": "SAG-002/MASKING",
        "AGGREGATE_ON_PII": "SAG-002/AGG_PII",
        "UNION_EXFILTRATION": "SAG-003/UNION",
        "SYSTEM_TABLE_ACCESS": "SAG-003/SYSTEM_TABLE",
        "DYNAMIC_SQL": "SAG-003/DYNAMIC_SQL",
        "FILE_OPERATION": "SAG-003/FILE_OP",
        "PRIVILEGE_ESCALATION": "SAG-003/PRIVILEGE",
        "COMMENT_INJECTION": "SAG-003/COMMENT",
        "CARTESIAN_PRODUCT": "SAG-003/CARTESIAN",
        "EXCESSIVE_COLUMNS": "SAG-003/EXCESSIVE_COLS",
    }

    def report(self, gate_results: list[Any]) -> ViolationReport:
        """Build a structured violation report from gate results.

        Parameters
        ----------
        gate_results : list
            List of GateResult objects from gate1, gate2, gate3.
            Each must have: .passed, .violations, .gate_name

        Returns
        -------
        ViolationReport
        """
        entries: list[ViolationEntry] = []
        gate_status: dict[str, bool] = {}
        blocked = False

        for gr in gate_results:
            gate_name = getattr(gr, "gate_name", "unknown")
            passed = getattr(gr, "passed", True)
            gate_status[gate_name] = passed

            if not passed:
                blocked = True

            for v in getattr(gr, "violations", []):
                v_type = getattr(v, "type", "UNKNOWN")
                entry = ViolationEntry(
                    gate=gate_name,
                    violation_type=v_type,
                    table=getattr(v, "table", ""),
                    column=getattr(v, "column", ""),
                    description=getattr(v, "description", ""),
                    severity=getattr(v, "severity", "CRITICAL"),
                    policy_ref=self._POLICY_MAP.get(v_type, f"{gate_name}/{v_type}"),
                )
                entries.append(entry)

        # Counts by severity
        critical_count = sum(1 for e in entries if e.severity == "CRITICAL")
        high_count = sum(1 for e in entries if e.severity == "HIGH")
        medium_count = sum(1 for e in entries if e.severity == "MEDIUM")

        # Build summary
        summary = self._build_summary(
            entries, gate_status, blocked, critical_count, high_count, medium_count
        )

        report = ViolationReport(
            violations=entries,
            summary=summary,
            blocked=blocked,
            gate_results=gate_status,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_violations=len(entries),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
        )

        if blocked:
            logger.warning(
                "Query BLOCKED: %d violation(s) (%d critical)",
                len(entries), critical_count,
            )
        else:
            logger.info(
                "Query PASSED with %d non-blocking violation(s)",
                len(entries),
            )

        return report

    def _build_summary(
        self,
        entries: list[ViolationEntry],
        gate_status: dict[str, bool],
        blocked: bool,
        critical: int,
        high: int,
        medium: int,
    ) -> str:
        """Build a human-readable summary string."""
        if not entries:
            return "All gates passed. No violations detected."

        failed_gates = [g for g, passed in gate_status.items() if not passed]
        passed_gates = [g for g, passed in gate_status.items() if passed]

        parts: list[str] = []

        if blocked:
            parts.append(
                f"BLOCKED: {len(entries)} violation(s) detected across "
                f"{len(failed_gates)} failed gate(s)."
            )
        else:
            parts.append(
                f"PASSED with {len(entries)} non-critical violation(s)."
            )

        if failed_gates:
            parts.append(f"Failed gates: {', '.join(failed_gates)}.")
        if passed_gates:
            parts.append(f"Passed gates: {', '.join(passed_gates)}.")

        severity_parts: list[str] = []
        if critical:
            severity_parts.append(f"{critical} CRITICAL")
        if high:
            severity_parts.append(f"{high} HIGH")
        if medium:
            severity_parts.append(f"{medium} MEDIUM")
        if severity_parts:
            parts.append(f"Severity breakdown: {', '.join(severity_parts)}.")

        return " ".join(parts)
