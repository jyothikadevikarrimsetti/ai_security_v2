"""SAG-002 -- Gate 2: Data Classification Check.

Validates column sensitivity levels against user clearance.  Operates
independently of Gate 1 -- it can BLOCK even if Gate 1 passes, and
vice versa.

Key rules:
  - Sensitivity-5 columns are ALWAYS DENIED (no masking option).
  - PII heuristics kick in for columns not in the classification cache.
  - Unmasked PII in SELECT is flagged for the query rewriter.
  - Aggregate functions on high-sensitivity columns are flagged.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from queryvault.app.models.enums import (
    GateResult as GateDecision,
    PolicyDecision,
    ColumnVisibility,
)
from queryvault.app.models.security_context import (
    PermissionEnvelope,
    SecurityContext,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local data classes (shared shape with gate1)
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    type: str
    table: str = ""
    column: str = ""
    description: str = ""
    severity: str = "CRITICAL"


@dataclass
class GateResult:
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    gate_name: str = "gate2_classification"
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Sensitivity helpers
# ---------------------------------------------------------------------------

_SENSITIVITY_LABELS = {
    1: "Public",
    2: "Internal",
    3: "Confidential",
    4: "Highly Confidential",
    5: "Restricted",
}

_PII_COLUMN_NAMES = {
    "ssn", "aadhaar_number", "social_security_number",
    "full_name", "patient_name", "date_of_birth", "dob",
    "phone", "email", "address", "financial_account",
    "insurance_id", "credit_card", "bank_account",
    "mrn", "medical_record_number",
    # Sensitivity 5 (restricted -- always denied)
    "substance_abuse", "psychotherapy_notes", "hiv_status",
    "genetic_data", "behavioral_health",
}

_AGGREGATE_FUNCTIONS = {"count", "max", "min", "avg", "sum", "stddev", "variance"}


def _get_user_clearance(security_context: SecurityContext) -> int:
    """Extract user clearance level from SecurityContext."""
    return security_context.authorization.clearance_level


def _get_col_sensitivity(
    col_name: str,
    table_name: str,
    classification_cache: dict[str, int],
) -> int:
    """Look up column sensitivity from cache; fall back to PII heuristics."""
    key = f"{table_name}.{col_name}".lower()
    if key in classification_cache:
        return classification_cache[key]

    # Also try column-only key
    if col_name.lower() in classification_cache:
        return classification_cache[col_name.lower()]

    # Heuristic fallback
    col_lower = col_name.lower()
    if any(tok in col_lower for tok in ("ssn", "aadhaar", "genetic")):
        return 4
    if any(tok in col_lower for tok in ("substance", "psychotherapy", "hiv")):
        return 5
    if any(tok in col_lower for tok in (
        "dob", "date_of_birth", "phone", "email",
        "address", "full_name", "patient_name",
    )):
        return 3
    if col_lower in {"mrn", "medical_record_number", "insurance_id"}:
        return 3
    return 1  # Default: Public


def _build_allowed_map(envelope: PermissionEnvelope) -> dict[str, str]:
    allowed: dict[str, str] = {}
    for tp in envelope.table_permissions:
        if tp.decision != PolicyDecision.DENY:
            name_part = tp.table_id.split(".")[-1].lower()
            allowed[name_part] = tp.table_id
            allowed[tp.table_id.lower()] = tp.table_id
            if tp.table_name:
                allowed[tp.table_name.lower()] = tp.table_id
    return allowed


def _get_table_permission(envelope, table_id):
    for tp in envelope.table_permissions:
        if tp.table_id == table_id:
            return tp
    return None


def _masked_column_names(tp) -> set[str]:
    names: set[str] = set()
    for col in tp.columns:
        col_name = col.get("column_name", col.get("name", "")).lower()
        col_vis = col.get("visibility", "VISIBLE").upper()
        if col_vis == "MASKED":
            names.add(col_name)
    return names


# ---------------------------------------------------------------------------
# Gate 2 runner
# ---------------------------------------------------------------------------

def run(
    parsed_sql: dict,
    permission_envelope: PermissionEnvelope,
    security_context: SecurityContext,
    classification_cache: dict[str, int] | None = None,
) -> GateResult:
    """Execute Gate 2 data classification check.

    Parameters
    ----------
    parsed_sql : dict
        Parsed SQL dictionary (same shape as gate1).
    permission_envelope : PermissionEnvelope
    security_context : SecurityContext
    classification_cache : dict | None
        Optional mapping of 'table.column' -> sensitivity level (int 1-5).

    Returns
    -------
    GateResult
    """
    start = time.monotonic()
    violations: list[Violation] = []
    cache = classification_cache or {}

    # If SQL is unparseable or not a SELECT, skip (gate1 handles that)
    if parsed_sql.get("parse_error") or not parsed_sql.get("is_select", True):
        return GateResult(
            passed=True,
            violations=[],
            latency_ms=(time.monotonic() - start) * 1000,
        )

    user_clearance = _get_user_clearance(security_context)
    allowed_map = _build_allowed_map(permission_envelope)

    columns: list[tuple[str, str]] = parsed_sql.get("columns", [])
    select_columns: list[tuple[str, str]] = parsed_sql.get("select_columns", [])
    select_col_set = {(t.lower() if t else "", c.lower()) for t, c in select_columns}

    for col_table, col_name in columns:
        if col_name in ("*", ""):
            continue

        col_lower = col_name.lower()

        # Resolve table
        if not col_table:
            # Unknown table reference -- cannot check classification
            # Still apply PII heuristics
            sensitivity = _get_col_sensitivity(col_lower, "", cache)
            if sensitivity == 5:
                violations.append(Violation(
                    type="SENSITIVITY_EXCEEDED",
                    column=col_name,
                    description=(
                        f"Column '{col_name}' has sensitivity level 5 "
                        f"(RESTRICTED) -- always denied"
                    ),
                    severity="CRITICAL",
                ))
            elif sensitivity > user_clearance:
                violations.append(Violation(
                    type="SENSITIVITY_EXCEEDED",
                    column=col_name,
                    description=(
                        f"Column '{col_name}' sensitivity={sensitivity} "
                        f"exceeds user clearance={user_clearance}"
                    ),
                    severity="CRITICAL",
                ))
            continue

        table_lower = col_table.lower()
        table_id = allowed_map.get(table_lower)
        if not table_id:
            continue

        tp = _get_table_permission(permission_envelope, table_id)

        # -- Masking compliance check ------------------------------------------
        if tp:
            masked_cols = _masked_column_names(tp)
            is_in_select = (
                (table_lower, col_lower) in select_col_set
                or ("", col_lower) in select_col_set
            )

            if col_lower in masked_cols and is_in_select:
                violations.append(Violation(
                    type="UNMASKED_PII_COLUMN",
                    table=col_table,
                    column=col_name,
                    description=(
                        f"PII column '{col_name}' selected without masking "
                        f"expression (query rewriter will apply masking)"
                    ),
                    severity="HIGH",
                ))

        # -- Sensitivity vs clearance ------------------------------------------
        sensitivity = _get_col_sensitivity(col_lower, table_lower, cache)

        if sensitivity == 5:
            violations.append(Violation(
                type="SENSITIVITY_EXCEEDED",
                table=col_table,
                column=col_name,
                description=(
                    f"Column '{col_name}' has sensitivity level 5 "
                    f"(RESTRICTED) -- always denied"
                ),
                severity="CRITICAL",
            ))
        elif sensitivity > user_clearance:
            violations.append(Violation(
                type="SENSITIVITY_EXCEEDED",
                table=col_table,
                column=col_name,
                description=(
                    f"Column '{col_name}' sensitivity={sensitivity} "
                    f"exceeds user clearance={user_clearance}"
                ),
                severity="CRITICAL",
            ))

    # -- Aggregate on PII detection --------------------------------------------
    agg_columns: list[tuple[str, str]] = parsed_sql.get("aggregate_columns", [])
    for func_name, col_name in agg_columns:
        col_lower = col_name.lower()
        sensitivity = _get_col_sensitivity(col_lower, "", cache)
        if sensitivity >= 4:
            violations.append(Violation(
                type="AGGREGATE_ON_PII",
                column=col_name,
                description=(
                    f"Aggregate function {func_name.upper()}() on PII column "
                    f"'{col_name}' (sensitivity={sensitivity})"
                ),
                severity="HIGH",
            ))

    # -- Determine pass / fail -------------------------------------------------
    critical = [v for v in violations if v.severity == "CRITICAL"]
    passed = len(critical) == 0

    latency_ms = (time.monotonic() - start) * 1000
    logger.debug(
        "Gate 2 (classification) complete: passed=%s violations=%d latency=%.2fms",
        passed, len(violations), latency_ms,
    )

    return GateResult(
        passed=passed,
        violations=violations,
        latency_ms=latency_ms,
    )
