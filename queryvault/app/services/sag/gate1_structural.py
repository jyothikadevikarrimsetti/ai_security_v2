"""SAG-001 -- Gate 1: Structural Validation.

Validates every table, column, join, row filter, aggregation requirement,
and subquery depth against the Permission Envelope.  This is the primary
authorisation gate in the SQL Accuracy Guard pipeline.

All violations are collected (no short-circuit) so that the downstream
ViolationReporter can emit a complete audit record.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from queryvault.app.models.enums import GateResult as GateDecision, PolicyDecision
from queryvault.app.models.security_context import PermissionEnvelope

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local data classes
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    """A single validation violation."""

    type: str
    table: str = ""
    column: str = ""
    description: str = ""
    severity: str = "CRITICAL"  # CRITICAL | HIGH | MEDIUM | LOW


@dataclass
class GateResult:
    """Outcome of a single validation gate."""

    passed: bool
    violations: list[Violation] = field(default_factory=list)
    gate_name: str = "gate1_structural"
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SENSITIVITY5_PATTERNS = [
    "substance_abuse", "behavioral_health_substance", "42cfr",
    "psychotherapy", "hiv_status", "genetic_data",
]


def _is_sensitivity5_table(table_name: str) -> bool:
    lower = table_name.lower()
    return any(p in lower for p in _SENSITIVITY5_PATTERNS)


def _build_allowed_map(envelope: PermissionEnvelope) -> dict[str, str]:
    """Map normalised table names to their canonical table_id."""
    allowed: dict[str, str] = {}
    for tp in envelope.table_permissions:
        if tp.decision != PolicyDecision.DENY:
            name_part = tp.table_id.split(".")[-1].lower()
            allowed[name_part] = tp.table_id
            allowed[tp.table_id.lower()] = tp.table_id
            if tp.table_name:
                allowed[tp.table_name.lower()] = tp.table_id
    return allowed


def _get_table_permission(envelope: PermissionEnvelope, table_id: str):
    """Look up a TablePermission by table_id."""
    for tp in envelope.table_permissions:
        if tp.table_id == table_id:
            return tp
    return None


def _column_names_by_visibility(tp, visibility: str) -> set[str]:
    """Extract column names from a TablePermission for the given visibility."""
    names: set[str] = set()
    for col in tp.columns:
        col_name = col.get("column_name", col.get("name", "")).lower()
        col_vis = col.get("visibility", "VISIBLE").upper()
        if col_vis == visibility:
            names.add(col_name)
    return names


def _allowed_column_names(tp) -> set[str]:
    """All column names that are not HIDDEN."""
    names: set[str] = set()
    for col in tp.columns:
        col_name = col.get("column_name", col.get("name", "")).lower()
        col_vis = col.get("visibility", "VISIBLE").upper()
        if col_vis != "HIDDEN":
            names.add(col_name)
    return names


def _denied_column_names(tp) -> set[str]:
    """Column names explicitly HIDDEN."""
    return _column_names_by_visibility(tp, "HIDDEN")


def _masked_column_names(tp) -> set[str]:
    """Column names with MASKED visibility."""
    return _column_names_by_visibility(tp, "MASKED")


# ---------------------------------------------------------------------------
# Gate 1 runner
# ---------------------------------------------------------------------------

def run(
    parsed_sql: dict,
    permission_envelope: PermissionEnvelope,
    max_subquery_depth: int = 3,
) -> GateResult:
    """Execute Gate 1 structural validation.

    Parameters
    ----------
    parsed_sql : dict
        A dictionary with keys extracted from SQL parsing:
        - tables: list[str]             -- all referenced tables (FROM/JOIN)
        - columns: list[tuple[str,str]] -- (table_or_alias, column_name)
        - select_columns: list[tuple[str,str]]
        - cte_names: list[str]
        - has_group_by: bool
        - has_where: bool
        - where_conditions: list[str]
        - subquery_depth: int
        - statement_count: int
        - has_write_ops: bool
        - is_select: bool
        - parse_error: str | None
    permission_envelope : PermissionEnvelope
        The L4-produced authorisation envelope.
    max_subquery_depth : int
        Maximum allowed subquery nesting (default 3).

    Returns
    -------
    GateResult
    """
    start = time.monotonic()
    violations: list[Violation] = []

    # -- Unparseable SQL -------------------------------------------------------
    parse_error = parsed_sql.get("parse_error")
    if parse_error:
        violations.append(Violation(
            type="UNPARSEABLE_SQL",
            description=f"SQL could not be parsed: {parse_error}",
            severity="CRITICAL",
        ))
        return GateResult(
            passed=False,
            violations=violations,
            latency_ms=(time.monotonic() - start) * 1000,
        )

    # -- Write operation check -------------------------------------------------
    if parsed_sql.get("has_write_ops") or not parsed_sql.get("is_select", True):
        violations.append(Violation(
            type="WRITE_OPERATION",
            description="SQL contains write operations (INSERT/UPDATE/DELETE/DROP)",
            severity="CRITICAL",
        ))

    allowed_map = _build_allowed_map(permission_envelope)
    tables: list[str] = parsed_sql.get("tables", [])
    columns: list[tuple[str, str]] = parsed_sql.get("columns", [])
    select_columns: list[tuple[str, str]] = parsed_sql.get("select_columns", [])
    cte_names: list[str] = [c.lower() for c in parsed_sql.get("cte_names", [])]

    # -- Table authorisation ---------------------------------------------------
    for table_name in tables:
        table_lower = table_name.lower()

        # Skip CTE virtual tables
        if table_lower in cte_names:
            continue

        name_part = table_lower.split(".")[-1]
        table_id = allowed_map.get(table_lower) or allowed_map.get(name_part)

        if not table_id:
            violations.append(Violation(
                type="UNAUTHORIZED_TABLE",
                table=table_name,
                description=f"Table '{table_name}' is not in the Permission Envelope or is DENIED",
                severity="CRITICAL",
            ))
            continue

        tp = _get_table_permission(permission_envelope, table_id)
        if not tp:
            continue

        # -- Column authorisation ----------------------------------------------
        allowed_cols = _allowed_column_names(tp)
        denied_cols = _denied_column_names(tp)

        for col_table, col_name in columns:
            if col_name == "*":
                continue
            col_lower = col_name.lower()

            # Match column to this table
            if col_table and col_table.lower() not in (
                name_part, table_lower, table_id.lower()
            ):
                continue

            if col_lower in denied_cols:
                violations.append(Violation(
                    type="UNAUTHORIZED_COLUMN",
                    table=table_name,
                    column=col_name,
                    description=(
                        f"Column '{col_name}' in table '{table_name}' "
                        f"is HIDDEN/DENIED for this role"
                    ),
                    severity="CRITICAL",
                ))
            elif allowed_cols and col_lower not in allowed_cols:
                violations.append(Violation(
                    type="UNAUTHORIZED_COLUMN",
                    table=table_name,
                    column=col_name,
                    description=(
                        f"Column '{col_name}' is not in the allowed column "
                        f"set for table '{table_name}'"
                    ),
                    severity="CRITICAL",
                ))

        # -- Aggregation enforcement -------------------------------------------
        if tp.aggregation_only:
            if not parsed_sql.get("has_group_by", False):
                violations.append(Violation(
                    type="AGGREGATION_VIOLATION",
                    table=table_name,
                    description=(
                        f"Table '{table_name}' requires aggregation_only "
                        f"(GROUP BY is mandatory)"
                    ),
                    severity="CRITICAL",
                ))

            # Block PII identifiers in SELECT for aggregation-only tables
            _PII_SAFETY_NET = {
                "mrn", "full_name", "ssn", "dob", "aadhaar_number",
                "phone", "email", "address", "patient_id",
            }
            for col_table, col_name in select_columns:
                if col_name.lower() in _PII_SAFETY_NET:
                    violations.append(Violation(
                        type="AGGREGATION_VIOLATION",
                        table=table_name,
                        column=col_name,
                        description=(
                            f"Patient identifier '{col_name}' in SELECT "
                            f"with aggregation_only table '{table_name}'"
                        ),
                        severity="CRITICAL",
                    ))

        # -- Row filter enforcement --------------------------------------------
        if tp.masking_rules:
            # Check for mandatory row filters from the envelope
            pass  # Handled below at envelope level

    # -- Global row filter enforcement -----------------------------------------
    row_filters = permission_envelope.row_filters
    if row_filters:
        has_where = parsed_sql.get("has_where", False)
        where_conditions = parsed_sql.get("where_conditions", [])
        where_str = " ".join(where_conditions).lower() if where_conditions else ""

        for rf in row_filters:
            col_hint = rf.split("=")[0].strip().split(".")[-1].strip().lower()
            if not has_where or col_hint not in where_str:
                violations.append(Violation(
                    type="MISSING_REQUIRED_FILTER",
                    description=(
                        f"Required row filter '{rf}' is missing from WHERE clause. "
                        f"Query rewriter will attempt injection."
                    ),
                    severity="HIGH",
                ))

    # -- Subquery depth --------------------------------------------------------
    subquery_depth = parsed_sql.get("subquery_depth", 0)
    if subquery_depth > max_subquery_depth:
        violations.append(Violation(
            type="EXCESSIVE_SUBQUERY_DEPTH",
            description=(
                f"Subquery depth {subquery_depth} exceeds "
                f"the allowed limit of {max_subquery_depth}"
            ),
            severity="HIGH",
        ))

    # -- Stacked query detection -----------------------------------------------
    statement_count = parsed_sql.get("statement_count", 1)
    if statement_count > 1:
        violations.append(Violation(
            type="STACKED_QUERIES",
            description=f"Multiple SQL statements detected ({statement_count})",
            severity="CRITICAL",
        ))

    # -- Determine pass / fail -------------------------------------------------
    critical = [v for v in violations if v.severity == "CRITICAL"]
    passed = len(critical) == 0

    latency_ms = (time.monotonic() - start) * 1000
    logger.debug(
        "Gate 1 (structural) complete: passed=%s violations=%d latency=%.2fms",
        passed, len(violations), latency_ms,
    )

    return GateResult(
        passed=passed,
        violations=violations,
        latency_ms=latency_ms,
    )
