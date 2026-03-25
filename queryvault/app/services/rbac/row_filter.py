"""Row Filter -- Zero Trust Control ZT-005.

Generates mandatory WHERE-clause injection rules based on the user's
role and organisational context.  Filters are enforced at two levels:

  1. Prompt level -- NL rules instruct the LLM to include the filters.
  2. Validation level -- Gate 1 in L6 verifies the generated SQL
     actually contains the required predicates.

Security invariants:
  - Row filters are additive (AND semantics) -- they can only narrow
    access, never broaden it.
  - Value sources reference SecurityContext fields; actual values are
    injected at resolution time.
  - Missing context values produce NULL, which causes no rows to match
    (fail closed).
"""

from __future__ import annotations

from typing import Any, Optional

import structlog
from pydantic import BaseModel, Field

from queryvault.app.models.enums import ColumnVisibility, PolicyDecision
from queryvault.app.models.security_context import SecurityContext

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class RowFilterRule(BaseModel):
    """A single mandatory row-level filter."""

    column: str = Field(
        ...,
        description="Column name in the target table to filter on.",
    )
    operator: str = Field(
        default="=",
        description="SQL operator (=, IN, >=, etc.).",
    )
    value_source: str = Field(
        ...,
        description=(
            "Dotted path into SecurityContext for the filter value. "
            "e.g. 'security_context.org_context.facility_ids'."
        ),
    )
    description: str = Field(
        default="",
        description="Human-readable explanation for audit logs.",
    )

    def resolve_value(self, security_context: SecurityContext) -> str | None:
        """Resolve the value_source against a live SecurityContext.

        Returns the SQL-safe literal or None if the path is missing.
        """
        val = _resolve_path(self.value_source, security_context)
        if val is None:
            return None
        return _to_sql_literal(val)

    def to_sql_predicate(self, security_context: SecurityContext) -> str:
        """Produce the full SQL predicate (e.g. ``facility_id IN ('F1','F2')``).

        Returns a NULL-safe predicate when the context value is missing,
        which ensures no rows match (fail closed).
        """
        resolved = self.resolve_value(security_context)
        if resolved is None:
            return f"{self.column} IS NULL AND FALSE"  # fail closed
        return f"{self.column} {self.operator} {resolved}"

    def to_nl_rule(self, table_name: str, security_context: SecurityContext) -> str:
        """Generate an NL rule string for LLM prompt injection."""
        predicate = self.to_sql_predicate(security_context)
        return (
            f"MANDATORY: When querying '{table_name}', you MUST include "
            f"this filter in the WHERE clause: {predicate}"
        )


# ---------------------------------------------------------------------------
# Role-based filter definitions
# ---------------------------------------------------------------------------
# In production these would be loaded from Neo4j or a policy store.
# Each entry maps a role (lowercased) to a list of (table_pattern, rules)
# tuples.  table_pattern supports:
#   - "*" matches any table
#   - "schema.table" exact match
#   - "schema.*" matches all tables in a schema

_ROLE_FILTER_RULES: dict[str, list[tuple[str, list[RowFilterRule]]]] = {
    "attending_physician": [
        (
            "*",
            [
                RowFilterRule(
                    column="provider_id",
                    operator="=",
                    value_source="security_context.org_context.provider_npi",
                    description="Physicians see only their own patients",
                ),
            ],
        ),
    ],
    "resident": [
        (
            "*",
            [
                RowFilterRule(
                    column="provider_id",
                    operator="=",
                    value_source="security_context.org_context.provider_npi",
                    description="Residents see only their assigned patients",
                ),
                RowFilterRule(
                    column="department_id",
                    operator="=",
                    value_source="security_context.org_context.department",
                    description="Residents scoped to their department",
                ),
            ],
        ),
    ],
    "nurse": [
        (
            "*",
            [
                RowFilterRule(
                    column="unit_id",
                    operator="IN",
                    value_source="security_context.org_context.unit_ids",
                    description="Nurses see only patients in their units",
                ),
                RowFilterRule(
                    column="facility_id",
                    operator="IN",
                    value_source="security_context.org_context.facility_ids",
                    description="Nurses scoped to their facilities",
                ),
            ],
        ),
    ],
    "nurse_practitioner": [
        (
            "*",
            [
                RowFilterRule(
                    column="facility_id",
                    operator="IN",
                    value_source="security_context.org_context.facility_ids",
                    description="Nurse practitioners scoped to their facilities",
                ),
            ],
        ),
    ],
    "billing_specialist": [
        (
            "*",
            [
                RowFilterRule(
                    column="facility_id",
                    operator="IN",
                    value_source="security_context.org_context.facility_ids",
                    description="Billing staff scoped to their facilities",
                ),
                RowFilterRule(
                    column="department_id",
                    operator="=",
                    value_source="security_context.org_context.department",
                    description="Billing staff scoped to their department",
                ),
            ],
        ),
    ],
    "department_head": [
        (
            "*",
            [
                RowFilterRule(
                    column="department_id",
                    operator="=",
                    value_source="security_context.org_context.department",
                    description="Department heads see only their department",
                ),
            ],
        ),
    ],
    "hr_analyst": [
        (
            "*",
            [
                RowFilterRule(
                    column="facility_id",
                    operator="IN",
                    value_source="security_context.org_context.facility_ids",
                    description="HR analysts scoped to their facilities",
                ),
            ],
        ),
    ],
    "researcher": [
        (
            "*",
            [
                RowFilterRule(
                    column="facility_id",
                    operator="IN",
                    value_source="security_context.org_context.facility_ids",
                    description="Researchers scoped to their facilities",
                ),
            ],
        ),
    ],
}


# ---------------------------------------------------------------------------
# RowFilter
# ---------------------------------------------------------------------------


class RowFilter:
    """Generates mandatory WHERE injection rules based on user role and context.

    Usage::

        rf = RowFilter()
        rules = await rf.get_filters(security_context, table="ehr.encounters")
        for rule in rules:
            predicate = rule.to_sql_predicate(security_context)
            nl_rule = rule.to_nl_rule("ehr.encounters", security_context)
    """

    def __init__(
        self,
        role_filter_rules: dict[str, list[tuple[str, list[RowFilterRule]]]] | None = None,
    ) -> None:
        """Initialise with optional custom role-filter mapping."""
        self._rules = (
            role_filter_rules
            if role_filter_rules is not None
            else _ROLE_FILTER_RULES
        )

    async def get_filters(
        self,
        security_context: SecurityContext,
        table: str,
    ) -> list[RowFilterRule]:
        """Return all mandatory row filters for the given table and user.

        Filters are accumulated across all of the user's effective roles
        (union of rules, AND semantics when applied).

        Args:
            security_context: Authenticated user's security context.
            table: Fully-qualified table identifier.

        Returns:
            De-duplicated list of RowFilterRule instances.
        """
        collected: dict[str, RowFilterRule] = {}  # keyed by column to dedup

        for role in security_context.authorization.effective_roles:
            role_lower = role.lower().strip()
            role_rules = self._rules.get(role_lower, [])

            for pattern, rules in role_rules:
                if self._table_matches_pattern(table, pattern):
                    for rule in rules:
                        # Use column as dedup key; first match wins
                        # (most-restrictive role's filter takes precedence
                        #  because roles are processed in order)
                        if rule.column not in collected:
                            collected[rule.column] = rule

        result = list(collected.values())

        logger.info(
            "row_filters_resolved",
            table=table,
            user=security_context.identity.oid,
            filter_count=len(result),
            columns=[r.column for r in result],
        )

        return result

    async def get_sql_predicates(
        self,
        security_context: SecurityContext,
        table: str,
    ) -> list[str]:
        """Convenience: return resolved SQL predicates ready for injection.

        Combines ``get_filters`` with ``RowFilterRule.to_sql_predicate``.
        """
        rules = await self.get_filters(security_context, table)
        return [r.to_sql_predicate(security_context) for r in rules]

    async def get_nl_rules(
        self,
        security_context: SecurityContext,
        table: str,
    ) -> list[str]:
        """Convenience: return NL rules for LLM prompt injection."""
        rules = await self.get_filters(security_context, table)
        return [r.to_nl_rule(table, security_context) for r in rules]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _table_matches_pattern(table: str, pattern: str) -> bool:
        """Check if a table identifier matches a filter pattern.

        Patterns:
          ``*``            -- matches any table
          ``schema.*``     -- matches all tables in the schema
          ``schema.table`` -- exact match
        """
        if pattern == "*":
            return True

        table_lower = table.lower()
        pattern_lower = pattern.lower()

        if pattern_lower.endswith(".*"):
            schema_prefix = pattern_lower[:-1]  # "schema."
            return table_lower.startswith(schema_prefix)

        return table_lower == pattern_lower


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _resolve_path(path: str, ctx: SecurityContext) -> Any:
    """Walk a dotted path against a SecurityContext.

    Supports paths like ``security_context.org_context.facility_ids``.
    The leading ``security_context.`` prefix is stripped since we already
    have the SecurityContext object.
    """
    clean = path
    if clean.startswith("security_context."):
        clean = clean[len("security_context."):]

    parts = clean.split(".")
    val: Any = ctx
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        else:
            val = getattr(val, part, None)
        if val is None:
            return None
    return val


def _to_sql_literal(val: Any) -> str:
    """Convert a Python value to a SQL-safe literal string."""
    if isinstance(val, list):
        if not val:
            return "(NULL)"
        items = ", ".join(f"'{str(v).replace(chr(39), chr(39)+chr(39))}'" for v in val)
        return f"({items})"
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"
    if isinstance(val, (int, float)):
        return str(val)
    safe = str(val).replace("'", "''")
    return f"'{safe}'"
