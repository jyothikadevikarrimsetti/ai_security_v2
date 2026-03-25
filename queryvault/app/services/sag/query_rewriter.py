"""SAG-004 -- Query Rewriter.

Transparent masking and limit rewriting applied AFTER the three gates
pass (or pass with HIGH-severity-only violations that require
transformation rather than blocking).

Transformations:
  1. Row-level WHERE filter injection (facility_id, department_id, etc.)
  2. Column masking SQL expressions per policy:
       - PARTIAL  : LEFT(name, 1) || '***'
       - YEAR_ONLY: EXTRACT(YEAR FROM dob)
       - HASH     : SHA256(ssn)
  3. Auto-inject LIMIT per policy (max_rows).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

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
# Result data class
# ---------------------------------------------------------------------------

@dataclass
class RewrittenSQL:
    """Result of the query rewrite phase."""

    original_sql: str = ""
    rewritten_sql: str = ""
    transformations_applied: list[str] = field(default_factory=list)
    row_filters_injected: list[str] = field(default_factory=list)
    columns_masked: list[str] = field(default_factory=list)
    limit_applied: int | None = None
    was_modified: bool = False


# ---------------------------------------------------------------------------
# Masking expression templates
# ---------------------------------------------------------------------------

_MASKING_TEMPLATES: dict[str, str] = {
    "PARTIAL": "LEFT({col}, 1) || '***'",
    "YEAR_ONLY": "EXTRACT(YEAR FROM {col})",
    "HASH": "SHA256(CAST({col} AS TEXT))",
    "REDACT": "'[REDACTED]'",
    "FIRST_INITIAL": "LEFT({col}, 1) || '.'",
}


def _get_masking_expression(col_name: str, masking_type: str) -> str:
    """Build the masking SQL expression for a given column and type."""
    template = _MASKING_TEMPLATES.get(masking_type.upper())
    if not template:
        # Default to REDACT if unknown type
        template = _MASKING_TEMPLATES["REDACT"]
    return template.format(col=col_name)


def _get_table_permission(envelope: PermissionEnvelope, table_id: str):
    for tp in envelope.table_permissions:
        if tp.table_id == table_id:
            return tp
    return None


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


# ---------------------------------------------------------------------------
# QueryRewriter class
# ---------------------------------------------------------------------------

class QueryRewriter:
    """Applies transparent SQL transformations required by policy."""

    def rewrite(
        self,
        sql: str,
        permission_envelope: PermissionEnvelope,
        security_context: SecurityContext,
    ) -> RewrittenSQL:
        """Rewrite SQL to enforce masking, row filters, and limits.

        Parameters
        ----------
        sql : str
            The validated SQL string (gates have passed).
        permission_envelope : PermissionEnvelope
            The L4 authorisation envelope.
        security_context : SecurityContext
            The authenticated user's security context.

        Returns
        -------
        RewrittenSQL
        """
        result = RewrittenSQL(original_sql=sql, rewritten_sql=sql)

        # -- 1. Inject row-level WHERE filters ---------------------------------
        result = self._inject_row_filters(result, permission_envelope, security_context)

        # -- 2. Apply column masking -------------------------------------------
        result = self._apply_column_masking(result, permission_envelope)

        # -- 3. Auto-inject LIMIT ----------------------------------------------
        result = self._inject_limit(result, permission_envelope)

        result.was_modified = result.rewritten_sql != sql
        return result

    # ------------------------------------------------------------------
    # Row-level filter injection
    # ------------------------------------------------------------------

    def _inject_row_filters(
        self,
        result: RewrittenSQL,
        envelope: PermissionEnvelope,
        security_context: SecurityContext,
    ) -> RewrittenSQL:
        """Inject mandatory WHERE filters (e.g., facility_id, department_id)."""
        filters_to_inject: list[str] = []

        # Global row filters from envelope
        for rf in envelope.row_filters:
            # Substitute placeholders with actual context values
            resolved = self._resolve_filter(rf, security_context)
            if resolved:
                filters_to_inject.append(resolved)

        # Per-table row filters from table permissions
        # (TablePermission doesn't have row_filters directly; envelope.row_filters
        #  covers global filters. Per-table filters would be embedded in masking_rules.)

        if not filters_to_inject:
            return result

        sql = result.rewritten_sql

        # Determine injection point
        where_match = re.search(r"\bWHERE\b", sql, re.IGNORECASE)
        if where_match:
            # Append to existing WHERE with AND
            inject_point = where_match.end()
            filter_clause = " " + " AND ".join(filters_to_inject) + " AND"
            sql = sql[:inject_point] + filter_clause + sql[inject_point:]
        else:
            # Insert WHERE before GROUP BY / ORDER BY / LIMIT / end
            insert_re = re.search(
                r"\b(GROUP\s+BY|ORDER\s+BY|LIMIT|HAVING|OFFSET|FETCH|$)",
                sql,
                re.IGNORECASE,
            )
            insert_pos = insert_re.start() if insert_re else len(sql)
            filter_clause = " WHERE " + " AND ".join(filters_to_inject) + " "
            sql = sql[:insert_pos].rstrip() + filter_clause + sql[insert_pos:]

        result.rewritten_sql = sql
        result.row_filters_injected = filters_to_inject
        result.transformations_applied.append("ROW_FILTER_INJECTION")

        logger.debug("Injected %d row filter(s)", len(filters_to_inject))
        return result

    def _resolve_filter(
        self,
        filter_template: str,
        security_context: SecurityContext,
    ) -> str | None:
        """Resolve a filter template by substituting context values.

        Supports placeholders like {facility_id}, {department}, {employee_id}.
        """
        resolved = filter_template

        replacements = {
            "{facility_id}": ", ".join(
                f"'{fid}'" for fid in security_context.org_context.facility_ids
            ) if security_context.org_context.facility_ids else None,
            "{department}": f"'{security_context.org_context.department}'"
                if security_context.org_context.department else None,
            "{department_id}": f"'{security_context.org_context.department}'"
                if security_context.org_context.department else None,
            "{employee_id}": f"'{security_context.org_context.employee_id}'"
                if security_context.org_context.employee_id else None,
            "{provider_npi}": f"'{security_context.org_context.provider_npi}'"
                if security_context.org_context.provider_npi else None,
        }

        for placeholder, value in replacements.items():
            if placeholder in resolved:
                if value is None:
                    # Cannot resolve -- skip this filter
                    logger.warning(
                        "Cannot resolve filter placeholder %s", placeholder
                    )
                    return None
                resolved = resolved.replace(placeholder, value)

        return resolved

    # ------------------------------------------------------------------
    # Column masking
    # ------------------------------------------------------------------

    def _apply_column_masking(
        self,
        result: RewrittenSQL,
        envelope: PermissionEnvelope,
    ) -> RewrittenSQL:
        """Replace masked columns in SELECT with their masking expressions."""
        allowed_map = _build_allowed_map(envelope)
        sql = result.rewritten_sql
        masked_applied: list[str] = []

        for tp in envelope.table_permissions:
            if tp.decision == PolicyDecision.DENY:
                continue

            table_name = tp.table_id.split(".")[-1]

            for col_def in tp.columns:
                col_name = col_def.get("column_name", col_def.get("name", ""))
                visibility = col_def.get("visibility", "VISIBLE").upper()
                masking_type = col_def.get("masking", col_def.get("masking_type", ""))

                if visibility != "MASKED" or not masking_type:
                    continue

                # Build the masking expression
                mask_expr = _get_masking_expression(col_name, masking_type)
                alias = f"{mask_expr} AS {col_name}"

                # Replace bare column references in SELECT
                # Pattern: match the column name as a standalone identifier in SELECT
                # (between SELECT and FROM)
                select_pattern = re.compile(
                    r"(?<=\bSELECT\b)(.*?)(?=\bFROM\b)",
                    re.IGNORECASE | re.DOTALL,
                )
                select_match = select_pattern.search(sql)
                if select_match:
                    select_clause = select_match.group(0)
                    # Replace standalone column name (word boundary)
                    col_pattern = re.compile(
                        rf"\b{re.escape(col_name)}\b"
                        rf"(?!\s*\.\s*\w)",  # Avoid table.column prefix matches
                        re.IGNORECASE,
                    )
                    if col_pattern.search(select_clause):
                        new_select = col_pattern.sub(alias, select_clause, count=1)
                        sql = sql[:select_match.start()] + new_select + sql[select_match.end():]
                        masked_applied.append(f"{col_name} -> {masking_type}")

        if masked_applied:
            result.rewritten_sql = sql
            result.columns_masked = masked_applied
            result.transformations_applied.append("COLUMN_MASKING")
            logger.debug("Masked %d column(s)", len(masked_applied))

        return result

    # ------------------------------------------------------------------
    # Limit injection
    # ------------------------------------------------------------------

    def _inject_limit(
        self,
        result: RewrittenSQL,
        envelope: PermissionEnvelope,
    ) -> RewrittenSQL:
        """Auto-inject LIMIT if the policy defines max_rows."""
        # Find the minimum max_rows across all referenced tables
        min_limit: int | None = None
        for tp in envelope.table_permissions:
            if tp.decision == PolicyDecision.DENY:
                continue
            if tp.max_rows is not None:
                if min_limit is None or tp.max_rows < min_limit:
                    min_limit = tp.max_rows

        if min_limit is None:
            return result

        sql = result.rewritten_sql

        # Check if LIMIT already exists
        limit_match = re.search(r"\bLIMIT\s+(\d+)", sql, re.IGNORECASE)
        if limit_match:
            existing_limit = int(limit_match.group(1))
            if existing_limit > min_limit:
                # Replace with the stricter policy limit
                sql = sql[:limit_match.start()] + f"LIMIT {min_limit}" + sql[limit_match.end():]
                result.rewritten_sql = sql
                result.limit_applied = min_limit
                result.transformations_applied.append("LIMIT_OVERRIDE")
        else:
            # Append LIMIT
            sql = sql.rstrip().rstrip(";") + f" LIMIT {min_limit}"
            result.rewritten_sql = sql
            result.limit_applied = min_limit
            result.transformations_applied.append("LIMIT_INJECTION")

        logger.debug("Applied LIMIT %d", min_limit)
        return result
