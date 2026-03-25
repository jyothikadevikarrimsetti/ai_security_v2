"""Column Scoper -- Zero Trust Control ZT-004.

Per table x role: assigns column visibility as VISIBLE, MASKED, HIDDEN,
or COMPUTED.

Security invariants:
  - PII columns default to HIDDEN unless explicitly allowed by policy.
  - HIDDEN columns are omitted entirely from LLM-visible output.
  - MASKED columns include SQL expression hints (e.g. LEFT(name,1)||'***').
  - COMPUTED columns carry a replacement expression.
  - DDL-like output is generated for LLM context showing only
    visible/masked columns.
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


class ColumnPolicy(BaseModel):
    """A single column-level policy decision from the permission envelope."""

    column_name: str
    visibility: ColumnVisibility = ColumnVisibility.HIDDEN
    masking_expression: Optional[str] = None
    computed_expression: Optional[str] = None
    reason: str = ""


class ColumnInfo(BaseModel):
    """Raw column metadata from the schema catalogue."""

    name: str
    data_type: str = "TEXT"
    is_pii: bool = False
    is_pk: bool = False
    description: str = ""


class ScopedColumn(BaseModel):
    """A column after visibility scoping has been applied."""

    name: str
    data_type: str = "TEXT"
    visibility: ColumnVisibility = ColumnVisibility.VISIBLE
    is_pk: bool = False
    description: str = ""
    masking_expression: Optional[str] = None
    computed_expression: Optional[str] = None


class ScopedColumns(BaseModel):
    """Result of scoping a single table's columns."""

    table_id: str
    table_name: str = ""
    visible: list[ScopedColumn] = Field(default_factory=list)
    masked: list[ScopedColumn] = Field(default_factory=list)
    hidden_count: int = 0
    ddl_fragment: str = ""
    row_filters: list[str] = Field(default_factory=list)
    aggregation_only: bool = False
    max_rows: Optional[int] = None


# ---------------------------------------------------------------------------
# ColumnScoper
# ---------------------------------------------------------------------------


class ColumnScoper:
    """Scopes column visibility per table x role and generates DDL fragments.

    Usage::

        scoper = ColumnScoper()
        result = await scoper.scope(
            table="ehr.patients",
            columns=[ColumnInfo(name="mrn", data_type="VARCHAR", is_pii=True), ...],
            policies=[ColumnPolicy(column_name="mrn", visibility=ColumnVisibility.MASKED, ...)],
            clearance=3,
        )
    """

    async def scope(
        self,
        table: str,
        columns: list[ColumnInfo],
        policies: list[ColumnPolicy],
        clearance: int,
        *,
        row_filters: list[str] | None = None,
        aggregation_only: bool = False,
        max_rows: int | None = None,
    ) -> ScopedColumns:
        """Scope columns for a single table and produce a DDL fragment.

        Args:
            table: Fully-qualified table identifier.
            columns: Raw column metadata from the catalogue.
            policies: Column-level policy decisions from the permission envelope.
            clearance: User's effective clearance level (1-5).
            row_filters: Optional pre-aggregated row filters for DDL comments.
            aggregation_only: Whether only aggregate queries are allowed.
            max_rows: Maximum rows the user may retrieve.

        Returns:
            ScopedColumns with classified columns and a DDL fragment.
        """
        # Build a lookup from column name (lowercased) to policy
        policy_map: dict[str, ColumnPolicy] = {
            p.column_name.lower(): p for p in policies
        }

        visible: list[ScopedColumn] = []
        masked: list[ScopedColumn] = []
        hidden_count = 0

        for col in columns:
            col_lower = col.name.lower()
            policy = policy_map.get(col_lower)

            # Determine visibility
            if policy:
                vis = policy.visibility
            else:
                # Default: PII is HIDDEN unless explicitly allowed
                vis = ColumnVisibility.HIDDEN if col.is_pii else ColumnVisibility.VISIBLE

            scoped = ScopedColumn(
                name=col.name,
                data_type=col.data_type,
                visibility=vis,
                is_pk=col.is_pk,
                # Strip description for hidden columns (no metadata leakage)
                description=col.description if vis != ColumnVisibility.HIDDEN else "",
            )

            if vis == ColumnVisibility.VISIBLE:
                visible.append(scoped)

            elif vis == ColumnVisibility.MASKED:
                scoped.masking_expression = (
                    policy.masking_expression
                    if policy and policy.masking_expression
                    else self._default_masking_expression(col.name)
                )
                masked.append(scoped)

            elif vis == ColumnVisibility.COMPUTED:
                scoped.computed_expression = (
                    policy.computed_expression if policy else None
                )
                # Computed columns appear in the visible set with their expression
                visible.append(scoped)

            elif vis == ColumnVisibility.HIDDEN:
                hidden_count += 1
                # Column name is never disclosed

        table_name = table.split(".")[-1] if "." in table else table

        # Build DDL fragment
        ddl = self._build_ddl(
            table_name=table_name,
            table_fqn=table,
            visible=visible,
            masked=masked,
            row_filters=row_filters or [],
            aggregation_only=aggregation_only,
            max_rows=max_rows,
        )

        result = ScopedColumns(
            table_id=table,
            table_name=table_name,
            visible=visible,
            masked=masked,
            hidden_count=hidden_count,
            ddl_fragment=ddl,
            row_filters=row_filters or [],
            aggregation_only=aggregation_only,
            max_rows=max_rows,
        )

        logger.info(
            "column_scoping_complete",
            table=table,
            visible=len(visible),
            masked=len(masked),
            hidden=hidden_count,
            clearance=clearance,
        )

        return result

    # ------------------------------------------------------------------
    # DDL generation
    # ------------------------------------------------------------------

    def _build_ddl(
        self,
        table_name: str,
        table_fqn: str,
        visible: list[ScopedColumn],
        masked: list[ScopedColumn],
        row_filters: list[str],
        aggregation_only: bool,
        max_rows: int | None,
    ) -> str:
        """Build a DDL-style fragment optimised for LLM consumption.

        Only visible and masked columns appear.  Hidden columns are
        excluded entirely -- their names are never disclosed.
        """
        lines: list[str] = [f"-- Table: {table_fqn}"]

        if aggregation_only:
            lines.append("-- NOTE: AGGREGATION ONLY -- no row-level SELECT allowed")

        if max_rows:
            lines.append(f"-- NOTE: LIMIT {max_rows} rows maximum")

        for rf in row_filters:
            lines.append(f"-- REQUIRED FILTER: {rf}")

        lines.append(f"CREATE TABLE {table_name} (")

        col_lines: list[str] = []

        for col in visible:
            parts = [f"  {col.name}", col.data_type or "TEXT"]
            if col.is_pk:
                parts.append("PRIMARY KEY")
            if col.visibility == ColumnVisibility.COMPUTED and col.computed_expression:
                parts.append(f"-- COMPUTED: {col.computed_expression}")
            if col.description:
                parts.append(f"-- {col.description[:80]}")
            col_lines.append(" ".join(parts))

        for col in masked:
            expr = col.masking_expression or f"MASKED({col.name})"
            parts = [f"  {col.name}", col.data_type or "TEXT", f"-- MASKED: use {expr}"]
            col_lines.append(" ".join(parts))

        lines.append(",\n".join(col_lines))
        lines.append(");")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_masking_expression(column_name: str) -> str:
        """Generate a default masking expression for a column.

        Produces a LEFT(col, 1) || '***' pattern that reveals only the
        first character.
        """
        return f"LEFT({column_name}, 1) || '***'"
