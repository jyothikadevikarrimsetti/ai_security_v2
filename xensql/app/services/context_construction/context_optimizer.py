"""CC-004 Context Optimizer — improve schema context quality before prompt assembly.

Responsibilities:
  - Reorder tables by relevance to the question / detected intent
  - Deduplicate contextual rules
  - Add explicit join path hints for multi-table queries
  - Inject sample values to reduce LLM hallucination
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from xensql.app.models.enums import IntentType
from xensql.app.models.schema import SchemaContext, TableInfo

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class OptimizedContext:
    """Result of context optimisation — enriched schema ready for prompt assembly."""

    tables: list[dict[str, Any]]
    join_hints: list[str]
    deduplicated_rules: list[str]
    sample_value_hints: list[str]
    tables_reordered: bool = False
    optimization_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ContextOptimizer
# ---------------------------------------------------------------------------


class ContextOptimizer:
    """Optimise the schema context before it is fed to the PromptAssembler.

    Usage::

        optimizer = ContextOptimizer()
        result = optimizer.optimize(
            schema_context=schema_ctx,
            intent=IntentType.AGGREGATION,
            question="Total revenue per department",
        )
        # result.tables → reordered list of table dicts
        # result.join_hints → ["JOIN encounters ON ..."]
        # result.deduplicated_rules → unique rules
    """

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def optimize(
        self,
        schema_context: SchemaContext,
        intent: IntentType | None,
        question: str,
        contextual_rules: list[str] | None = None,
    ) -> OptimizedContext:
        """Optimise the schema context for prompt quality.

        Parameters
        ----------
        schema_context:
            The SchemaContext built from the filtered_schema received from
            QueryVault.
        intent:
            The classified intent of the user's question.
        question:
            The raw natural-language question.
        contextual_rules:
            Rules received from QueryVault (will be deduplicated).

        Returns
        -------
        OptimizedContext
        """
        rules = contextual_rules or []
        notes: list[str] = []

        # 1. Deduplicate rules
        deduped_rules = self._deduplicate_rules(rules)
        if len(deduped_rules) < len(rules):
            notes.append(
                f"Deduplicated rules: {len(rules)} -> {len(deduped_rules)}"
            )

        # 2. Reorder tables by relevance
        reordered_tables, was_reordered = self._reorder_tables(
            schema_context.tables, question, intent
        )
        if was_reordered:
            notes.append("Tables reordered by relevance score")

        # 3. Build join path hints
        join_hints = self._build_join_hints(schema_context)

        # 4. Generate sample value hints
        sample_hints = self._build_sample_value_hints(
            reordered_tables, question
        )

        # Convert TableInfo objects to dicts for downstream consumption
        table_dicts = [self._table_to_dict(t) for t in reordered_tables]

        return OptimizedContext(
            tables=table_dicts,
            join_hints=join_hints,
            deduplicated_rules=deduped_rules,
            sample_value_hints=sample_hints,
            tables_reordered=was_reordered,
            optimization_notes=notes,
        )

    # ------------------------------------------------------------------ #
    # Rule deduplication
    # ------------------------------------------------------------------ #

    @staticmethod
    def _deduplicate_rules(rules: list[str]) -> list[str]:
        """Remove duplicate rules while preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for rule in rules:
            normalised = rule.strip().lower()
            if normalised not in seen:
                seen.add(normalised)
                result.append(rule.strip())
        return result

    # ------------------------------------------------------------------ #
    # Table reordering
    # ------------------------------------------------------------------ #

    def _reorder_tables(
        self,
        tables: list[TableInfo],
        question: str,
        intent: IntentType | None,
    ) -> tuple[list[TableInfo], bool]:
        """Reorder tables by relevance to the question.

        Scoring factors:
        - Table name or description word overlap with question
        - Column name overlap with question
        - FK connectivity (tables with more FK relations score higher for
          JOIN_QUERY intent)

        Returns (reordered_tables, was_reordered).
        """
        if len(tables) <= 1:
            return tables, False

        question_tokens = set(self._tokenise_text(question))

        scored: list[tuple[float, int, TableInfo]] = []
        for idx, table in enumerate(tables):
            score = self._relevance_score(table, question_tokens, intent)
            # Use negative idx as tiebreaker to preserve original order
            scored.append((score, -idx, table))

        scored.sort(key=lambda x: x[0], reverse=True)
        reordered = [t for _, _, t in scored]

        # Check if order actually changed
        original_names = [t.table_name for t in tables]
        new_names = [t.table_name for t in reordered]
        was_reordered = original_names != new_names

        return reordered, was_reordered

    def _relevance_score(
        self,
        table: TableInfo,
        question_tokens: set[str],
        intent: IntentType | None,
    ) -> float:
        """Compute a relevance score for a table against the question."""
        score = 0.0

        # Table name overlap
        table_tokens = set(self._tokenise_text(table.table_name))
        name_overlap = len(table_tokens & question_tokens)
        score += name_overlap * 3.0

        # Description overlap
        if table.description:
            desc_tokens = set(self._tokenise_text(table.description))
            desc_overlap = len(desc_tokens & question_tokens)
            score += desc_overlap * 1.0

        # Column name overlap
        for col in table.columns:
            col_tokens = set(self._tokenise_text(col.column_name))
            col_overlap = len(col_tokens & question_tokens)
            score += col_overlap * 2.0

        # FK connectivity bonus for JOIN queries
        if intent == IntentType.JOIN_QUERY:
            fk_count = sum(1 for c in table.columns if c.is_fk)
            score += fk_count * 1.5

        # PK presence bonus (usually dimension tables)
        pk_count = sum(1 for c in table.columns if c.is_pk)
        score += pk_count * 0.5

        return score

    # ------------------------------------------------------------------ #
    # Join path hints
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_join_hints(schema_context: SchemaContext) -> list[str]:
        """Build explicit join path hints from foreign key relationships.

        These are injected into the prompt so the LLM does not have to
        guess join conditions.
        """
        hints: list[str] = []
        for fk in schema_context.join_paths:
            hint = (
                f"JOIN {fk.to_table} ON "
                f"{fk.from_table}.{fk.from_column} = "
                f"{fk.to_table}.{fk.to_column}"
            )
            hints.append(hint)
        return hints

    # ------------------------------------------------------------------ #
    # Sample value hints
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_sample_value_hints(
        tables: list[TableInfo],
        question: str,
    ) -> list[str]:
        """Generate sample value hints for enum-like columns.

        When the question references a value (e.g. "Cardiology"), and a
        column description contains that value, we add a hint so the LLM
        knows what values to use.
        """
        hints: list[str] = []
        question_lower = question.lower()

        for table in tables:
            for col in table.columns:
                if not col.description:
                    continue
                # Look for enumerated values in descriptions like
                # "Values: inpatient, outpatient, emergency"
                desc_lower = col.description.lower()
                if "values:" in desc_lower or "enum:" in desc_lower:
                    # Check if the question references this column's domain
                    col_name_parts = col.column_name.lower().replace("_", " ")
                    if any(
                        part in question_lower
                        for part in col_name_parts.split()
                        if len(part) > 2
                    ):
                        hints.append(
                            f"Column {table.table_name}.{col.column_name}: "
                            f"{col.description}"
                        )

        return hints

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    @staticmethod
    def _tokenise_text(text: str) -> list[str]:
        """Split text into lowercase tokens, splitting on non-alphanumeric."""
        return [t for t in re.split(r"[^a-zA-Z0-9]+", text.lower()) if t]

    @staticmethod
    def _table_to_dict(table: TableInfo) -> dict[str, Any]:
        """Convert a TableInfo model to a plain dict for the assembler."""
        return {
            "table_id": table.table_id,
            "database_name": table.database_name,
            "schema_name": table.schema_name,
            "table_name": table.table_name,
            "description": table.description,
            "columns": [
                {
                    "column_name": c.column_name,
                    "data_type": c.data_type,
                    "description": c.description,
                    "is_pk": c.is_pk,
                    "is_fk": c.is_fk,
                    "fk_ref": c.fk_ref,
                }
                for c in table.columns
            ],
        }
