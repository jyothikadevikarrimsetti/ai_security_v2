"""Context Minimizer -- reduce schema context before sending to LLM.

Applies the minimum data exposure principle by keeping only the most
relevant tables in the schema sent to the NL-to-SQL model. Reduces
token usage, minimizes information leakage, and improves model focus.

Behaviour:
  - Keeps only top N most relevant tables (default 8).
  - Filters join graph to only include edges between kept tables.
  - Respects minimum relevance threshold (default 0.2).
  - Preserves table ordering by relevance score.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ContextMinimizer:
    """Reduces filtered schema to the minimum necessary for LLM context.

    Operates on the schema dict produced by upstream filtering (RBAC /
    policy resolution). Keeps the top-N most relevant tables and prunes
    the join graph to only include edges between retained tables.

    Usage:
        minimizer = ContextMinimizer(min_relevance=0.2)
        minimal = minimizer.minimize(filtered_schema, max_tables=8)
    """

    def __init__(self, min_relevance: float = 0.2) -> None:
        """
        Args:
            min_relevance: Minimum relevance_score for a table to be
                           considered. Tables below this threshold are
                           dropped even if max_tables is not reached.
        """
        self._min_relevance = min_relevance

    def minimize(
        self,
        filtered_schema: dict[str, Any],
        max_tables: int = 8,
    ) -> dict[str, Any]:
        """Reduce schema to the top-N most relevant tables.

        Args:
            filtered_schema: Schema dict with "tables" and "join_graph" keys.
                Each table should have a "relevance_score" field (0.0-1.0).
                Tables without a score default to 0.5.
            max_tables: Maximum number of tables to retain.

        Returns:
            Minimized schema dict with pruned tables and join graph.
        """
        tables: list[dict[str, Any]] = filtered_schema.get("tables", [])
        if not tables:
            return filtered_schema

        original_count = len(tables)

        # Step 1: Filter by minimum relevance threshold
        kept = [
            t for t in tables
            if t.get("relevance_score", 0.5) >= self._min_relevance
        ]

        # Step 2: Sort by relevance (descending) and keep top N
        kept.sort(
            key=lambda t: t.get("relevance_score", 0.0),
            reverse=True,
        )

        removed_count = 0
        if len(kept) > max_tables:
            removed_count = len(kept) - max_tables
            kept = kept[:max_tables]

        # Step 3: Build set of retained table identifiers for join pruning
        kept_ids: set[str] = set()
        for t in kept:
            tid = t.get("table_id", "").lower()
            tname = t.get("table_name", "").lower()
            if tid:
                kept_ids.add(tid)
            if tname:
                kept_ids.add(tname)

        # Step 4: Prune join graph to only include edges between kept tables
        join_graph = filtered_schema.get("join_graph", [])
        if isinstance(join_graph, list):
            filtered_joins = [
                j for j in join_graph
                if (
                    j.get("from_table", "").lower() in kept_ids
                    and j.get("to_table", "").lower() in kept_ids
                )
            ]
        else:
            # Preserve non-list join_graph formats
            filtered_joins = join_graph

        if removed_count > 0 or len(kept) < original_count:
            logger.info(
                "context_minimized",
                original_tables=original_count,
                kept_tables=len(kept),
                removed_low_relevance=original_count - len(kept),
                removed_over_limit=removed_count,
                join_edges_before=len(join_graph) if isinstance(join_graph, list) else "N/A",
                join_edges_after=len(filtered_joins) if isinstance(filtered_joins, list) else "N/A",
            )

        # Build result preserving any extra keys from the original schema
        result = dict(filtered_schema)
        result["tables"] = kept
        result["join_graph"] = filtered_joins
        return result
