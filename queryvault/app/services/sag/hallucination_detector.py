"""SAG-005 -- Hallucination Detector.

Maps every SQL identifier (table names, column names) to the filtered
schema that was provided to the LLM.  Any unresolved reference is
treated as a hallucination and triggers a block.

Target: 100% catch rate for hallucinated tables and columns.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL reserved words (excluded from identifier detection)
# ---------------------------------------------------------------------------

_SQL_KEYWORDS = frozenset({
    "select", "from", "where", "group", "order", "having", "limit", "offset",
    "and", "or", "not", "in", "between", "like", "is", "null", "as",
    "join", "inner", "left", "right", "outer", "cross", "on", "using",
    "insert", "update", "delete", "set", "values", "into",
    "create", "alter", "drop", "table", "index", "view",
    "case", "when", "then", "else", "end",
    "asc", "desc", "by", "distinct", "all", "top", "with",
    "union", "except", "intersect",
    "count", "sum", "avg", "min", "max", "coalesce", "isnull",
    "cast", "convert", "trim", "upper", "lower", "substring",
    "date", "year", "month", "day", "hour", "minute", "second",
    "current_date", "current_timestamp", "now", "getdate", "sysdate",
    "date_trunc", "date_format", "date_add", "date_sub", "datediff",
    "extract", "interval", "dual", "lateral", "unnest", "generate_series",
    "exists", "any", "some", "rollup", "cube", "grouping",
    "over", "partition", "row_number", "rank", "dense_rank", "lag", "lead",
    "true", "false", "boolean", "int", "varchar", "text", "numeric",
    "float", "decimal", "bigint", "smallint", "timestamp",
    "full", "natural", "recursive", "temporary", "temp", "if",
    "primary", "key", "foreign", "references", "constraint", "unique",
    "check", "default", "not", "null", "auto_increment", "serial",
    "first", "last", "next", "prior", "fetch", "rows", "only",
    "percent", "ties", "window", "range", "preceding", "following",
    "unbounded", "current", "row", "groups", "filter",
    "sha256", "md5", "length", "concat", "replace", "position",
    "abs", "ceil", "floor", "round", "power", "sqrt", "mod",
    "string_agg", "array_agg", "json_agg", "jsonb_agg",
})


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------

@dataclass
class HallucinationResult:
    """Result of hallucination detection."""

    is_hallucinated: bool = False
    hallucinated_tables: list[str] = field(default_factory=list)
    hallucinated_columns: list[str] = field(default_factory=list)
    tables_checked: int = 0
    columns_checked: int = 0


# ---------------------------------------------------------------------------
# HallucinationDetector
# ---------------------------------------------------------------------------

class HallucinationDetector:
    """Detects LLM hallucinations by verifying SQL identifiers against
    the filtered schema that was provided to the model."""

    def check(
        self,
        sql: str,
        filtered_schema: dict,
    ) -> HallucinationResult:
        """Check SQL for hallucinated table/column references.

        Parameters
        ----------
        sql : str
            The AI-generated SQL string.
        filtered_schema : dict
            The schema dict provided to the LLM, with structure:
            {
              "tables": [
                {
                  "table_id": "schema.table_name",
                  "table_name": "table_name",
                  "columns": [{"name": "col1"}, ...]
                },
                ...
              ]
            }

        Returns
        -------
        HallucinationResult
        """
        if not sql or not sql.strip():
            return HallucinationResult()

        # Build the allowed identifier sets from the schema
        allowed_tables, allowed_columns = self._build_allowed_sets(filtered_schema)

        # Extract identifiers from the SQL
        sql_tables = self._extract_tables(sql)
        sql_columns = self._extract_columns(sql)

        # Check for hallucinated tables
        hallucinated_tables = [
            t for t in sql_tables
            if t.lower() not in allowed_tables
        ]

        # Check for hallucinated columns
        hallucinated_columns = [
            c for c in sql_columns
            if c.lower() not in allowed_columns and c.lower() not in _SQL_KEYWORDS
        ]

        is_hallucinated = bool(hallucinated_tables) or bool(hallucinated_columns)

        if is_hallucinated:
            logger.warning(
                "Hallucination detected: tables=%s columns=%s",
                hallucinated_tables,
                hallucinated_columns[:10],
            )

        return HallucinationResult(
            is_hallucinated=is_hallucinated,
            hallucinated_tables=hallucinated_tables,
            hallucinated_columns=hallucinated_columns,
            tables_checked=len(sql_tables),
            columns_checked=len(sql_columns),
        )

    # ------------------------------------------------------------------
    # Schema parsing
    # ------------------------------------------------------------------

    def _build_allowed_sets(
        self,
        schema: dict,
    ) -> tuple[set[str], set[str]]:
        """Build normalised sets of allowed table and column names."""
        tables: set[str] = set()
        columns: set[str] = set()

        for t in schema.get("tables", []):
            table_id = (t.get("table_id") or "").lower()
            table_name = (t.get("table_name") or "").lower()

            if table_id:
                tables.add(table_id)
                parts = table_id.split(".")
                if parts:
                    tables.add(parts[-1])  # short name
                if len(parts) >= 2:
                    tables.add(".".join(parts[-2:]))  # schema.table

            if table_name:
                tables.add(table_name)

            for col in t.get("columns", []):
                col_name = (col.get("name") or col.get("column_name") or "").lower()
                if col_name:
                    columns.add(col_name)

        return tables, columns

    # ------------------------------------------------------------------
    # SQL identifier extraction
    # ------------------------------------------------------------------

    def _extract_tables(self, sql: str) -> list[str]:
        """Extract table names from FROM/JOIN clauses."""
        # Strip EXTRACT(...FROM...) to avoid false positives
        cleaned = re.sub(
            r"\bEXTRACT\s*\([^)]*\)", "", sql, flags=re.IGNORECASE
        )
        # Strip string literals to avoid false positives
        cleaned = re.sub(r"'[^']*'", "''", cleaned)

        tables: list[str] = []
        seen: set[str] = set()

        for m in re.finditer(
            r"\b(?:FROM|JOIN)\s+([a-zA-Z_\"`][\w.\"`]*)",
            cleaned,
            flags=re.IGNORECASE,
        ):
            raw = m.group(1).strip().strip('"`').split()[0]
            raw_lower = raw.lower()
            if raw_lower not in _SQL_KEYWORDS and raw_lower not in seen:
                tables.append(raw)
                seen.add(raw_lower)

        return tables

    def _extract_columns(self, sql: str) -> list[str]:
        """Extract column identifiers from SELECT, WHERE, ORDER BY, GROUP BY.

        This uses a conservative approach: we extract identifiers from
        known clause positions to minimise false positives from aliases.
        """
        # Strip string literals
        cleaned = re.sub(r"'[^']*'", "''", sql)

        columns: list[str] = []
        seen: set[str] = set()

        # Columns from WHERE / ORDER BY / GROUP BY (comparison targets)
        for m in re.finditer(
            r"\b([a-zA-Z_]\w*)\s*(?:=|<|>|!=|<>|<=|>=|\bLIKE\b|\bIN\b|\bBETWEEN\b|\bIS\b)",
            cleaned,
            re.IGNORECASE,
        ):
            word = m.group(1)
            word_lower = word.lower()
            if word_lower not in _SQL_KEYWORDS and word_lower not in seen:
                columns.append(word)
                seen.add(word_lower)

        # Columns from SELECT (before FROM)
        select_match = re.search(
            r"\bSELECT\b(.*?)\bFROM\b", cleaned, re.IGNORECASE | re.DOTALL
        )
        if select_match:
            select_clause = select_match.group(1)
            for m in re.finditer(r"\b([a-zA-Z_]\w*)\b", select_clause):
                word = m.group(1)
                word_lower = word.lower()
                if word_lower not in _SQL_KEYWORDS and word_lower not in seen:
                    columns.append(word)
                    seen.add(word_lower)

        # Columns from ORDER BY
        order_match = re.search(
            r"\bORDER\s+BY\b(.*?)(?:\bLIMIT\b|\bOFFSET\b|\bFETCH\b|$)",
            cleaned,
            re.IGNORECASE | re.DOTALL,
        )
        if order_match:
            order_clause = order_match.group(1)
            for m in re.finditer(r"\b([a-zA-Z_]\w*)\b", order_clause):
                word = m.group(1)
                word_lower = word.lower()
                if word_lower not in _SQL_KEYWORDS and word_lower not in seen:
                    columns.append(word)
                    seen.add(word_lower)

        # Columns from GROUP BY
        group_match = re.search(
            r"\bGROUP\s+BY\b(.*?)(?:\bHAVING\b|\bORDER\b|\bLIMIT\b|$)",
            cleaned,
            re.IGNORECASE | re.DOTALL,
        )
        if group_match:
            group_clause = group_match.group(1)
            for m in re.finditer(r"\b([a-zA-Z_]\w*)\b", group_clause):
                word = m.group(1)
                word_lower = word.lower()
                if word_lower not in _SQL_KEYWORDS and word_lower not in seen:
                    columns.append(word)
                    seen.add(word_lower)

        return columns
