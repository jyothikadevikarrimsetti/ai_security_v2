"""SG-003: Dialect Handler -- includes DB dialect in prompt and maps syntax.

Provides dialect-specific hints (TOP vs LIMIT, ISNULL vs COALESCE, date
and string functions) so the LLM generates syntactically correct SQL for
the target database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from xensql.app.models.enums import SQLDialect

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Dialect hint templates
# ---------------------------------------------------------------------------

_DIALECT_HINTS: dict[SQLDialect, str] = {
    SQLDialect.POSTGRESQL: """SQL Dialect: PostgreSQL
Rules:
- Use LIMIT / OFFSET for pagination (not TOP).
- Use COALESCE() for null handling (not ISNULL).
- Use ILIKE for case-insensitive LIKE.
- String concatenation: use || operator.
- Current timestamp: NOW() or CURRENT_TIMESTAMP.
- Date extraction: EXTRACT(YEAR FROM col) or DATE_PART('year', col).
- Date arithmetic: col + INTERVAL '7 days'.
- Boolean type: TRUE / FALSE literals.
- Use double-quotes for identifiers with special chars.
- Array support: col = ANY(ARRAY[...]).
- Use :: for type casting (e.g. col::TEXT).
""",

    SQLDialect.MYSQL: """SQL Dialect: MySQL
Rules:
- Use LIMIT / OFFSET for pagination (not TOP).
- Use COALESCE() or IFNULL() for null handling.
- Use backticks for identifier quoting.
- String concatenation: CONCAT(a, b).
- Current timestamp: NOW() or CURRENT_TIMESTAMP.
- Date extraction: YEAR(col), MONTH(col), DAY(col).
- Date arithmetic: DATE_ADD(col, INTERVAL 7 DAY).
- Boolean: 1/0 or TRUE/FALSE.
- No ILIKE -- use LOWER(col) LIKE LOWER(pattern).
- Use CAST(col AS CHAR) for type casting.
""",

    SQLDialect.SQLSERVER: """SQL Dialect: SQL Server (T-SQL)
Rules:
- Use TOP N for row limiting (not LIMIT). For OFFSET: OFFSET N ROWS FETCH NEXT M ROWS ONLY.
- Use ISNULL() or COALESCE() for null handling.
- Use square brackets for identifier quoting.
- String concatenation: use + operator or CONCAT().
- Current timestamp: GETDATE() or SYSDATETIME().
- Date extraction: YEAR(col), MONTH(col), DAY(col) or DATEPART(year, col).
- Date arithmetic: DATEADD(DAY, 7, col).
- Boolean: use BIT (1/0), not TRUE/FALSE.
- Case-insensitive by default (collation-dependent).
- Use CAST(col AS VARCHAR) or CONVERT().
""",

    SQLDialect.ORACLE: """SQL Dialect: Oracle
Rules:
- Row limiting: use FETCH FIRST N ROWS ONLY (12c+), or ROWNUM in subquery.
- Use NVL() or COALESCE() for null handling.
- Use double-quotes for identifier quoting.
- String concatenation: use || operator.
- Current timestamp: SYSDATE or SYSTIMESTAMP.
- Date extraction: EXTRACT(YEAR FROM col) or TO_CHAR(col, 'YYYY').
- Date arithmetic: col + 7 (days) or col + INTERVAL '7' DAY.
- Boolean: no native BOOLEAN in SQL -- use 1/0 or 'Y'/'N'.
- FROM DUAL for queries without a table.
- Use TO_CHAR, TO_DATE, TO_NUMBER for conversions.
""",
}

# Patterns for engine-string detection from table metadata
_ENGINE_PATTERNS: list[tuple[str, SQLDialect]] = [
    (r"\bpostgres(?:ql)?\b", SQLDialect.POSTGRESQL),
    (r"\brds\s+postgres", SQLDialect.POSTGRESQL),
    (r"\bmysql\b", SQLDialect.MYSQL),
    (r"\bmariadb\b", SQLDialect.MYSQL),
    (r"\bsql\s*server\b", SQLDialect.SQLSERVER),
    (r"\btsql\b", SQLDialect.SQLSERVER),
    (r"\bmssql\b", SQLDialect.SQLSERVER),
    (r"\boracle\b", SQLDialect.ORACLE),
]

# Compiled for repeated use
_ENGINE_RE = [(re.compile(p, re.IGNORECASE), d) for p, d in _ENGINE_PATTERNS]


@dataclass(frozen=True)
class TableInfo:
    """Minimal table metadata used for dialect detection."""

    table_id: str = ""
    engine: str = ""
    description: str = ""
    dialect: str = ""


class DialectHandler:
    """Provides dialect hints for LLM prompts and detects dialect from schema.

    This is a pure pipeline utility -- no auth or validation concerns.
    """

    def get_dialect_hints(self, dialect: SQLDialect) -> str:
        """Return dialect-specific syntax instructions for the LLM prompt.

        Args:
            dialect: Target SQL dialect enum value.

        Returns:
            Multi-line string of dialect rules to embed in the system prompt.
        """
        hints = _DIALECT_HINTS.get(dialect)
        if hints:
            return hints.strip()

        logger.warning("unknown_dialect_for_hints", dialect=dialect)
        return f"SQL Dialect: {dialect.value}\nUse standard ANSI SQL syntax."

    def detect_dialect(self, table_infos: list[TableInfo]) -> SQLDialect:
        """Detect the dominant SQL dialect from table metadata.

        Inspects engine strings, descriptions, and explicit dialect fields
        to determine which dialect the majority of tables belong to.
        Falls back to PostgreSQL if detection is inconclusive.

        Args:
            table_infos: List of table metadata objects.

        Returns:
            The detected SQLDialect enum value.
        """
        if not table_infos:
            logger.info("no_tables_for_dialect_detection, defaulting to postgresql")
            return SQLDialect.POSTGRESQL

        votes: dict[SQLDialect, int] = {}

        for info in table_infos:
            detected = self._detect_single(info)
            if detected:
                votes[detected] = votes.get(detected, 0) + 1

        if not votes:
            logger.info("dialect_detection_inconclusive, defaulting to postgresql")
            return SQLDialect.POSTGRESQL

        winner = max(votes, key=lambda d: votes[d])
        logger.info(
            "dialect_detected",
            dialect=winner.value,
            votes=votes,
            table_count=len(table_infos),
        )
        return winner

    @staticmethod
    def _detect_single(info: TableInfo) -> SQLDialect | None:
        """Detect dialect for a single table from its metadata."""
        # 1. Explicit dialect field
        if info.dialect:
            try:
                return SQLDialect(info.dialect.upper())
            except ValueError:
                pass

        # 2. Engine string
        engine_lower = info.engine.lower() if info.engine else ""
        if engine_lower:
            for regex, dialect in _ENGINE_RE:
                if regex.search(engine_lower):
                    return dialect

        # 3. Description heuristics
        desc = info.description or ""
        if desc:
            for regex, dialect in _ENGINE_RE:
                if regex.search(desc):
                    return dialect

        return None
