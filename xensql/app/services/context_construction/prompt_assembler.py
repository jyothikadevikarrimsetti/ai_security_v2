"""CC-001 Prompt Assembler — construct the LLM prompt from pre-filtered context.

Assembles a four-section prompt for SQL generation:
  1. System instructions (role + absolute rules + dialect awareness)
  2. Contextual rules from QueryVault (NEVER truncated)
  3. Schema DDL fragments ordered by relevance
  4. User question + dialect hints

XenSQL is an NL-to-SQL Pipeline Engine. It does NOT handle auth, RBAC, or
security. It receives pre-filtered schema + contextual_rules from QueryVault
and assembles prompts for the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from xensql.app.models.enums import SQLDialect

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dialect metadata
# ---------------------------------------------------------------------------

_DIALECT_LABELS: dict[SQLDialect, str] = {
    SQLDialect.POSTGRESQL: "PostgreSQL",
    SQLDialect.MYSQL: "MySQL",
    SQLDialect.SQLSERVER: "Microsoft SQL Server (T-SQL)",
    SQLDialect.ORACLE: "Oracle SQL",
}

_DIALECT_HINTS: dict[SQLDialect, str] = {
    SQLDialect.POSTGRESQL: (
        "Use LIMIT N, COALESCE(), DATE_TRUNC(), standard SQL intervals."
    ),
    SQLDialect.MYSQL: (
        "Use LIMIT N, IFNULL(), CURDATE(), "
        "DATE_SUB(CURDATE(), INTERVAL N DAY). "
        "Always specify the unit keyword with INTERVAL."
    ),
    SQLDialect.SQLSERVER: (
        "Use TOP N, bracket-quoted identifiers, ISNULL(), GETDATE()."
    ),
    SQLDialect.ORACLE: (
        "Use FETCH FIRST N ROWS ONLY, NVL(), SYSDATE, TO_DATE()."
    ),
}

# ---------------------------------------------------------------------------
# System prompt template
# ---------------------------------------------------------------------------

_SYSTEM_TEMPLATE = """\
You are a SQL query generator. Your ONLY job is to produce a single, valid
SQL SELECT query that answers the user's question using ONLY the provided
schema.

ABSOLUTE RULES:
1. Use ONLY tables and columns from the AVAILABLE SCHEMA section.
2. NEVER reference tables or columns not listed in the schema.
3. Follow ALL rules in the CONTEXTUAL RULES section without exception.
4. Generate ONLY SELECT statements. Never INSERT, UPDATE, DELETE, or DROP.
5. Include LIMIT {max_rows} unless the query already uses aggregation.
6. If the question cannot be answered with the provided schema,
   respond with: CANNOT_ANSWER: [brief reason]
7. Output ONLY the SQL query. No explanations, no markdown fences.
8. If a contextual rule conflicts with the question, the rule ALWAYS wins.
9. Use table aliases in multi-table queries.
10. For string comparisons use UPPER() on both sides.\
"""

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssembledPrompt:
    """Output of prompt assembly — ready for LLM consumption."""

    messages: list[dict[str, str]]
    tables_included: int
    tables_truncated: int
    rules_count: int
    token_breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def total_estimated_tokens(self) -> int:
        return sum(self.token_breakdown.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~1 token per 4 characters."""
    return max(1, len(text) // 4)


def _resolve_dialect(dialect: str | SQLDialect | None) -> SQLDialect | None:
    """Normalise a dialect value to a SQLDialect enum (or None)."""
    if dialect is None:
        return None
    if isinstance(dialect, SQLDialect):
        return dialect
    try:
        return SQLDialect(dialect.upper())
    except (ValueError, AttributeError):
        return None


def _table_to_ddl(table: dict[str, Any]) -> str:
    """Convert a table dict (from filtered_schema) to a CREATE TABLE DDL string."""
    table_name = table.get("table_name", table.get("table_id", "unknown"))
    columns = table.get("columns", [])

    col_lines: list[str] = []
    for col in columns:
        name = col.get("column_name", col.get("name", ""))
        dtype = col.get("data_type", "VARCHAR")
        desc = col.get("description", "")
        line = f"  {name} {dtype}"
        if desc:
            line += f"  -- {desc}"
        col_lines.append(line)

    header = f"CREATE TABLE {table_name} ("
    footer = ");"
    return "\n".join([header, *col_lines, footer])


# ---------------------------------------------------------------------------
# PromptAssembler
# ---------------------------------------------------------------------------


class PromptAssembler:
    """Assemble the four-section LLM prompt.

    Sections (in message order):
      1. System instructions — role, absolute rules, dialect context
      2. Contextual rules from QueryVault — NEVER truncated
      3. Schema DDL fragments — ordered by relevance, may be trimmed
      4. User question + dialect hints

    Usage::

        assembler = PromptAssembler()
        prompt = assembler.assemble(
            question="Show all patients from cardiology",
            schema_context={"tables": [...], "join_paths": [...]},
            contextual_rules=["Only return encounters from 2024"],
            dialect="POSTGRESQL",
        )
        # prompt.messages → list of {"role": ..., "content": ...}
    """

    def __init__(self, max_rows: int = 1000) -> None:
        self._max_rows = max_rows

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def assemble(
        self,
        question: str,
        schema_context: dict[str, Any],
        contextual_rules: list[str] | None = None,
        dialect: str | SQLDialect | None = None,
        *,
        max_prompt_tokens: int = 10_000,
        response_reserve_tokens: int = 2048,
    ) -> AssembledPrompt:
        """Build the complete prompt as a ``messages`` list.

        Parameters
        ----------
        question:
            The end-user's natural-language question.
        schema_context:
            Pre-filtered schema payload from QueryVault.
            Expected keys: ``tables`` (list[dict]), optionally ``join_paths``.
        contextual_rules:
            NL policy rules / mandatory filters / join hints supplied by
            QueryVault.  These are NEVER truncated.
        dialect:
            Target SQL dialect (string or enum).  Appended as a hint in the
            user message footer.
        max_prompt_tokens:
            Soft token ceiling for the full prompt.
        response_reserve_tokens:
            Tokens reserved for the LLM response.

        Returns
        -------
        AssembledPrompt
            Contains ``messages`` ready for the LLM, plus metrics.
        """
        rules = contextual_rules or []
        resolved_dialect = _resolve_dialect(dialect)
        tables: list[dict[str, Any]] = schema_context.get("tables", [])

        # -- Section 1: system instructions --------------------------------
        system_text = _SYSTEM_TEMPLATE.format(max_rows=self._max_rows)
        if resolved_dialect:
            label = _DIALECT_LABELS.get(resolved_dialect, resolved_dialect.value)
            system_text += f"\n\nTarget SQL dialect: {label}."

        # -- Section 2: contextual rules (NEVER truncated) -----------------
        rules_text = self._format_rules(rules)

        # -- Section 3: schema DDL -----------------------------------------
        table_ddls = [_table_to_ddl(t) for t in tables]
        schema_text = self._format_schema(table_ddls)

        # -- Section 4: user question + dialect hints ----------------------
        question_text = self._format_question(question, resolved_dialect)

        # -- Token budget: trim schema if necessary ------------------------
        fixed_tokens = (
            _estimate_tokens(system_text)
            + _estimate_tokens(rules_text)
            + _estimate_tokens(question_text)
            + response_reserve_tokens
            + 200  # overhead
        )
        schema_budget = max(0, max_prompt_tokens - fixed_tokens)

        schema_text, included, truncated = self._trim_schema(
            table_ddls, schema_budget
        )

        # -- Compose user message ------------------------------------------
        user_parts: list[str] = []
        if rules_text:
            user_parts.append(rules_text)
        user_parts.append(schema_text)
        user_parts.append(question_text)
        user_message = "\n\n".join(user_parts)

        messages = [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_message},
        ]

        token_breakdown = {
            "system": _estimate_tokens(system_text),
            "rules": _estimate_tokens(rules_text),
            "schema": _estimate_tokens(schema_text),
            "question": _estimate_tokens(question_text),
        }

        if truncated > 0:
            logger.warning(
                "Schema tables truncated due to token budget: "
                "included=%d, truncated=%d",
                included,
                truncated,
            )

        return AssembledPrompt(
            messages=messages,
            tables_included=included,
            tables_truncated=truncated,
            rules_count=len(rules),
            token_breakdown=token_breakdown,
        )

    # ------------------------------------------------------------------ #
    # Section formatters
    # ------------------------------------------------------------------ #

    @staticmethod
    def _format_rules(rules: list[str]) -> str:
        """Format contextual rules into the CONTEXTUAL RULES section."""
        if not rules:
            return ""
        lines = [
            "=== CONTEXTUAL RULES ===",
            "You MUST follow ALL of the following rules when generating SQL.",
            "Violating ANY rule makes the query invalid.",
            "",
        ]
        for i, rule in enumerate(rules, 1):
            lines.append(f"RULE {i}: {rule}")
        lines.append("=== END CONTEXTUAL RULES ===")
        return "\n".join(lines)

    @staticmethod
    def _format_schema(ddl_fragments: list[str]) -> str:
        """Wrap DDL fragments in the AVAILABLE SCHEMA section."""
        header = [
            "=== AVAILABLE SCHEMA ===",
            "The following tables and columns are the ONLY ones you may use.",
            "Any table or column not listed here DOES NOT EXIST.",
            "",
        ]
        body = [f"{ddl}\n" for ddl in ddl_fragments]
        footer = ["=== END AVAILABLE SCHEMA ==="]
        return "\n".join(header + body + footer)

    @staticmethod
    def _format_question(
        question: str, dialect: SQLDialect | None
    ) -> str:
        """Format the user question section with dialect hints."""
        lines = [
            f"=== USER QUESTION ===\n{question}\n=== END USER QUESTION ===",
        ]

        if dialect:
            label = _DIALECT_LABELS.get(dialect, dialect.value)
            footer = (
                f"Generate a single valid {label} SELECT query "
                "using ONLY the tables and columns above."
            )
            hint = _DIALECT_HINTS.get(dialect)
            if hint:
                footer += f" {hint}"
            lines.append(footer)
        else:
            lines.append(
                "Generate a single valid SELECT query "
                "using ONLY the tables and columns above."
            )

        return "\n\n".join(lines)

    # ------------------------------------------------------------------ #
    # Schema trimming
    # ------------------------------------------------------------------ #

    @staticmethod
    def _trim_schema(
        ddl_fragments: list[str],
        budget_tokens: int,
    ) -> tuple[str, int, int]:
        """Include as many DDL fragments as fit within the token budget.

        The first three tables are always included (must-have).  Remaining
        tables are added in order until the budget is exhausted.

        Returns (formatted_schema_text, tables_included, tables_truncated).
        """
        must_include_count = min(3, len(ddl_fragments))
        must_include = ddl_fragments[:must_include_count]
        optional = ddl_fragments[must_include_count:]

        included_ddls: list[str] = list(must_include)
        used_tokens = sum(_estimate_tokens(d) for d in included_ddls)
        truncated = 0

        for ddl in optional:
            cost = _estimate_tokens(ddl)
            if used_tokens + cost <= budget_tokens:
                included_ddls.append(ddl)
                used_tokens += cost
            else:
                truncated += 1

        header = [
            "=== AVAILABLE SCHEMA ===",
            "The following tables and columns are the ONLY ones you may use.",
            "Any table or column not listed here DOES NOT EXIST.",
            "",
        ]
        body = [f"{ddl}\n" for ddl in included_ddls]
        footer = ["=== END AVAILABLE SCHEMA ==="]
        schema_text = "\n".join(header + body + footer)

        return schema_text, len(included_ddls), truncated
