"""CC-002 Token Budget — enforce token limits on prompt sections.

Priority order (highest to lowest — never truncate higher-priority items):
  1. Contextual rules — NEVER truncated
  2. Row filters / mandatory filters — NEVER truncated
  3. High-ranked DDL (top tables by relevance)
  4. Table/column descriptions
  5. Lower-ranked tables (dropped first)

Uses tiktoken for accurate counting with a fallback character-based estimate
when tiktoken is not installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Token counting — tiktoken with fallback
# ---------------------------------------------------------------------------

try:
    import tiktoken

    _ENCODER = tiktoken.get_encoding("cl100k_base")

    def _count_tokens(text: str) -> int:
        """Count tokens using tiktoken cl100k_base encoding."""
        return len(_ENCODER.encode(text))

except ImportError:
    _ENCODER = None

    def _count_tokens(text: str) -> int:  # type: ignore[misc]
        """Fallback estimate: ~1 token per 4 characters."""
        return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

# Section names used as dict keys in prompt_sections
SECTION_RULES = "rules"
SECTION_ROW_FILTERS = "row_filters"
SECTION_SCHEMA = "schema"
SECTION_DESCRIPTIONS = "descriptions"
SECTION_QUESTION = "question"
SECTION_SYSTEM = "system"


@dataclass
class BudgetResult:
    """Result of token budget enforcement."""

    trimmed_sections: dict[str, str]
    total_tokens: int
    budget_limit: int
    tables_dropped: int = 0
    descriptions_truncated: int = 0
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# TokenBudget
# ---------------------------------------------------------------------------


class TokenBudget:
    """Enforce a token budget across prompt sections.

    Sections are trimmed in reverse priority order: lower-ranked tables and
    descriptions are removed first.  Rules and row filters are never touched.

    Usage::

        budget = TokenBudget(max_tokens=4096)
        result = budget.enforce(prompt_sections)
        # result.trimmed_sections → dict of section_name → trimmed text
    """

    def __init__(self, max_tokens: int = 4096) -> None:
        self._max_tokens = max_tokens

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def enforce(
        self,
        prompt_sections: dict[str, Any],
        max_tokens: int | None = None,
    ) -> BudgetResult:
        """Apply the token budget to *prompt_sections*.

        Parameters
        ----------
        prompt_sections:
            Dict with keys from the ``SECTION_*`` constants.  Expected:

            - ``"rules"`` — contextual rules text (never truncated)
            - ``"row_filters"`` — mandatory row filter text (never truncated)
            - ``"schema"`` — list of DDL fragment strings ordered by relevance
            - ``"descriptions"`` — list of table description strings
            - ``"question"`` — user question text
            - ``"system"`` — system instruction text

        max_tokens:
            Override the instance default.

        Returns
        -------
        BudgetResult
        """
        limit = max_tokens or self._max_tokens
        trimmed: dict[str, str] = {}
        warnings: list[str] = []

        # -- Priority 1 & 2: rules + row_filters — copy untouched ----------
        rules_text = prompt_sections.get(SECTION_RULES, "")
        filters_text = prompt_sections.get(SECTION_ROW_FILTERS, "")
        system_text = prompt_sections.get(SECTION_SYSTEM, "")
        question_text = prompt_sections.get(SECTION_QUESTION, "")

        trimmed[SECTION_RULES] = rules_text
        trimmed[SECTION_ROW_FILTERS] = filters_text
        trimmed[SECTION_SYSTEM] = system_text
        trimmed[SECTION_QUESTION] = question_text

        fixed_cost = (
            _count_tokens(rules_text)
            + _count_tokens(filters_text)
            + _count_tokens(system_text)
            + _count_tokens(question_text)
        )

        remaining = limit - fixed_cost
        if remaining <= 0:
            warnings.append(
                f"Fixed sections alone ({fixed_cost} tokens) exceed the "
                f"budget ({limit}). Schema will be empty."
            )
            trimmed[SECTION_SCHEMA] = ""
            trimmed[SECTION_DESCRIPTIONS] = ""
            return BudgetResult(
                trimmed_sections=trimmed,
                total_tokens=fixed_cost,
                budget_limit=limit,
                tables_dropped=len(prompt_sections.get(SECTION_SCHEMA, [])),
                warnings=warnings,
            )

        # -- Priority 5 → 3: fit schema DDL (highest-ranked first) ---------
        schema_ddls: list[str] = prompt_sections.get(SECTION_SCHEMA, [])
        if isinstance(schema_ddls, str):
            schema_ddls = [schema_ddls]

        included_ddls: list[str] = []
        tables_dropped = 0
        schema_used = 0

        for ddl in schema_ddls:
            cost = _count_tokens(ddl)
            if schema_used + cost <= remaining:
                included_ddls.append(ddl)
                schema_used += cost
            else:
                tables_dropped += 1

        trimmed[SECTION_SCHEMA] = "\n\n".join(included_ddls)
        remaining -= schema_used

        # -- Priority 4: descriptions (truncate if over budget) -------------
        descriptions: list[str] = prompt_sections.get(SECTION_DESCRIPTIONS, [])
        if isinstance(descriptions, str):
            descriptions = [descriptions]

        included_descs: list[str] = []
        descs_truncated = 0
        for desc in descriptions:
            cost = _count_tokens(desc)
            if cost <= remaining:
                included_descs.append(desc)
                remaining -= cost
            else:
                # Try truncating the description to fit
                truncated = self._truncate_to_budget(desc, remaining)
                if truncated:
                    included_descs.append(truncated)
                    remaining -= _count_tokens(truncated)
                    descs_truncated += 1
                else:
                    descs_truncated += 1

        trimmed[SECTION_DESCRIPTIONS] = "\n".join(included_descs)

        if tables_dropped:
            warnings.append(
                f"Dropped {tables_dropped} lower-ranked table(s) "
                "to fit token budget."
            )
        if descs_truncated:
            warnings.append(
                f"Truncated {descs_truncated} description(s) "
                "to fit token budget."
            )

        total = sum(_count_tokens(v) for v in trimmed.values())

        return BudgetResult(
            trimmed_sections=trimmed,
            total_tokens=total,
            budget_limit=limit,
            tables_dropped=tables_dropped,
            descriptions_truncated=descs_truncated,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #

    @staticmethod
    def count_tokens(text: str) -> int:
        """Public accessor for token counting (uses tiktoken or fallback)."""
        return _count_tokens(text)

    @staticmethod
    def _truncate_to_budget(text: str, budget: int) -> str:
        """Truncate *text* word-by-word to fit within *budget* tokens."""
        if budget <= 0:
            return ""
        words = text.split()
        result = ""
        for word in words:
            candidate = f"{result} {word}".strip()
            if _count_tokens(candidate) > budget:
                break
            result = candidate
        if result:
            result += "..."
        return result
