"""SG-002: Response Parser -- extracts clean SQL from LLM responses.

Handles markdown code blocks (```sql...```), bare SELECT/WITH statements,
explanation text mixed with SQL, and multiple candidates.  Detects
CANNOT_ANSWER (explicit LLM refusal).

Does NOT block write operations -- that is QueryVault's responsibility.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------

# Markdown fenced SQL blocks (```sql ... ``` or ``` ... ```)
_MD_FENCE = re.compile(r"```(?:sql)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)

# Bare SQL start -- SELECT, WITH, or opening parenthesis
_SQL_START = re.compile(r"(?:^|\n)\s*((?:SELECT|WITH|\()\s)", re.IGNORECASE)

# CANNOT_ANSWER detection
_CANNOT_ANSWER_PREFIX = re.compile(r"^\s*CANNOT[_\s]?ANSWER", re.IGNORECASE)

# Common LLM refusal phrases
_REFUSAL_PHRASES = [
    "i cannot",
    "i'm unable",
    "i am unable",
    "cannot generate",
    "i cannot help",
    "i don't have access",
    "i'm not able",
    "i am not able",
    "unfortunately, i",
    "i'm sorry, but i cannot",
]


@dataclass(frozen=True)
class ParseResult:
    """Structured output from SQL extraction."""

    sql: str | None
    confidence: float
    explanation: str
    parse_error: str | None
    cannot_answer: bool
    cannot_answer_reason: str | None = None

    @property
    def success(self) -> bool:
        return self.sql is not None and not self.cannot_answer


def parse(llm_response: str) -> ParseResult:
    """Extract clean SQL from an LLM response string.

    Processing order:
      1. Check for CANNOT_ANSWER / refusal.
      2. Extract from markdown fenced code blocks.
      3. Fall back to bare SQL detection.
      4. Normalise whitespace.

    No injection scanning or write-operation blocking is performed here.
    """
    text = llm_response.strip()

    if not text:
        return ParseResult(
            sql=None,
            confidence=0.0,
            explanation="",
            parse_error="Empty LLM response",
            cannot_answer=False,
        )

    # ------------------------------------------------------------------
    # 1. CANNOT_ANSWER / refusal detection
    # ------------------------------------------------------------------
    if _CANNOT_ANSWER_PREFIX.match(text):
        reason = text.split(":", 1)[1].strip() if ":" in text else "LLM declined to answer"
        logger.info("llm_cannot_answer", reason=reason[:120])
        return ParseResult(
            sql=None,
            confidence=0.0,
            explanation="",
            parse_error=None,
            cannot_answer=True,
            cannot_answer_reason=reason,
        )

    lower_text = text.lower()
    for phrase in _REFUSAL_PHRASES:
        if lower_text.startswith(phrase):
            return ParseResult(
                sql=None,
                confidence=0.0,
                explanation="",
                parse_error=None,
                cannot_answer=True,
                cannot_answer_reason=text[:300],
            )

    # ------------------------------------------------------------------
    # 2. Extract from markdown code blocks
    # ------------------------------------------------------------------
    explanation = ""
    md_matches = _MD_FENCE.findall(text)

    if md_matches:
        # Take the first non-empty SQL block
        sql_candidates = [m.strip() for m in md_matches if m.strip()]
        if sql_candidates:
            sql = sql_candidates[0]
            # Capture text before the first code fence as explanation
            fence_start = text.find("```")
            if fence_start > 0:
                explanation = text[:fence_start].strip()
            confidence = 0.9 if len(sql_candidates) == 1 else 0.7
            return _finalise(sql, confidence, explanation)

    # ------------------------------------------------------------------
    # 3. Bare SQL detection
    # ------------------------------------------------------------------
    sql_match = _SQL_START.search(text)
    if sql_match:
        raw_sql = text[sql_match.start():].strip()
        # Capture text before the SQL as explanation
        if sql_match.start() > 0:
            explanation = text[: sql_match.start()].strip()

        # Trim trailing explanation after SQL ends
        sql = _trim_trailing_explanation(raw_sql)
        return _finalise(sql, 0.6, explanation)

    # ------------------------------------------------------------------
    # 4. No SQL found
    # ------------------------------------------------------------------
    return ParseResult(
        sql=None,
        confidence=0.0,
        explanation=text[:300],
        parse_error="No SQL found in LLM response",
        cannot_answer=False,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trim_trailing_explanation(raw: str) -> str:
    """Remove non-SQL explanation text trailing after the query."""
    lines = raw.split("\n")
    sql_lines: list[str] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        # A blank line after real SQL content may signal end of query
        if not stripped and sql_lines and sql_lines[-1].strip():
            remaining = "\n".join(lines[i + 1 :]).strip()
            if not remaining or not _SQL_START.match(remaining):
                break
        sql_lines.append(line)
    return "\n".join(sql_lines).strip()


def _finalise(sql: str, confidence: float, explanation: str) -> ParseResult:
    """Normalise extracted SQL and return a ParseResult."""
    # Strip trailing semicolons
    sql = sql.rstrip(";").strip()

    if not sql:
        return ParseResult(
            sql=None,
            confidence=0.0,
            explanation=explanation,
            parse_error="Empty SQL extracted",
            cannot_answer=False,
        )

    # Basic structural check -- must start with SELECT, WITH, or (
    upper = sql.upper().lstrip()
    if not (upper.startswith("SELECT") or upper.startswith("WITH") or upper.startswith("(")):
        return ParseResult(
            sql=None,
            confidence=0.0,
            explanation=explanation,
            parse_error=f"SQL does not start with SELECT/WITH: {sql[:80]}",
            cannot_answer=False,
        )

    # Collapse excessive blank lines
    sql = re.sub(r"\n{3,}", "\n\n", sql).strip()

    logger.debug("sql_extracted", sql_len=len(sql), confidence=confidence)
    return ParseResult(
        sql=sql,
        confidence=confidence,
        explanation=explanation,
        parse_error=None,
        cannot_answer=False,
    )
