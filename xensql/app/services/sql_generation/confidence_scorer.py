"""SG-005: Confidence Scorer -- estimates confidence in generated SQL.

Produces a composite score from retrieval quality, intent clarity, and
generation metadata.  Weighted breakdown:
  - retrieval: 0.4
  - intent:    0.3
  - generation: 0.3

Confidence levels: HIGH (>= 0.75), MEDIUM (>= 0.45), LOW (< 0.45).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from xensql.app.models.enums import ConfidenceLevel

logger = structlog.get_logger(__name__)

# Default weights
_W_RETRIEVAL = 0.4
_W_INTENT = 0.3
_W_GENERATION = 0.3


@dataclass(frozen=True)
class ConfidenceBreakdown:
    """Per-stage confidence scores."""

    retrieval_score: float = 0.0
    intent_score: float = 0.0
    generation_score: float = 0.0


@dataclass(frozen=True)
class ConfidenceScore:
    """Composite confidence result."""

    level: ConfidenceLevel = ConfidenceLevel.LOW
    score: float = 0.0
    breakdown: ConfidenceBreakdown = field(default_factory=ConfidenceBreakdown)
    flags: list[str] = field(default_factory=list)


@dataclass
class RetrievalMeta:
    """Input signals from the retrieval stage."""

    matched_tables: int = 0
    total_candidates: int = 0
    retrieval_score: float = 0.0
    cache_hit: bool = False
    latency_ms: float = 0.0


@dataclass
class IntentResult:
    """Input signals from intent classification."""

    confidence: float = 0.0
    used_fallback: bool = False
    intent_type: str = ""


@dataclass
class GenerationMeta:
    """Input signals from the generation stage."""

    attempt_count: int = 1
    completion_tokens: int = 0
    status: str = "GENERATED"
    cache_hit: bool = False


class ConfidenceScorer:
    """Scores confidence in generated SQL from pipeline stage signals.

    Weights are configurable at construction time; defaults match the
    spec: retrieval 0.4, intent 0.3, generation 0.3.
    """

    def __init__(
        self,
        w_retrieval: float = _W_RETRIEVAL,
        w_intent: float = _W_INTENT,
        w_generation: float = _W_GENERATION,
    ) -> None:
        self._w_retrieval = w_retrieval
        self._w_intent = w_intent
        self._w_generation = w_generation

    def score(
        self,
        retrieval_meta: RetrievalMeta,
        intent_result: IntentResult,
        generation_meta: GenerationMeta,
    ) -> ConfidenceScore:
        """Compute composite confidence from pipeline stage outputs.

        Args:
            retrieval_meta: Signals from schema retrieval.
            intent_result:  Signals from intent classification.
            generation_meta: Signals from SQL generation.

        Returns:
            ConfidenceScore with level, numeric score, breakdown, and flags.
        """
        flags: list[str] = []

        r_score = self._score_retrieval(retrieval_meta, flags)
        i_score = self._score_intent(intent_result, flags)
        g_score = self._score_generation(generation_meta, flags)

        composite = (
            r_score * self._w_retrieval
            + i_score * self._w_intent
            + g_score * self._w_generation
        )

        if composite >= 0.75:
            level = ConfidenceLevel.HIGH
        elif composite >= 0.45:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        result = ConfidenceScore(
            level=level,
            score=round(composite, 3),
            breakdown=ConfidenceBreakdown(
                retrieval_score=round(r_score, 3),
                intent_score=round(i_score, 3),
                generation_score=round(g_score, 3),
            ),
            flags=flags,
        )

        logger.debug(
            "confidence_scored",
            level=level.value,
            score=result.score,
            flags=flags,
        )
        return result

    # ------------------------------------------------------------------
    # Stage scorers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_retrieval(meta: RetrievalMeta, flags: list[str]) -> float:
        """Score retrieval quality."""
        if meta.matched_tables == 0:
            flags.append("no_tables_retrieved")
            return 0.0

        score = 0.5  # base for having at least one table

        # Bonus for multiple candidate tables found
        if meta.total_candidates >= 3:
            score += 0.15

        # Bonus for high retrieval similarity score
        if meta.retrieval_score >= 0.8:
            score += 0.15
        elif meta.retrieval_score >= 0.6:
            score += 0.1

        # Bonus for cache hit (stable / repeated question)
        if meta.cache_hit:
            score += 0.05

        # Penalty for slow retrieval
        if meta.latency_ms > 500:
            flags.append("slow_retrieval")
            score -= 0.05

        return max(0.0, min(1.0, score))

    @staticmethod
    def _score_intent(result: IntentResult, flags: list[str]) -> float:
        """Score intent classification clarity."""
        if result.confidence == 0.0 and not result.intent_type:
            flags.append("no_intent_data")
            return 0.3

        score = result.confidence

        if score < 0.5:
            flags.append("low_intent_confidence")

        # Penalise fallback classification
        if result.used_fallback:
            flags.append("intent_used_fallback")
            score *= 0.7

        return max(0.0, min(1.0, score))

    @staticmethod
    def _score_generation(meta: GenerationMeta, flags: list[str]) -> float:
        """Score generation quality from attempt metadata."""
        if meta.status == "CANNOT_ANSWER":
            flags.append("llm_cannot_answer")
            return 0.1

        if meta.status != "GENERATED":
            return 0.0

        score = 0.7  # base for successful generation

        # Bonus for first-attempt success
        if meta.attempt_count == 1:
            score += 0.1
        else:
            flags.append(f"required_{meta.attempt_count}_attempts")

        # Bonus for cache hit
        if meta.cache_hit:
            score += 0.1

        # Bonus for reasonable token usage
        if 10 < meta.completion_tokens < 500:
            score += 0.1
        elif meta.completion_tokens >= 500:
            flags.append("long_sql_output")
            score -= 0.05

        return max(0.0, min(1.0, score))
