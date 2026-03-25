"""Tests for XenSQL Confidence Scorer."""
import pytest
from xensql.app.services.sql_generation.confidence_scorer import (
    ConfidenceScorer, RetrievalMeta, IntentResult, GenerationMeta
)
from xensql.app.models.enums import ConfidenceLevel


@pytest.fixture
def scorer():
    return ConfidenceScorer()


class TestConfidenceScoring:
    def test_high_confidence(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=5, total_candidates=10, retrieval_score=0.9),
            IntentResult(confidence=0.95, intent_type="AGGREGATION"),
            GenerationMeta(attempt_count=1, completion_tokens=50, status="GENERATED"),
        )
        assert result.level == ConfidenceLevel.HIGH
        assert result.score >= 0.75

    def test_medium_confidence(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=2, total_candidates=5, retrieval_score=0.5),
            IntentResult(confidence=0.6, intent_type="DATA_LOOKUP"),
            GenerationMeta(attempt_count=2, completion_tokens=100, status="GENERATED"),
        )
        assert result.level == ConfidenceLevel.MEDIUM
        assert 0.45 <= result.score < 0.75

    def test_low_confidence_no_tables(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=0, total_candidates=0, retrieval_score=0.0),
            IntentResult(confidence=0.3, used_fallback=True, intent_type="DATA_LOOKUP"),
            GenerationMeta(attempt_count=3, completion_tokens=10, status="GENERATED"),
        )
        assert result.level == ConfidenceLevel.LOW
        assert result.score < 0.45
        assert "no_tables_retrieved" in result.flags

    def test_cannot_answer_low(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=3, total_candidates=10, retrieval_score=0.8),
            IntentResult(confidence=0.9, intent_type="DATA_LOOKUP"),
            GenerationMeta(status="CANNOT_ANSWER"),
        )
        assert "llm_cannot_answer" in result.flags
        assert result.score < 0.75

    def test_score_bounded_0_to_1(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=100, total_candidates=100, retrieval_score=1.0, cache_hit=True),
            IntentResult(confidence=1.0, intent_type="AGGREGATION"),
            GenerationMeta(attempt_count=1, completion_tokens=50, status="GENERATED", cache_hit=True),
        )
        assert 0.0 <= result.score <= 1.0

    def test_breakdown_populated(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=3, total_candidates=5, retrieval_score=0.7),
            IntentResult(confidence=0.8, intent_type="TREND"),
            GenerationMeta(attempt_count=1, completion_tokens=80, status="GENERATED"),
        )
        assert result.breakdown.retrieval_score > 0
        assert result.breakdown.intent_score > 0
        assert result.breakdown.generation_score > 0

    def test_slow_retrieval_flagged(self, scorer):
        result = scorer.score(
            RetrievalMeta(matched_tables=3, total_candidates=5, retrieval_score=0.7, latency_ms=600),
            IntentResult(confidence=0.8, intent_type="DATA_LOOKUP"),
            GenerationMeta(attempt_count=1, completion_tokens=50, status="GENERATED"),
        )
        assert "slow_retrieval" in result.flags
