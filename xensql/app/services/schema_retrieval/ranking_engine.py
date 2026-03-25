"""Domain-Aware Ranking Engine -- composite scoring model for XenSQL.

Computes final relevance score using configurable weights:
  final = semantic_similarity * 0.50
        + domain_affinity     * 0.20
        + intent_match        * 0.15
        + join_connectivity   * 0.10
        + multi_strategy      * 0.05

Includes:
- Universal join anchor boosts (e.g. patients, encounters, providers)
- Intent-specific scoring adjustments (time_column_boost, bridge_table_boost, etc.)
- TF-IDF reranking from enrichment terms

XenSQL is a pure NL-to-SQL pipeline engine. No RBAC, no sensitivity demotion,
no clearance checks. QueryVault handles all access-control filtering upstream.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

import structlog
import yaml

from xensql.app.models.enums import DomainType, IntentType
from xensql.app.models.schema import TableInfo

from .retrieval_pipeline import RetrievalCandidate

logger = structlog.get_logger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "ranking_weights.yaml"


def _load_config() -> dict[str, Any]:
    try:
        with open(_CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("ranking_weights_not_found", path=str(_CONFIG_PATH))
        return {}


class RankingEngine:
    """Applies configurable composite scoring to candidate tables.

    No sensitivity demotion -- QueryVault pre-filters the schema before
    XenSQL ever sees it.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or _load_config()
        self._scoring = self._config.get("scoring", {})
        self._domain_config = self._config.get("domain_affinity", {})
        self._intent_config = self._config.get("intent_scoring", {})

    def rank(
        self,
        candidates: list[RetrievalCandidate],
        intent: IntentType,
        question: str = "",
        domain_hints: list[DomainType] | None = None,
        synonyms: list[str] | None = None,
        table_hints: list[str] | None = None,
    ) -> list[RetrievalCandidate]:
        """Score and rank candidates using the composite scoring model.

        Args:
            candidates: Candidate tables from retrieval pipeline.
            intent: Classified intent of the question.
            question: Original question text (for TF-IDF reranking).
            domain_hints: Domain hints from intent classification.
            synonyms: Synonym expansions for TF-IDF.
            table_hints: Explicit table name hints for TF-IDF.

        Returns:
            Candidates sorted by final_score descending.
        """
        # Apply TF-IDF reranking if question text is available
        if question:
            self._apply_tfidf_rerank(
                candidates, question, synonyms or [], table_hints or []
            )

        # Weights
        w_semantic = self._scoring.get("semantic_similarity", 0.50)
        w_domain = self._scoring.get("domain_affinity", 0.20)
        w_intent = self._scoring.get("intent_match", 0.15)
        w_join = self._scoring.get("join_connectivity", 0.10)
        w_multi = self._scoring.get("multi_strategy_bonus", 0.05)

        # Universal anchors
        universal_anchors = set(
            self._domain_config.get(
                "universal_anchors", ["patients", "encounters", "providers"]
            )
        )
        anchor_boost = self._domain_config.get("universal_anchor_boost", 0.15)

        hint_domains = {h.value for h in domain_hints} if domain_hints else set()

        for c in candidates:
            # --- Domain affinity ---
            domain_score = 0.0
            if c.domain:
                if c.domain in hint_domains:
                    domain_score = 1.0
                else:
                    domain_score = 0.5

            # Universal anchor boost -- suppress for aggregate/trend/comparison
            # intents so analytics/summary tables can outrank transactional anchors.
            aggregate_intents = {
                IntentType.AGGREGATION,
                IntentType.TREND,
                IntentType.COMPARISON,
            }
            if (
                c.table_name.lower() in universal_anchors
                and intent not in aggregate_intents
            ):
                domain_score = max(domain_score, 0.8) + anchor_boost

            # --- Intent-specific scoring ---
            intent_score = self._compute_intent_score(c, intent)

            # --- Join connectivity ---
            join_score = c.fk_score
            if c.is_bridge_table and intent == IntentType.JOIN_QUERY:
                join_score = min(join_score + 0.2, 1.0)

            # --- Composite score ---
            raw_score = (
                c.semantic_score * w_semantic
                + domain_score * w_domain
                + intent_score * w_intent
                + join_score * w_join
                + c.multi_strategy_bonus * w_multi
            )

            c.final_score = round(raw_score, 4)

        # Sort descending
        candidates.sort(key=lambda x: x.final_score, reverse=True)
        return candidates

    # ------------------------------------------------------------------
    # Intent-specific scoring
    # ------------------------------------------------------------------

    def _compute_intent_score(
        self,
        candidate: RetrievalCandidate,
        intent: IntentType,
    ) -> float:
        """Compute intent-specific bonus for a candidate."""
        rules = self._intent_config.get(intent.value, {})
        score = 0.0
        name = candidate.table_name.lower()
        desc = candidate.description.lower()

        if intent == IntentType.AGGREGATION:
            # Let semantic + TF-IDF handle table relevance -- no hardcoded boosts.
            pass

        elif intent == IntentType.TREND:
            # Boost tables with time columns
            if any(kw in desc for kw in ["date", "timestamp", "time", "period"]):
                score += rules.get("time_column_boost", 0.15)

        elif intent == IntentType.JOIN_QUERY:
            if candidate.is_bridge_table:
                score += rules.get("bridge_table_boost", 0.20)
            if candidate.fk_score > 0:
                score += rules.get("fk_connectivity_boost", 0.15)

        elif intent == IntentType.DATA_LOOKUP:
            if any(kw in desc or kw in name for kw in _desc_keywords(desc)):
                score += rules.get("column_match_boost", 0.20)

        elif intent == IntentType.DEFINITION:
            if desc or name:
                score += rules.get("column_match_boost", 0.15)

        return min(score, 1.0)

    # ------------------------------------------------------------------
    # TF-IDF reranking
    # ------------------------------------------------------------------

    def _apply_tfidf_rerank(
        self,
        candidates: list[RetrievalCandidate],
        question: str,
        synonyms: list[str],
        table_hints: list[str],
    ) -> None:
        """Score candidates using manual TF-IDF against question terms."""
        if not candidates:
            return

        # Build query terms
        query_terms: list[str] = []
        query_terms.extend(self._tokenize(question))
        for syn in synonyms:
            query_terms.extend(self._tokenize(syn))
        for hint in table_hints:
            query_terms.extend(self._tokenize(hint))

        if not query_terms:
            return

        # Build document corpus from candidate descriptions + table names
        docs: list[set[str]] = []
        for c in candidates:
            tokens = set(self._tokenize(c.description)) | set(
                self._tokenize(c.table_name)
            )
            docs.append(tokens)

        n_docs = len(docs)

        # Compute IDF for each query term
        idf: dict[str, float] = {}
        for term in set(query_terms):
            doc_freq = sum(1 for d in docs if term in d)
            idf[term] = math.log((n_docs + 1) / (doc_freq + 1)) + 1.0

        # Score each candidate -- store as a bonus in semantic_score adjustment
        for i, c in enumerate(candidates):
            doc_tokens = docs[i]
            if not doc_tokens:
                continue

            score = 0.0
            for term in set(query_terms):
                if term in doc_tokens:
                    score += idf.get(term, 1.0)

            max_possible = sum(idf.get(t, 1.0) for t in set(query_terms))
            tfidf = min(score / max_possible, 1.0) if max_possible > 0 else 0.0

            # Blend TF-IDF into semantic score as a small additive boost
            c.semantic_score = max(c.semantic_score, c.semantic_score + tfidf * 0.10)

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Lowercase, split on non-alphanumeric, filter short tokens."""
        if not text:
            return []
        return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 2]


def _desc_keywords(desc: str) -> list[str]:
    """Extract simple keywords from a description for matching."""
    if not desc:
        return []
    return [w for w in re.split(r"[^a-z0-9]+", desc.lower()) if len(w) >= 3]
