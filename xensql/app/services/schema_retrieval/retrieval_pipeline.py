"""Multi-Strategy Retrieval Pipeline for XenSQL.

Three retrieval strategies run concurrently and results are fused:
1. Semantic Vector Search -- cosine similarity over table/column embeddings via pgvector
2. Keyword / Exact Match  -- table name, column name, domain tag matching
3. FK Graph Walk          -- depth-1/2 expansion from seed tables via foreign keys

Strategy fusion deduplicates, applies multi-strategy bonus, and produces
a ranked candidate list.

XenSQL is a pure NL-to-SQL pipeline engine. It does NOT handle auth, RBAC,
or security. The pipeline operates on the full schema catalog it can see;
QueryVault is responsible for pre-filtering.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from xensql.app.models.enums import DomainType, IntentType
from xensql.app.models.schema import ColumnInfo, ForeignKey, TableInfo

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "ranking_weights.yaml"


def _load_retrieval_config() -> dict[str, Any]:
    """Load retrieval section from ranking_weights.yaml."""
    try:
        with open(_CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("ranking_weights_not_found", path=str(_CONFIG_PATH))
        return {}


# ---------------------------------------------------------------------------
# Data classes for internal candidate representation
# ---------------------------------------------------------------------------


@dataclass
class RetrievalCandidate:
    """A candidate table discovered during retrieval."""

    table_id: str
    table_name: str
    description: str = ""
    domain: str | None = None
    columns: list[ColumnInfo] = field(default_factory=list)

    # Per-strategy scores
    semantic_score: float = 0.0
    keyword_score: float = 0.0
    fk_score: float = 0.0
    multi_strategy_bonus: float = 0.0
    final_score: float = 0.0

    # Strategy tracking
    contributing_strategies: list[str] = field(default_factory=list)
    fk_path: list[str] = field(default_factory=list)
    is_bridge_table: bool = False


# ---------------------------------------------------------------------------
# Vector search client protocol
# ---------------------------------------------------------------------------


class VectorSearchClient:
    """Async client for pgvector similarity search.

    Wraps an async SQLAlchemy engine pointed at a pgvector-enabled database.
    """

    def __init__(self, engine: Any) -> None:
        self._engine = engine

    async def search_similar(
        self,
        embedding: list[float],
        top_k: int = 15,
        min_similarity: float = 0.35,
        entity_type: str | None = None,
        database_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Perform cosine similarity search over embedded schema metadata.

        Returns list of dicts with keys: entity_fqn, source_text, entity_type, similarity.
        """
        if not self._engine:
            logger.warning("pgvector_not_available")
            return []

        try:
            from sqlalchemy import text as sa_text
            from sqlalchemy.ext.asyncio import AsyncSession
            from sqlalchemy.orm import sessionmaker

            session_factory = sessionmaker(self._engine, class_=AsyncSession)
            embedding_str = "[" + ",".join(str(x) for x in embedding) + "]"

            type_filter = ""
            db_filter = ""
            params: dict[str, Any] = {
                "embedding": embedding_str,
                "top_k": top_k,
                "min_sim": min_similarity,
            }

            if entity_type:
                type_filter = "AND entity_type = :etype"
                params["etype"] = entity_type

            if database_names:
                db_filter = "AND database_name = ANY(:db_names)"
                params["db_names"] = database_names

            query = sa_text(f"""
                SELECT entity_fqn, source_text, entity_type,
                       1 - (embedding <=> CAST(:embedding AS vector)) AS similarity
                FROM schema_embeddings
                WHERE is_active = true
                  {type_filter}
                  {db_filter}
                  AND 1 - (embedding <=> CAST(:embedding AS vector)) >= :min_sim
                ORDER BY embedding <=> CAST(:embedding AS vector)
                LIMIT :top_k
            """)

            async with session_factory() as session:
                result = await session.execute(query, params)
                rows = result.fetchall()

            return [
                {
                    "entity_fqn": r[0],
                    "source_text": r[1] or "",
                    "entity_type": r[2] or "table",
                    "similarity": float(r[3]),
                }
                for r in rows
            ]
        except Exception as exc:
            logger.error("vector_search_failed", error=str(exc))
            return []


# ---------------------------------------------------------------------------
# Catalog search client protocol
# ---------------------------------------------------------------------------


class CatalogSearchClient:
    """Client for keyword / metadata search against the schema catalog.

    Implementations should query the underlying catalog store (e.g. knowledge
    graph, metadata DB) by table name, column name, and domain tag.
    """

    async def search_tables(
        self, query: str, *, limit: int = 10
    ) -> list[TableInfo]:
        """Search catalog for tables matching *query* by name/description."""
        raise NotImplementedError

    async def get_tables_by_domain(
        self, domain: str, *, limit: int = 5
    ) -> list[TableInfo]:
        """Return tables tagged with *domain*."""
        raise NotImplementedError

    async def get_foreign_keys(self, table_id: str) -> list[ForeignKey]:
        """Return FK edges originating from *table_id*."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


class RetrievalPipeline:
    """Executes multi-strategy retrieval and fuses results.

    No RBAC filtering -- the pipeline works on the full catalog it can see.
    """

    def __init__(
        self,
        vector_client: VectorSearchClient,
        catalog_client: CatalogSearchClient,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._vector = vector_client
        self._catalog = catalog_client
        self._config = config or _load_retrieval_config()
        self._retrieval = self._config.get("retrieval", {})

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def retrieve_candidates(
        self,
        question_embedding: list[float],
        intent: IntentType,
        question: str = "",
        database_names: list[str] | None = None,
        domain_hints: list[DomainType] | None = None,
        top_k: int = 20,
    ) -> tuple[list[RetrievalCandidate], dict[str, float]]:
        """Run all three strategies concurrently and fuse results.

        Args:
            question_embedding: Dense vector for the user question.
            intent: Classified intent of the question.
            question: Original question text (for keyword matching).
            database_names: Optional database scope filter.
            domain_hints: Optional domain hints from intent classification.
            top_k: Maximum candidates to return.

        Returns:
            (ranked_candidates, timing_ms) -- candidates sorted by final_score desc.
        """
        semantic_top_k = self._retrieval.get("semantic_top_k", 25)
        min_sim = self._retrieval.get("semantic_min_threshold", 0.30)

        timing: dict[str, float] = {}

        # Run all three strategies concurrently via asyncio.gather
        t0 = time.monotonic()

        semantic_task = self._semantic_search(
            question_embedding, semantic_top_k, min_sim, intent, database_names
        )
        keyword_task = self._keyword_search(question, intent, domain_hints)

        semantic_results, keyword_results = await asyncio.gather(
            semantic_task, keyword_task
        )
        timing["semantic_ms"] = (time.monotonic() - t0) * 1000
        timing["keyword_ms"] = timing["semantic_ms"]  # ran concurrently

        # FK walk seeds from top semantic + keyword hits
        seed_tables = _extract_seed_table_ids(semantic_results, keyword_results)

        t1 = time.monotonic()
        fk_results = await self._fk_graph_walk(seed_tables, intent)
        timing["fk_walk_ms"] = (time.monotonic() - t1) * 1000

        # Fuse results
        candidates = self._fuse_strategies(
            semantic_results, keyword_results, fk_results
        )

        # Sort by final_score descending, limit
        candidates.sort(key=lambda c: c.final_score, reverse=True)
        timing["total_ms"] = (time.monotonic() - t0) * 1000

        return candidates[:top_k], timing

    # ------------------------------------------------------------------
    # Strategy 1: Semantic Vector Search
    # ------------------------------------------------------------------

    async def _semantic_search(
        self,
        embedding: list[float],
        top_k: int,
        min_similarity: float,
        intent: IntentType,
        database_names: list[str] | None = None,
    ) -> list[RetrievalCandidate]:
        """Query pgvector for semantically similar tables."""
        results = await self._vector.search_similar(
            embedding,
            top_k=top_k,
            min_similarity=min_similarity,
            entity_type="table",
            database_names=database_names,
        )

        # If database filtering returned too few results, retry without filter
        if database_names and len(results) < 2:
            logger.debug("semantic_search_broadening", filtered_count=len(results))
            results = await self._vector.search_similar(
                embedding,
                top_k=top_k,
                min_similarity=min_similarity,
                entity_type="table",
            )

        # Column-level semantic search for intents where column names matter
        column_intents = {
            IntentType.DATA_LOOKUP,
            IntentType.DEFINITION,
            IntentType.AGGREGATION,
        }
        if intent in column_intents:
            col_results = await self._vector.search_similar(
                embedding,
                top_k=5,
                min_similarity=min_similarity + 0.05,
                entity_type="column",
                database_names=database_names,
            )
            results.extend(col_results)

        return _vector_results_to_candidates(results)

    # ------------------------------------------------------------------
    # Strategy 2: Keyword / Exact Match
    # ------------------------------------------------------------------

    async def _keyword_search(
        self,
        question: str,
        intent: IntentType,
        domain_hints: list[DomainType] | None = None,
    ) -> list[RetrievalCandidate]:
        """Search catalog by table/column names extracted from the question."""
        exact_table_boost = self._retrieval.get("keyword_exact_table_boost", 0.95)
        domain_boost = self._retrieval.get("keyword_domain_boost", 0.60)
        max_domain_adds = self._retrieval.get("keyword_domain_max_additions", 3)

        candidates: list[RetrievalCandidate] = []

        # Search by question text
        if question:
            try:
                tables = await self._catalog.search_tables(question, limit=10)
                for t in tables:
                    candidates.append(RetrievalCandidate(
                        table_id=t.table_id,
                        table_name=t.table_name,
                        description=t.description,
                        domain=t.domain.value if t.domain else None,
                        columns=t.columns,
                        keyword_score=exact_table_boost,
                        contributing_strategies=["keyword"],
                    ))
            except Exception as exc:
                logger.warning("keyword_search_failed", error=str(exc))

        # Domain-based additions
        if domain_hints:
            domain_added = 0
            for hint in domain_hints:
                if domain_added >= max_domain_adds:
                    break
                try:
                    domain_tables = await self._catalog.get_tables_by_domain(
                        hint.value, limit=5
                    )
                    for t in domain_tables:
                        if not any(c.table_id == t.table_id for c in candidates):
                            candidates.append(RetrievalCandidate(
                                table_id=t.table_id,
                                table_name=t.table_name,
                                description=t.description,
                                domain=t.domain.value if t.domain else None,
                                columns=t.columns,
                                keyword_score=domain_boost,
                                contributing_strategies=["keyword"],
                            ))
                            domain_added += 1
                except Exception as exc:
                    logger.debug(
                        "domain_search_failed",
                        domain=hint.value,
                        error=str(exc),
                    )

        return candidates

    # ------------------------------------------------------------------
    # Strategy 3: FK Graph Walk
    # ------------------------------------------------------------------

    async def _fk_graph_walk(
        self,
        seed_table_ids: list[str],
        intent: IntentType,
    ) -> list[RetrievalCandidate]:
        """Expand seed tables via FK edges (depth 1-2)."""
        depth_1_boost = self._retrieval.get("fk_depth_1_boost", 0.70)
        depth_2_boost = self._retrieval.get("fk_depth_2_boost", 0.50)

        candidates: list[RetrievalCandidate] = []
        visited: set[str] = set(seed_table_ids)
        max_depth = 2 if intent == IntentType.JOIN_QUERY else 1

        for table_id in seed_table_ids[:5]:  # Cap seeds for performance
            try:
                fks = await self._catalog.get_foreign_keys(table_id)
                for fk in fks:
                    target = fk.to_table
                    if target and target not in visited:
                        visited.add(target)
                        is_bridge = _is_bridge_table(target)
                        candidates.append(RetrievalCandidate(
                            table_id=target,
                            table_name=target.split(".")[-1],
                            fk_score=depth_1_boost,
                            contributing_strategies=["fk_walk"],
                            fk_path=[table_id, target],
                            is_bridge_table=is_bridge,
                        ))

                        # Depth-2 walk for JOIN_QUERY intent
                        if max_depth >= 2:
                            try:
                                fks_2 = await self._catalog.get_foreign_keys(target)
                                for fk2 in fks_2[:3]:
                                    t2 = fk2.to_table
                                    if t2 and t2 not in visited:
                                        visited.add(t2)
                                        candidates.append(RetrievalCandidate(
                                            table_id=t2,
                                            table_name=t2.split(".")[-1],
                                            fk_score=depth_2_boost,
                                            contributing_strategies=["fk_walk"],
                                            fk_path=[table_id, target, t2],
                                            is_bridge_table=_is_bridge_table(t2),
                                        ))
                            except Exception:
                                pass
            except Exception as exc:
                logger.debug("fk_walk_failed", table=table_id, error=str(exc))

        return candidates

    # ------------------------------------------------------------------
    # Strategy fusion
    # ------------------------------------------------------------------

    def _fuse_strategies(
        self,
        semantic: list[RetrievalCandidate],
        keyword: list[RetrievalCandidate],
        fk_walk: list[RetrievalCandidate],
    ) -> list[RetrievalCandidate]:
        """Merge, deduplicate, and score candidates from all strategies."""
        bonus_value = self._retrieval.get("multi_strategy_bonus_value", 0.08)

        merged: dict[str, RetrievalCandidate] = {}

        for candidates in [semantic, keyword, fk_walk]:
            for c in candidates:
                if c.table_id in merged:
                    existing = merged[c.table_id]
                    # Take max per strategy
                    existing.semantic_score = max(existing.semantic_score, c.semantic_score)
                    existing.keyword_score = max(existing.keyword_score, c.keyword_score)
                    existing.fk_score = max(existing.fk_score, c.fk_score)
                    # Merge strategies
                    for s in c.contributing_strategies:
                        if s not in existing.contributing_strategies:
                            existing.contributing_strategies.append(s)
                    # Inherit metadata
                    if not existing.description and c.description:
                        existing.description = c.description
                    if not existing.domain and c.domain:
                        existing.domain = c.domain
                    if c.is_bridge_table:
                        existing.is_bridge_table = True
                    if not existing.columns and c.columns:
                        existing.columns = c.columns
                else:
                    merged[c.table_id] = RetrievalCandidate(
                        table_id=c.table_id,
                        table_name=c.table_name,
                        description=c.description,
                        domain=c.domain,
                        columns=list(c.columns),
                        semantic_score=c.semantic_score,
                        keyword_score=c.keyword_score,
                        fk_score=c.fk_score,
                        contributing_strategies=list(c.contributing_strategies),
                        fk_path=list(c.fk_path),
                        is_bridge_table=c.is_bridge_table,
                    )

        # Apply multi-strategy bonus and compute preliminary score
        for c in merged.values():
            if len(c.contributing_strategies) > 1:
                c.multi_strategy_bonus = bonus_value * (
                    len(c.contributing_strategies) - 1
                )
            c.final_score = (
                max(c.semantic_score, c.keyword_score, c.fk_score)
                + c.multi_strategy_bonus
            )

        return list(merged.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vector_results_to_candidates(
    results: list[dict[str, Any]],
) -> list[RetrievalCandidate]:
    """Convert vector search result dicts to RetrievalCandidate objects."""
    seen: set[str] = set()
    candidates: list[RetrievalCandidate] = []

    for r in results:
        table_fqn = r["entity_fqn"]
        # Strip embedding key suffixes
        if ":col_desc" in table_fqn or ":desc" in table_fqn:
            table_fqn = table_fqn.rsplit(":", 1)[0]
        # Column FQN -- extract table portion
        if "." in table_fqn and table_fqn.count(".") > 2:
            parts = table_fqn.split(".")
            table_fqn = ".".join(parts[:3])

        if table_fqn in seen:
            continue
        seen.add(table_fqn)

        candidates.append(RetrievalCandidate(
            table_id=table_fqn,
            table_name=table_fqn.split(".")[-1] if "." in table_fqn else table_fqn,
            semantic_score=r["similarity"],
            contributing_strategies=["semantic"],
        ))

    return candidates


def _extract_seed_table_ids(
    semantic: list[RetrievalCandidate],
    keyword: list[RetrievalCandidate],
) -> list[str]:
    """Pick the best seed tables for FK graph walk."""
    seeds: list[str] = []
    seen: set[str] = set()
    combined = sorted(
        semantic + keyword,
        key=lambda x: x.final_score or max(x.semantic_score, x.keyword_score),
        reverse=True,
    )
    for c in combined:
        if c.table_id not in seen:
            seeds.append(c.table_id)
            seen.add(c.table_id)
        if len(seeds) >= 5:
            break
    return seeds


def _is_bridge_table(table_name: str) -> bool:
    """Heuristic: detect bridge/junction tables by naming patterns."""
    name = table_name.lower().split(".")[-1]
    patterns = [
        "_to_", "_x_", "_map", "_link", "_bridge", "_assoc",
        "_rel", "_xref", "mapping", "junction",
    ]
    return any(p in name for p in patterns)
