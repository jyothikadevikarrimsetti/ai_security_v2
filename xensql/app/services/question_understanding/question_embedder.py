"""Question Embedder -- preprocess, expand, hash, embed, cache.

Preprocessing pipeline:
1. Normalize whitespace
2. Expand abbreviations via TerminologyExpander (additive, original preserved)
3. SHA-256 hash for cache keying (preprocessed text + model version)
4. Generate dense embedding vector via embedding client
5. L2 normalize the vector
6. Cache result in Redis

XenSQL pipeline concern only -- no auth, RBAC, security context, or
role-based context suffixes. Those belong to QueryVault.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from typing import Protocol

import structlog

from xensql.app.services.question_understanding.terminology_expander import (
    TerminologyExpander,
)

logger = structlog.get_logger(__name__)


# -- Protocols for dependency injection ---------------------------------------


class EmbeddingClient(Protocol):
    """Protocol for embedding providers (Voyage, OpenAI, etc.)."""

    async def embed(self, text: str) -> list[float]: ...

    @property
    def model_name(self) -> str: ...

    @property
    def dimensions(self) -> int: ...


class EmbeddingCache(Protocol):
    """Protocol for embedding cache backends (Redis, in-memory, etc.)."""

    async def get_embedding(self, key: str) -> list[float] | None: ...

    async def set_embedding(self, key: str, vector: list[float]) -> None: ...


# -- Question Embedder --------------------------------------------------------


class QuestionEmbedder:
    """Preprocesses questions and generates cached, L2-normalized embeddings.

    Usage:
        expander = TerminologyExpander()
        embedder = QuestionEmbedder(
            embedding_client=voyage_client,
            cache=redis_cache,
            terminology_expander=expander,
        )

        vector = await embedder.embed("Show BP readings for patient")
    """

    def __init__(
        self,
        embedding_client: EmbeddingClient,
        cache: EmbeddingCache,
        terminology_expander: TerminologyExpander | None = None,
    ) -> None:
        self._client = embedding_client
        self._cache = cache
        self._expander = terminology_expander or TerminologyExpander()

    def preprocess(self, question: str) -> str:
        """Full preprocessing pipeline (no security context appended).

        Steps:
        1. Normalize whitespace
        2. Expand abbreviations

        Returns the preprocessed question text ready for embedding.
        """
        text = question.strip()

        # Normalize whitespace
        text = _normalize_whitespace(text)

        # Expand abbreviations
        text = self._expander.expand(text)

        return text

    def compute_cache_key(self, preprocessed_text: str) -> str:
        """SHA-256 hash of preprocessed question + model version for cache key."""
        model = self._client.model_name
        dims = self._client.dimensions
        raw = f"{preprocessed_text}|{model}|v{dims}"
        return hashlib.sha256(raw.encode()).hexdigest()

    async def embed(self, question: str) -> list[float]:
        """Full embedding pipeline: preprocess -> cache check -> embed -> normalize -> cache store.

        Args:
            question: The raw natural-language question.

        Returns:
            L2-normalized embedding vector.

        Raises:
            RuntimeError: If embedding generation fails.
        """
        preprocessed = self.preprocess(question)
        cache_key = self.compute_cache_key(preprocessed)

        # Check cache
        cached = await self._cache.get_embedding(cache_key)
        if cached is not None:
            logger.debug("embedding_cache_hit", key=cache_key[:12])
            return cached

        # Generate embedding
        start = time.monotonic()
        try:
            raw_vector = await self._client.embed(preprocessed)
        except Exception as exc:
            logger.error("embedding_generation_failed", error=str(exc))
            raise RuntimeError(f"Embedding generation failed: {exc}") from exc

        elapsed_ms = (time.monotonic() - start) * 1000

        # L2 normalize
        vector = _l2_normalize(raw_vector)

        logger.info(
            "embedding_generated",
            latency_ms=round(elapsed_ms, 2),
            dimensions=len(vector),
            cache_key=cache_key[:12],
        )

        # Store in cache
        await self._cache.set_embedding(cache_key, vector)

        return vector

    async def embed_with_metadata(
        self, question: str
    ) -> tuple[str, list[float], bool]:
        """Embed with full metadata returned.

        Returns:
            (preprocessed_question, embedding_vector, cache_hit)
        """
        preprocessed = self.preprocess(question)
        cache_key = self.compute_cache_key(preprocessed)

        cached = await self._cache.get_embedding(cache_key)
        if cached is not None:
            return preprocessed, cached, True

        start = time.monotonic()
        try:
            raw_vector = await self._client.embed(preprocessed)
        except Exception as exc:
            raise RuntimeError(f"Embedding generation failed: {exc}") from exc

        vector = _l2_normalize(raw_vector)
        elapsed_ms = (time.monotonic() - start) * 1000

        logger.info("embedding_generated", latency_ms=round(elapsed_ms, 2))
        await self._cache.set_embedding(cache_key, vector)

        return preprocessed, vector, False


# -- Helpers ------------------------------------------------------------------


def _normalize_whitespace(text: str) -> str:
    """Collapse multiple whitespace characters into single spaces."""
    return re.sub(r"\s+", " ", text).strip()


def _l2_normalize(vector: list[float]) -> list[float]:
    """L2-normalize a vector to unit length.

    Returns the original vector if the norm is zero (avoids division by zero).
    """
    norm = math.sqrt(sum(x * x for x in vector))
    if norm == 0.0:
        return vector
    return [x / norm for x in vector]
