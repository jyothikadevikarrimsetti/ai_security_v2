"""Retrieval Cache -- cache retrieval results by embedding fingerprint.

Redis-backed cache with configurable TTL (default 15 minutes).
Avoids repeated pgvector ANN scans and FK graph walks for identical
or near-identical queries.

XenSQL is a pure NL-to-SQL pipeline engine. No RBAC or clearance
scoping in cache keys -- the pipeline operates on whatever schema it receives.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Default TTL: 15 minutes
_DEFAULT_TTL_SECONDS = 900


class RetrievalCache:
    """Cache retrieval results by embedding fingerprint.

    Uses Redis as the backend. Falls back gracefully (returns cache miss)
    when Redis is unavailable.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        default_ttl: int = _DEFAULT_TTL_SECONDS,
        key_prefix: str = "xensql:retrieval:",
    ) -> None:
        self._redis_url = redis_url
        self._default_ttl = default_ttl
        self._key_prefix = key_prefix
        self._redis: Any | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Initialize async Redis connection."""
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            # Verify connectivity
            await self._redis.ping()
            logger.info("retrieval_cache_connected", url=self._redis_url)
        except Exception as exc:
            logger.warning(
                "retrieval_cache_connect_failed",
                error=str(exc),
                msg="Cache will operate in pass-through mode",
            )
            self._redis = None

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, cache_key: str) -> Any | None:
        """Retrieve cached result by key.

        Args:
            cache_key: Cache key (typically from compute_key()).

        Returns:
            Deserialized result, or None on cache miss / error.
        """
        if not self._redis:
            return None

        full_key = self._key_prefix + cache_key
        try:
            raw = await self._redis.get(full_key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:
            logger.debug("cache_get_failed", key=cache_key, error=str(exc))
            return None

    async def set(
        self,
        cache_key: str,
        result: Any,
        ttl: int | None = None,
    ) -> None:
        """Store a result in the cache.

        Args:
            cache_key: Cache key (typically from compute_key()).
            result: JSON-serializable result to cache.
            ttl: Time-to-live in seconds. Defaults to configured TTL.
        """
        if not self._redis:
            return

        full_key = self._key_prefix + cache_key
        effective_ttl = ttl if ttl is not None else self._default_ttl
        try:
            serialized = json.dumps(result, default=str)
            await self._redis.set(full_key, serialized, ex=effective_ttl)
        except Exception as exc:
            logger.debug("cache_set_failed", key=cache_key, error=str(exc))

    async def invalidate(self, cache_key: str) -> None:
        """Remove a specific key from the cache."""
        if not self._redis:
            return

        full_key = self._key_prefix + cache_key
        try:
            await self._redis.delete(full_key)
        except Exception as exc:
            logger.debug("cache_invalidate_failed", key=cache_key, error=str(exc))

    async def invalidate_pattern(self, pattern: str) -> int:
        """Remove all keys matching a glob pattern.

        Args:
            pattern: Glob pattern (e.g. "sem:*" to clear all semantic caches).

        Returns:
            Number of keys deleted.
        """
        if not self._redis:
            return 0

        full_pattern = self._key_prefix + pattern
        try:
            keys = []
            async for key in self._redis.scan_iter(match=full_pattern, count=100):
                keys.append(key)
            if keys:
                deleted = await self._redis.delete(*keys)
                logger.info("cache_pattern_invalidated", pattern=pattern, deleted=deleted)
                return deleted
            return 0
        except Exception as exc:
            logger.debug("cache_pattern_invalidate_failed", pattern=pattern, error=str(exc))
            return 0

    # ------------------------------------------------------------------
    # Key computation
    # ------------------------------------------------------------------

    @staticmethod
    def compute_key(
        embedding: list[float],
        params: dict[str, Any] | None = None,
    ) -> str:
        """Compute a deterministic cache key from an embedding and parameters.

        Uses a fingerprint of the first 16 embedding dimensions plus any
        additional parameters to produce a short, unique key.

        Args:
            embedding: Dense vector (only first 16 dims used for fingerprint).
            params: Optional dict of additional parameters to include in key
                    (e.g. top_k, intent, database_names).

        Returns:
            Hex string cache key.
        """
        # Embedding fingerprint from first 16 dimensions
        sig_parts = [str(v) for v in embedding[:16]]
        sig_data = "|".join(sig_parts).encode()

        # Include additional params if provided
        if params:
            param_str = json.dumps(params, sort_keys=True, default=str)
            sig_data += b"|" + param_str.encode()

        return hashlib.sha256(sig_data).hexdigest()[:24]

    # ------------------------------------------------------------------
    # Convenience: FK graph local cache
    # ------------------------------------------------------------------

    _fk_local_cache: dict[str, Any] = {}

    def get_fk_local(self, table_id: str) -> Any | None:
        """Get FK edges from in-memory local cache (non-async)."""
        return self._fk_local_cache.get(table_id)

    def set_fk_local(self, table_id: str, fks: Any) -> None:
        """Store FK edges in in-memory local cache (non-async)."""
        self._fk_local_cache[table_id] = fks

    def clear_fk_local(self) -> None:
        """Clear the in-memory FK cache."""
        self._fk_local_cache.clear()
