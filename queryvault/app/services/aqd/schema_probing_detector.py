"""AQD-002: Schema Probing Detector.

Redis-backed sliding-window detection of systematic schema enumeration.
Monitors 8 probing patterns and returns a zero-signal on detection to
prevent information leakage.

Probing Patterns
----------------
1. table_enumeration     -- "list tables", "what tables"
2. column_discovery      -- "what columns in ..."
3. schema_metadata       -- "describe", "DDL", "schema"
4. information_schema    -- direct information_schema references
5. database_listing      -- "show databases", "list catalogs"
6. type_discovery        -- "what type is ...", "data type"
7. relationship_probing  -- "foreign key between ...", "joins"
8. sensitivity_probing   -- "sensitive", "PHI", "PII", "SSN"
"""

from __future__ import annotations

import re
import time

import structlog

from queryvault.app.models.threat import ProbingSignal

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Probing pattern definitions
# ---------------------------------------------------------------------------

_PROBING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("table_enumeration", re.compile(
        r"\b(what|which|list|show|get|give|enumerate|display|tell\s+me)\s+"
        r"(all\s+)?(the\s+)?(tables?|entities?|objects?|collections?|views?)\b",
        re.IGNORECASE,
    )),
    ("column_discovery", re.compile(
        r"\b(what|which|list|show|get|give|enumerate|describe)\s+"
        r"(all\s+)?(the\s+)?(columns?|fields?|attributes?|properties?)"
        r"\s+(are|does|in|of|for|from)\b",
        re.IGNORECASE,
    )),
    ("schema_metadata", re.compile(
        r"\b(schema|metadata|structure|definition|DDL|describe\s+table|explain\s+table)\b",
        re.IGNORECASE,
    )),
    ("information_schema", re.compile(
        r"\binformation_schema\b",
        re.IGNORECASE,
    )),
    ("database_listing", re.compile(
        r"\b(what|which|list|show|get|enumerate)\s+"
        r"(all\s+)?(the\s+)?(databases?|catalogs?|schemas?|namespaces?)\b",
        re.IGNORECASE,
    )),
    ("type_discovery", re.compile(
        r"\b(what\s+type|data\s*type|column\s+type|field\s+type)\b",
        re.IGNORECASE,
    )),
    ("relationship_probing", re.compile(
        r"\b(foreign\s+key|relationship|reference|join|connected\s+to|linked\s+to)"
        r"\b.*\b(between|from|to|with)\b",
        re.IGNORECASE,
    )),
    ("sensitivity_probing", re.compile(
        r"\b(sensitive|restricted|confidential|protected|PHI|PII|SSN|"
        r"social\s+security|credit\s+card|password|secret)\b",
        re.IGNORECASE,
    )),
]


class SchemaProbingDetector:
    """Detects schema enumeration via Redis-backed sliding-window tracking.

    Parameters
    ----------
    redis_url:
        Redis connection URL (default ``redis://localhost:6379/4``).
    window_seconds:
        Sliding window duration in seconds (default 300 = 5 min).
    threshold:
        Number of probing queries within the window that triggers
        a probing alert (default 5).
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/4",
        window_seconds: int = 300,
        threshold: int = 5,
    ) -> None:
        self._redis_url = redis_url
        self._window = window_seconds
        self._threshold = threshold
        self._redis: object | None = None

    # -- lifecycle ----------------------------------------------------------

    async def connect(self) -> None:
        """Open Redis connection (best-effort; degrades to stateless)."""
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
            )
        except Exception as exc:
            logger.warning("probing_detector_redis_unavailable", error=str(exc))

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()  # type: ignore[union-attr]

    # -- internals ----------------------------------------------------------

    def _detect_patterns(self, question: str) -> list[str]:
        """Return names of all probing patterns matched in *question*."""
        return [
            name for name, pattern in _PROBING_PATTERNS if pattern.search(question)
        ]

    # -- public API ---------------------------------------------------------

    async def check(
        self,
        question: str,
        user_id: str,
        session_id: str | None = None,
    ) -> ProbingSignal:
        """Check whether *question* is part of a schema probing sequence.

        When probing is detected the returned ``ProbingSignal`` carries a
        zero score on the *information* axis -- the caller should return an
        opaque refusal rather than any schema detail.

        Parameters
        ----------
        question:
            Raw user question.
        user_id:
            Authenticated user identifier.
        session_id:
            Optional session identifier for finer-grained tracking.

        Returns
        -------
        ProbingSignal
        """
        detected = self._detect_patterns(question)

        if not detected:
            return ProbingSignal(is_probing=False, score=0.0)

        # -- Stateless fallback when Redis is unavailable -------------------
        if not self._redis:
            score = min(1.0, len(detected) * 0.25)
            return ProbingSignal(
                is_probing=score >= 0.8,
                score=round(score, 4),
                recent_probing_count=len(detected),
                patterns_detected=detected,
            )

        # -- Redis sliding-window tracking ----------------------------------
        key = f"qv:probing:{user_id}"
        now = time.time()
        window_start = now - self._window

        try:
            pipe = self._redis.pipeline()  # type: ignore[union-attr]
            pipe.zadd(key, {f"{now}:{','.join(detected)}": now})
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            pipe.expire(key, int(self._window * 2))
            results = await pipe.execute()

            recent_count: int = results[2]
        except Exception as exc:
            logger.warning("probing_redis_error", error=str(exc))
            recent_count = len(detected)

        score = min(1.0, recent_count / max(self._threshold, 1))
        is_probing = recent_count >= self._threshold

        if is_probing:
            logger.warning(
                "schema_probing_detected",
                user_id=user_id,
                session_id=session_id,
                recent_count=recent_count,
                patterns=detected,
            )

        return ProbingSignal(
            is_probing=is_probing,
            score=round(score, 4),
            recent_probing_count=recent_count,
            patterns_detected=detected,
        )
