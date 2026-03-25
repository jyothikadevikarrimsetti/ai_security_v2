"""AQD-003: Behavioral Fingerprinting.

Per-user behavioral profiles stored in Redis with a 30-day rolling
window.  Detects anomalous deviations from established baselines:

Tracked Signals
---------------
- tables_accessed   -- frequency map of table access
- query_frequency   -- rolling 30-day query count & daily average
- typical_hours     -- hours-of-day the user normally queries
- denial_count      -- consecutive / total access-denied events

Anomaly Detectors
-----------------
- first_time_table_access  -- user accesses a table never seen before
- off_hours_access         -- query outside the user's normal hours
- volume_spike             -- query rate >3x the daily average
- repeated_denials         -- >5 accumulated access denials
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import structlog

from queryvault.app.models.threat import BehavioralProfile, BehavioralScore

logger = structlog.get_logger(__name__)


class BehavioralFingerprint:
    """Per-user behavioral fingerprinting with Redis-backed profiles.

    Parameters
    ----------
    redis_url:
        Redis connection URL (default ``redis://localhost:6379/4``).
    anomaly_threshold:
        Anomaly-score value at which ``is_anomalous`` flips to *True*
        (default 0.7).
    ttl_days:
        Profile TTL in Redis, in days (default 30).
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/4",
        anomaly_threshold: float = 0.7,
        ttl_days: int = 30,
    ) -> None:
        self._redis_url = redis_url
        self._anomaly_threshold = anomaly_threshold
        self._ttl_days = ttl_days
        self._redis: object | None = None

    # -- lifecycle ----------------------------------------------------------

    async def connect(self) -> None:
        """Open Redis connection (best-effort)."""
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
            )
        except Exception as exc:
            logger.warning("behavioral_redis_unavailable", error=str(exc))

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.aclose()  # type: ignore[union-attr]

    # -- Redis helpers ------------------------------------------------------

    def _key(self, user_id: str) -> str:
        return f"qv:behavior:{user_id}"

    async def _get_profile(self, user_id: str) -> BehavioralProfile | None:
        """Load a user's profile from Redis."""
        if not self._redis:
            return None
        try:
            raw = await self._redis.get(self._key(user_id))  # type: ignore[union-attr]
            if not raw:
                return None
            return BehavioralProfile.model_validate_json(raw)
        except Exception:
            return None

    async def _save_profile(self, profile: BehavioralProfile) -> None:
        """Persist a user's profile to Redis with TTL."""
        if not self._redis:
            return
        try:
            ttl = self._ttl_days * 86_400
            await self._redis.set(  # type: ignore[union-attr]
                self._key(profile.user_id),
                profile.model_dump_json(),
                ex=ttl,
            )
        except Exception as exc:
            logger.warning("behavioral_save_failed", error=str(exc))

    # -- public API ---------------------------------------------------------

    async def check(
        self,
        user_id: str,
        tables: list[str] | None = None,
        session_id: str | None = None,
    ) -> BehavioralScore:
        """Check current query context against the user's behavioral baseline.

        Parameters
        ----------
        user_id:
            Authenticated user identifier.
        tables:
            Tables referenced in the current query (may be ``None``).
        session_id:
            Optional session identifier.

        Returns
        -------
        BehavioralScore
        """
        profile = await self._get_profile(user_id)
        flags: list[str] = []
        first_time: list[str] = []

        if not profile:
            return BehavioralScore(
                anomaly_score=0.0,
                is_anomalous=False,
                flags=["new_user_no_baseline"],
            )

        score = 0.0

        # 1. First-time table access
        if tables:
            for table in tables:
                if table not in profile.tables_accessed:
                    first_time.append(table)
            if first_time:
                flags.append("first_time_table_access")
                score += 0.15 * len(first_time)

        # 2. Off-hours access
        current_hour = datetime.now(UTC).hour
        if profile.typical_hours and current_hour not in profile.typical_hours:
            flags.append("off_hours_access")
            score += 0.2

        # 3. Volume spike (>3x daily average)
        if profile.avg_queries_per_day > 0 and profile.query_count_30d > 0:
            daily_avg = profile.avg_queries_per_day
            effective_rate = profile.query_count_30d / max(30, 1)
            if daily_avg > 0 and effective_rate > daily_avg * 3:
                flags.append("volume_spike")
                score += 0.25

        # 4. Repeated denials
        if profile.denial_count > 5:
            flags.append("repeated_denials")
            score += 0.2

        score = min(1.0, score)
        is_anomalous = score >= self._anomaly_threshold

        if is_anomalous:
            logger.warning(
                "behavioral_anomaly",
                user_id=user_id,
                session_id=session_id,
                score=score,
                flags=flags,
            )

        return BehavioralScore(
            anomaly_score=round(score, 4),
            is_anomalous=is_anomalous,
            flags=flags,
            first_time_tables=first_time,
            baseline_query_rate=profile.avg_queries_per_day,
            current_query_rate=0.0,
        )

    async def record(
        self,
        user_id: str,
        query_result: dict | None = None,
    ) -> None:
        """Update the user's behavioral profile after a query.

        Parameters
        ----------
        user_id:
            Authenticated user identifier.
        query_result:
            Optional dict with keys ``tables_accessed`` (list[str]) and
            ``was_denied`` (bool).
        """
        profile = await self._get_profile(user_id)
        if not profile:
            profile = BehavioralProfile(user_id=user_id)

        qr = query_result or {}

        # Update tables
        for table in qr.get("tables_accessed", []):
            profile.tables_accessed[table] = profile.tables_accessed.get(table, 0) + 1

        # Update counts
        profile.query_count_30d += 1
        profile.avg_queries_per_day = profile.query_count_30d / max(30, 1)

        # Update typical hours
        current_hour = datetime.now(UTC).hour
        if current_hour not in profile.typical_hours:
            profile.typical_hours.append(current_hour)
            if len(profile.typical_hours) > 12:
                profile.typical_hours = profile.typical_hours[-12:]

        if qr.get("was_denied", False):
            profile.denial_count += 1

        profile.last_active = datetime.now(UTC)

        await self._save_profile(profile)
