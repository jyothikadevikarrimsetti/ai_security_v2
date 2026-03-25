"""
session_store.py -- Redis Context & JTI Storage
================================================

Responsibilities:
  1. Store SecurityContext with TTL (keyed by ctx_id)
  2. Retrieve SecurityContext by ctx_id
  3. Delete / revoke SecurityContext
  4. JTI blacklist -- track revoked JWT IDs to prevent replay
  5. Auto-expire entries via Redis TTL

TTLs:
  Normal session  = 900 seconds  (15 min)
  BTG session     = 14400 seconds (4 hours)
  JTI blacklist   = 86400 seconds (24 hours)

Fallback:
  If Redis is unavailable, uses an in-memory dict with manual TTL checks.
  This keeps the service running in dev/test without Redis infrastructure.

All public methods are async to support non-blocking I/O in production.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Optional

from queryvault.app.models.security_context import SecurityContext

logger = logging.getLogger("queryvault.identity.session_store")


class SessionStore:
    """
    Redis-backed session store with in-memory fallback.

    Keys:
      zt:qv:ctx:{ctx_id}           -> serialised SecurityContext (TTL = context TTL)
      zt:qv:jti:blacklist:{jti}    -> "1" (TTL = token max lifetime)

    All public methods are async.
    """

    def __init__(
        self,
        *,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "zt:qv:",
        jti_blacklist_prefix: str = "zt:qv:jti:blacklist:",
    ):
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._jti_blacklist_prefix = jti_blacklist_prefix
        self._redis = None
        self._memory_store: dict[str, tuple[str, float]] = {}  # key -> (value, expire_at)
        self._init_redis()

    def _init_redis(self) -> None:
        """Try to connect to Redis.  Fall back silently to in-memory."""
        try:
            import redis as redis_lib
            self._redis = redis_lib.asyncio.Redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
            )
            logger.info("Redis async client created: %s", self._redis_url)
        except Exception as e:
            logger.warning("Redis unavailable (%s) -- using in-memory fallback", e)
            self._redis = None

    # ─────────────────────────────────────────────────────
    # LOW-LEVEL OPS (Redis or in-memory)
    # ─────────────────────────────────────────────────────

    async def _set(self, key: str, value: str, ttl_seconds: int) -> None:
        if self._redis:
            try:
                await self._redis.setex(key, ttl_seconds, value)
                return
            except Exception as e:
                logger.warning("Redis SET failed (%s) -- falling back to memory", e)
        self._memory_store[key] = (value, time.time() + ttl_seconds)

    async def _get(self, key: str) -> Optional[str]:
        if self._redis:
            try:
                return await self._redis.get(key)
            except Exception as e:
                logger.warning("Redis GET failed (%s) -- falling back to memory", e)
        entry = self._memory_store.get(key)
        if entry is None:
            return None
        value, expire_at = entry
        if time.time() > expire_at:
            del self._memory_store[key]
            return None
        return value

    async def _delete(self, key: str) -> bool:
        if self._redis:
            try:
                return bool(await self._redis.delete(key))
            except Exception as e:
                logger.warning("Redis DELETE failed (%s) -- falling back to memory", e)
        return self._memory_store.pop(key, None) is not None

    async def _exists(self, key: str) -> bool:
        if self._redis:
            try:
                return bool(await self._redis.exists(key))
            except Exception as e:
                logger.warning("Redis EXISTS failed (%s) -- falling back to memory", e)
        entry = self._memory_store.get(key)
        if entry is None:
            return False
        _, expire_at = entry
        if time.time() > expire_at:
            del self._memory_store[key]
            return False
        return True

    # ─────────────────────────────────────────────────────
    # SECURITY CONTEXT STORAGE
    # ─────────────────────────────────────────────────────

    def _ctx_key(self, ctx_id: str) -> str:
        return f"{self._key_prefix}ctx:{ctx_id}"

    @staticmethod
    def _serialize_context(ctx: SecurityContext) -> str:
        """Serialise a SecurityContext to JSON with datetime/enum handling."""
        def _default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):
                return obj.value
            raise TypeError(f"Not serialisable: {type(obj)}")
        return json.dumps(ctx.model_dump(), default=_default, sort_keys=True)

    async def store(self, ctx_id: str, context: SecurityContext, ttl: int = 900) -> None:
        """Store a SecurityContext with TTL."""
        key = self._ctx_key(ctx_id)
        value = self._serialize_context(context)
        await self._set(key, value, ttl)
        logger.info("Context stored | ctx_id=%s ttl=%ds", ctx_id, ttl)

    async def get(self, ctx_id: str) -> Optional[SecurityContext]:
        """Retrieve a SecurityContext by ctx_id.  Returns None if expired/missing."""
        key = self._ctx_key(ctx_id)
        raw = await self._get(key)
        if raw is None:
            logger.debug("Context not found: %s", ctx_id)
            return None

        try:
            data = json.loads(raw)
            return SecurityContext(**data)
        except Exception as e:
            logger.error("Failed to deserialise context %s: %s", ctx_id, e)
            return None

    async def delete(self, ctx_id: str) -> bool:
        """Delete a SecurityContext (revocation)."""
        key = self._ctx_key(ctx_id)
        deleted = await self._delete(key)
        logger.info("Context deleted | ctx_id=%s deleted=%s", ctx_id, deleted)
        return deleted

    # ─────────────────────────────────────────────────────
    # JTI BLACKLIST (token revocation)
    # ─────────────────────────────────────────────────────

    def _jti_key(self, jti: str) -> str:
        return f"{self._jti_blacklist_prefix}{jti}"

    async def blacklist_jti(self, jti: str, ttl: int = 86400) -> None:
        """Add a JWT ID to the blacklist.  TTL should match token max lifetime."""
        key = self._jti_key(jti)
        await self._set(key, "1", ttl)
        logger.info("JTI blacklisted | jti=%s ttl=%ds", jti, ttl)

    async def is_jti_blacklisted(self, jti: str) -> bool:
        """Check if a JWT ID has been revoked."""
        key = self._jti_key(jti)
        blacklisted = await self._exists(key)
        if blacklisted:
            logger.warning("Blacklisted JTI detected: %s", jti)
        return blacklisted
