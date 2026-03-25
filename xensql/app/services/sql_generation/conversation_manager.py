"""SG-004: Conversation Manager -- multi-turn follow-up support.

Stores conversation history in Redis, enriches follow-up questions with
prior context (e.g. 'show that by month' references the previous query),
and manages the context window (max N turns).
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from xensql.app.models.conversation import ConversationContext, ConversationTurn

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Follow-up detection
# ---------------------------------------------------------------------------

# Pronouns and phrases that indicate the question references a prior turn
_FOLLOW_UP_PATTERNS = re.compile(
    r"\b("
    r"that|those|these|it|them|"
    r"the same|the previous|the above|the last|"
    r"break .* down|drill .* down|"
    r"show .* by|group .* by|filter .* to|"
    r"same .* but|now show|also show|and also|"
    r"instead of|rather than|"
    r"add .* to|remove .* from|"
    r"what about|how about|"
    r"can you also|now include|exclude"
    r")\b",
    re.IGNORECASE,
)


class ConversationManager:
    """Manages multi-turn conversation state backed by Redis.

    Provides context retrieval, turn recording, and question enrichment.
    No user identity tracking -- that stays in QueryVault.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        max_turns: int = 10,
        ttl_seconds: int = 3600,
    ) -> None:
        self._redis_url = redis_url
        self._max_turns = max_turns
        self._ttl = ttl_seconds
        self._redis: Any = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish connection to Redis for session storage."""
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url, decode_responses=True
            )
            await self._redis.ping()
            logger.info("conversation_redis_connected")
        except Exception as exc:
            logger.warning("conversation_redis_unavailable", error=str(exc))
            self._redis = None

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    # ------------------------------------------------------------------
    # Context retrieval
    # ------------------------------------------------------------------

    async def get_context(self, session_id: str) -> ConversationContext | None:
        """Retrieve conversation context for a session from Redis.

        Args:
            session_id: Unique session identifier.

        Returns:
            ConversationContext if found, None otherwise.
        """
        if not self._redis or not session_id:
            return None

        try:
            raw = await self._redis.get(self._key(session_id))
            if not raw:
                return None
            return ConversationContext.model_validate_json(raw)
        except Exception as exc:
            logger.warning(
                "conversation_load_failed",
                session_id=session_id,
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------
    # Turn recording
    # ------------------------------------------------------------------

    async def record_turn(
        self,
        session_id: str,
        turn: ConversationTurn,
    ) -> None:
        """Record a completed turn in the conversation session.

        Appends the turn to the session context, trims to max_turns,
        and persists to Redis with TTL.

        Args:
            session_id: Unique session identifier.
            turn: The completed conversation turn to record.
        """
        if not self._redis or not session_id:
            return

        try:
            ctx = await self.get_context(session_id)
            if not ctx:
                ctx = ConversationContext(
                    session_id=session_id, max_turns=self._max_turns
                )

            # Append and trim to context window
            ctx.turns.append(turn)
            if len(ctx.turns) > self._max_turns:
                ctx.turns = ctx.turns[-self._max_turns :]

            await self._redis.set(
                self._key(session_id),
                ctx.model_dump_json(),
                ex=self._ttl,
            )
            logger.debug(
                "conversation_turn_recorded",
                session_id=session_id,
                turn_count=len(ctx.turns),
            )
        except Exception as exc:
            logger.warning(
                "conversation_save_failed",
                session_id=session_id,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Question enrichment
    # ------------------------------------------------------------------

    def enrich_question(
        self,
        question: str,
        context: ConversationContext | None,
    ) -> str:
        """Enrich a follow-up question with prior conversation context.

        If the question contains follow-up patterns (pronouns, references)
        and prior context exists, prepends context from recent turns so the
        LLM can resolve references like 'show that by month'.

        Args:
            question: The current user question.
            context: Prior conversation context (may be None).

        Returns:
            The enriched question string. Returns the original question
            unchanged if no enrichment is needed.
        """
        is_follow_up = bool(_FOLLOW_UP_PATTERNS.search(question))

        if not is_follow_up or not context or not context.turns:
            return question

        # Build context prefix from the last 3 turns
        recent = context.turns[-3:]
        context_parts: list[str] = []

        last = recent[-1]

        if last.tables_used:
            tables_str = ", ".join(last.tables_used)
            context_parts.append(f"[Previous query used tables: {tables_str}]")
        if last.sql:
            prev_sql = last.sql[:200]
            context_parts.append(f"[Previous SQL: {prev_sql}]")
        if last.question:
            context_parts.append(f"[Previous question: {last.question}]")

        if not context_parts:
            return question

        enriched = " ".join(context_parts) + " " + question
        logger.info(
            "question_enriched",
            original_len=len(question),
            enriched_len=len(enriched),
        )
        return enriched

    def is_follow_up(self, question: str) -> bool:
        """Check whether a question appears to reference prior context."""
        return bool(_FOLLOW_UP_PATTERNS.search(question))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key(self, session_id: str) -> str:
        return f"xensql:conv:{session_id}"
