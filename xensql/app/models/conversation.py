"""Multi-turn conversation context models for XenSQL Pipeline Engine."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class ConversationTurn(BaseModel):
    """A single Q&A turn in a conversation session."""

    model_config = ConfigDict(frozen=True)

    question: str
    sql: str | None = None
    tables_used: list[str] = Field(default_factory=list)
    intent: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ConversationContext(BaseModel):
    """Full conversation context for a pipeline session.

    Tracks prior turns so the LLM can resolve pronouns and follow-up
    questions. No user identity -- that stays in QueryVault.
    """

    model_config = ConfigDict()

    session_id: str
    turns: list[ConversationTurn] = Field(default_factory=list)
    max_turns: int = Field(
        default=10, ge=1, le=50,
        description="Maximum turns retained in context window",
    )

    @property
    def last_question(self) -> str | None:
        """Return the most recent question, or None if no turns."""
        return self.turns[-1].question if self.turns else None

    @property
    def last_sql(self) -> str | None:
        """Return the most recent SQL, or None if no turns."""
        return self.turns[-1].sql if self.turns else None

    @property
    def last_tables(self) -> list[str]:
        """Return tables used in the most recent turn."""
        return self.turns[-1].tables_used if self.turns else []
