"""Intent classification models for XenSQL NL-to-SQL Pipeline Engine."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from xensql.app.models.enums import DomainType, IntentType


class IntentResult(BaseModel):
    """Output of the intent classification stage.

    Captures the primary intent, confidence, and any supporting signals
    that downstream stages (prompt assembly, SQL generation) can use.
    """

    model_config = ConfigDict(frozen=True)

    intent: IntentType
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    matched_keywords: list[str] = Field(default_factory=list)
    domain_hints: list[DomainType] = Field(default_factory=list)
    secondary_intents: list[IntentType] = Field(
        default_factory=list,
        description="Additional intents that scored above threshold",
    )
