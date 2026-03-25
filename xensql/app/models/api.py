"""API request and response models for XenSQL NL-to-SQL Pipeline Engine.

XenSQL receives pre-filtered schema from QueryVault and returns raw SQL.
No auth, RBAC, validation, execution, or audit concerns here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from xensql.app.models.enums import (
    AmbiguityType,
    ConfidenceLevel,
    PipelineErrorCode,
    PipelineStatus,
)


# -- Confidence ----------------------------------------------------------------


class ConfidenceBreakdown(BaseModel):
    """Detailed confidence score breakdown across pipeline stages."""

    model_config = ConfigDict()

    retrieval_score: float = Field(0.0, ge=0.0, le=1.0, description="Schema retrieval quality")
    intent_score: float = Field(0.0, ge=0.0, le=1.0, description="Intent classification confidence")
    generation_score: float = Field(0.0, ge=0.0, le=1.0, description="SQL generation quality signals")


class ConfidenceScore(BaseModel):
    """Composite confidence score for generated SQL."""

    model_config = ConfigDict()

    level: ConfidenceLevel = ConfidenceLevel.LOW
    score: float = Field(0.0, ge=0.0, le=1.0, description="Overall confidence 0.0-1.0")
    breakdown: ConfidenceBreakdown = Field(default_factory=ConfidenceBreakdown)
    flags: list[str] = Field(default_factory=list, description="Reasons affecting confidence")


# -- Ambiguity -----------------------------------------------------------------


class ClarificationOption(BaseModel):
    """A suggested clarification for an ambiguous question."""

    model_config = ConfigDict()

    label: str
    rephrased_question: str


class AmbiguityResult(BaseModel):
    """Result of ambiguity detection on the input question."""

    model_config = ConfigDict()

    is_ambiguous: bool = False
    ambiguity_type: AmbiguityType | None = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reason: str = ""
    clarifications: list[ClarificationOption] = Field(default_factory=list)


# -- Pipeline Metadata ---------------------------------------------------------


class PipelineMetadata(BaseModel):
    """Metadata from the pipeline execution for observability."""

    model_config = ConfigDict()

    generation_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    tables_used: int = 0
    intent: str = ""
    intent_confidence: float = 0.0
    llm_model: str = ""
    llm_provider: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    dialect: str = ""
    conversation_turn: int = 0


# -- Request / Response --------------------------------------------------------


class ConversationTurnInput(BaseModel):
    """A prior conversation turn provided by the caller."""

    model_config = ConfigDict(extra="ignore")

    question: str
    sql: str | None = None


class PipelineRequest(BaseModel):
    """POST /api/v1/pipeline/query -- main pipeline request.

    The caller (QueryVault) supplies the pre-filtered schema and any
    contextual rules. XenSQL never fetches schema on its own.
    """

    model_config = ConfigDict(extra="forbid")

    question: str = Field(..., min_length=3, max_length=2000)
    filtered_schema: dict[str, Any] = Field(
        ..., description="Pre-filtered schema payload from QueryVault"
    )
    contextual_rules: list[str] = Field(
        default_factory=list,
        description="Natural-language rules/constraints for SQL generation",
    )
    tenant_id: str = Field(
        default="", description="Tenant identifier passed through from QueryVault"
    )
    dialect_hint: str | None = Field(
        default=None, description="Optional SQL dialect preference"
    )
    session_id: str | None = Field(
        default=None, description="Session ID for multi-turn conversation"
    )
    conversation_history: list[ConversationTurnInput] = Field(
        default_factory=list, description="Prior Q&A turns in this session"
    )
    max_tables: int = Field(default=10, ge=1, le=25)
    provider_override: str | None = Field(
        default=None, description="Force a specific LLM provider name"
    )

    @field_validator("question")
    @classmethod
    def validate_question(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 3:
            raise ValueError("Question must be at least 3 characters")
        return stripped


class PipelineResponse(BaseModel):
    """Response from POST /api/v1/pipeline/query."""

    model_config = ConfigDict()

    request_id: str = ""
    status: PipelineStatus
    sql: str | None = None

    # Intelligence
    confidence: ConfidenceScore | None = None
    ambiguity: AmbiguityResult | None = None
    explanation: str = Field(
        default="", description="Human-readable explanation of the generated SQL"
    )

    # Metadata
    metadata: PipelineMetadata = Field(default_factory=PipelineMetadata)

    # Error info
    error: str | None = None
    error_code: PipelineErrorCode | None = None


# -- Provider listing ----------------------------------------------------------


class ProviderInfo(BaseModel):
    """Information about an available LLM provider."""

    model_config = ConfigDict()

    name: str
    model: str
    fallback_model: str = ""
    provider_type: str = ""
    is_available: bool = True


class ProvidersResponse(BaseModel):
    """Response from GET /api/v1/pipeline/providers."""

    model_config = ConfigDict()

    providers: list[ProviderInfo] = Field(default_factory=list)
    default_provider: str = ""


# -- Health --------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Response for /health endpoint."""

    model_config = ConfigDict()

    status: str = "ok"
    service: str = "xensql"
    version: str = "1.0.0"
    dependencies: dict[str, bool] = Field(default_factory=dict)
