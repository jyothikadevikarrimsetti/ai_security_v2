"""API request and response models for the QueryVault Security Gateway.

These models define the public contract for the main gateway endpoint
(POST /api/v1/gateway/query) and the internal structures that carry
security metadata through all pipeline zones.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from queryvault.app.models.enums import GateResult, ThreatLevel


# -- Pre-Model Security Checks ------------------------------------------------


class PreModelChecks(BaseModel):
    """Aggregated results from the PRE_MODEL security zone.

    Captures injection scanning, schema-probing detection, and behavioral
    anomaly analysis performed before the NL-to-SQL model is invoked.
    """

    injection_blocked: bool = Field(
        default=False,
        description="True if the injection scanner blocked the query.",
    )
    injection_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Injection risk score (0.0 = safe, 1.0 = certain attack).",
    )
    injection_flags: list[str] = Field(
        default_factory=list,
        description="Human-readable flags raised by the injection scanner.",
    )
    probing_detected: bool = Field(
        default=False,
        description="True if schema-probing behaviour was detected.",
    )
    probing_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Schema-probing confidence score.",
    )
    behavioral_anomaly_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Deviation from the user's established behavioural baseline.",
    )
    behavioral_flags: list[str] = Field(
        default_factory=list,
        description="Behavioural anomaly indicators (e.g. first-time table, off-hours).",
    )
    threat_level: ThreatLevel = Field(
        default=ThreatLevel.NONE,
        description="Overall threat level assigned by the AQD classifier.",
    )
    threat_category: str | None = Field(
        default=None,
        description="Primary threat category if a threat was detected.",
    )


# -- Post-Model Security Checks -----------------------------------------------


class PostModelChecks(BaseModel):
    """Aggregated results from the POST_MODEL security zone.

    Contains SQL validation outcomes, hallucination detection results,
    gate verdicts, policy violations, and any SQL rewrites that were applied.
    """

    validation_decision: str = Field(
        default="",
        description="Final validation verdict: 'APPROVED' or 'BLOCKED'.",
    )
    hallucination_detected: bool = Field(
        default=False,
        description="True if the generated SQL references non-existent schema objects.",
    )
    hallucinated_identifiers: list[str] = Field(
        default_factory=list,
        description="Table or column names not present in the authorised schema.",
    )
    gate_results: dict[str, GateResult] = Field(
        default_factory=dict,
        description="Per-gate pass/fail/error outcomes from L6 multi-gate validation.",
    )
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Policy violations detected during validation.",
    )
    rewrites_applied: list[str] = Field(
        default_factory=list,
        description="Descriptions of SQL rewrites applied (masking, row filters, etc.).",
    )


# -- Execution Result ----------------------------------------------------------


class ExecutionResult(BaseModel):
    """Results from the EXECUTION security zone (L7).

    Contains the query output along with runtime guardrail metrics.
    """

    rows_returned: int = Field(
        default=0,
        ge=0,
        description="Number of rows returned by the executed SQL.",
    )
    execution_latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock execution time in milliseconds.",
    )
    sanitization_applied: bool = Field(
        default=False,
        description="True if output sanitisation was performed on the result set.",
    )
    resource_limits_hit: bool = Field(
        default=False,
        description="True if a row-cap or timeout limit was enforced.",
    )
    data: dict[str, Any] | None = Field(
        default=None,
        description="Query result payload (columns + rows).",
    )


# -- Security Summary ---------------------------------------------------------


class SecuritySummary(BaseModel):
    """Aggregated security metadata across all pipeline zones.

    Provides a single object that consumers can inspect to understand the
    overall security posture of a gateway request.
    """

    zones_passed: list[str] = Field(
        default_factory=list,
        description="Security zones the request successfully passed through.",
    )
    threat_level: ThreatLevel = Field(
        default=ThreatLevel.NONE,
        description="Highest threat level observed across all zones.",
    )
    validation_result: str = Field(
        default="",
        description="Final SQL validation decision (APPROVED / BLOCKED).",
    )
    execution_status: str = Field(
        default="",
        description="Execution outcome (e.g. 'SUCCESS', 'SKIPPED', 'ERROR').",
    )
    audit_trail_id: str = Field(
        default="",
        description="Unique identifier for the full audit trail of this request.",
    )
    pre_model: PreModelChecks = Field(
        default_factory=PreModelChecks,
        description="Detailed pre-model check results.",
    )
    post_model: PostModelChecks = Field(
        default_factory=PostModelChecks,
        description="Detailed post-model check results.",
    )
    execution: ExecutionResult | None = Field(
        default=None,
        description="Execution zone results (None if execution was not requested).",
    )


# -- Gateway Request / Response ------------------------------------------------


class GatewayQueryRequest(BaseModel):
    """POST /api/v1/gateway/query -- Main QueryVault security gateway endpoint.

    Accepts a natural-language question and a JWT, then routes the request
    through all security zones before returning validated (and optionally
    executed) SQL.
    """

    question: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        description="Natural-language question to be translated to SQL.",
    )
    jwt_token: str = Field(
        ...,
        min_length=10,
        description="Raw JWT for L1 identity resolution and RBAC derivation.",
    )

    @field_validator("question")
    @classmethod
    def strip_and_validate_question(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 3:
            raise ValueError("Question must be at least 3 characters after trimming.")
        return stripped


class GatewayQueryResponse(BaseModel):
    """Response from POST /api/v1/gateway/query.

    Contains the generated/validated SQL, optional execution results,
    a security summary spanning every zone, and an audit identifier.
    """

    request_id: str = Field(
        default="",
        description="Correlation ID for end-to-end tracing.",
    )
    sql: str | None = Field(
        default=None,
        description="Generated (or rewritten) SQL statement.",
    )
    results: dict[str, Any] | None = Field(
        default=None,
        description="Query execution results (present only when execution was requested).",
    )
    security_summary: SecuritySummary = Field(
        default_factory=SecuritySummary,
        description="Full security metadata from all pipeline zones.",
    )
    audit_id: str = Field(
        default="",
        description="Audit event identifier for this request.",
    )
    error: str | None = Field(
        default=None,
        description="Error message if the request could not be completed.",
    )
    blocked_reason: str | None = Field(
        default=None,
        description="Human-readable reason if the request was blocked by a security gate.",
    )
