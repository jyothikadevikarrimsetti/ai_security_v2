"""Threat classification and behavioral analysis models for QueryVault.

These models capture the output of the Adaptive Query Defence (AQD) system
that runs in the PRE_MODEL security zone.  Three signal sources feed into
the final ThreatClassification:

  1. InjectionScanResult  -- pattern-based injection detection (AQD-001)
  2. ProbingSignal        -- schema enumeration / reconnaissance detection (AQD-002)
  3. BehavioralScore      -- per-user behavioral baseline deviation (AQD-003)

Additional models:
  - BehavioralProfile       -- Redis-stored per-user profile (AQD-003)
  - InjectionAnalysisResult -- post-LLM SQL analysis (AQD-004)
  - Pattern                 -- attack pattern entry (AQD-007)
  - AnomalyAlert            -- alerts from L8 continuous monitoring
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Optional

from pydantic import BaseModel, Field

from queryvault.app.models.enums import (
    AlertStatus,
    Severity,
    ThreatCategory,
    ThreatLevel,
)


# -- Injection Scan Result (AQD-001) ------------------------------------------


class InjectionScanResult(BaseModel):
    """Result from the injection scanner.

    Analyses the raw natural-language question for SQL injection patterns,
    prompt injection attempts, and encoded attack payloads.
    """

    is_blocked: bool = Field(
        default=False,
        description="True if the scanner determined the query should be blocked.",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Injection risk score (0.0 = safe, 1.0 = certain attack).",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Category flags for detected risks (e.g. OVERRIDE_ATTEMPT).",
    )
    matched_patterns: list[str] = Field(
        default_factory=list,
        description="Snippet excerpts of injection patterns that matched.",
    )
    sanitized_text: str = Field(
        default="",
        description="Input text with dangerous patterns redacted.",
    )


# -- Probing Signal (AQD-002) -------------------------------------------------


class ProbingSignal(BaseModel):
    """Schema-probing detection signal.

    Detects reconnaissance behaviour such as systematic enumeration of
    table names, column names, or database metadata.
    """

    is_probing: bool = Field(
        default=False,
        description="True if probing intensity exceeded the threshold.",
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Probing confidence score.",
    )
    recent_probing_count: int = Field(
        default=0,
        description="Number of probing queries in the current sliding window.",
    )
    patterns_detected: list[str] = Field(
        default_factory=list,
        description="Probing pattern names detected in the query.",
    )


# -- Behavioral Score (AQD-003) ------------------------------------------------


class BehavioralScore(BaseModel):
    """Behavioral fingerprint deviation score.

    Compares the current request against the user's established query
    fingerprint to detect anomalous access patterns.
    """

    anomaly_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Deviation from the user's behavioral baseline (0.0 = normal).",
    )
    is_anomalous: bool = Field(
        default=False,
        description="True if anomaly_score exceeds the configured threshold.",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Anomaly indicators (e.g. off_hours_access, volume_spike).",
    )
    first_time_tables: list[str] = Field(
        default_factory=list,
        description="Tables accessed for the first time by this user.",
    )
    baseline_query_rate: float = Field(
        default=0.0,
        description="User's established average queries per day.",
    )
    current_query_rate: float = Field(
        default=0.0,
        description="Current effective query rate.",
    )


# -- Behavioral Profile (AQD-003, Redis-stored) --------------------------------


class BehavioralProfile(BaseModel):
    """Per-user behavioral profile stored in Redis with rolling TTL."""

    user_id: str
    tables_accessed: dict[str, int] = Field(default_factory=dict)
    domains_accessed: dict[str, int] = Field(default_factory=dict)
    query_count_30d: int = 0
    avg_queries_per_day: float = 0.0
    typical_hours: list[int] = Field(default_factory=list)
    denial_count: int = 0
    last_active: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# -- Injection Analysis Result (AQD-004, post-LLM) ----------------------------


class InjectionAnalysisResult(BaseModel):
    """Result from post-LLM SQL injection analysis."""

    is_safe: bool = Field(
        default=True,
        description="True if the generated SQL passed all safety rules.",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="SQL injection risk score.",
    )
    threats: list[str] = Field(
        default_factory=list,
        description="Human-readable threat descriptions.",
    )
    matched_rules: list[str] = Field(
        default_factory=list,
        description="Rule identifiers that fired.",
    )
    sanitized_sql: str = Field(
        default="",
        description="SQL with dangerous constructs neutralized.",
    )


# -- Threat Classification (AQD-006) ------------------------------------------


class ThreatClassification(BaseModel):
    """Combined threat classification from all AQD signals.

    Merges injection, probing, and behavioral signals into a single
    threat verdict used by the gateway to decide whether to proceed.
    """

    level: ThreatLevel = Field(
        default=ThreatLevel.NONE,
        description="Overall threat level.",
    )
    category: Optional[ThreatCategory] = Field(
        default=None,
        description="Primary threat category (None if no threat detected).",
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Weighted composite score from all signals.",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons for the classification.",
    )
    should_block: bool = Field(
        default=False,
        description="True if the combined signals warrant blocking the request.",
    )

    # Component signals
    injection: InjectionScanResult = Field(default_factory=InjectionScanResult)
    probing: ProbingSignal = Field(default_factory=ProbingSignal)
    behavioral: BehavioralScore = Field(default_factory=BehavioralScore)


# -- Pattern (AQD-007) --------------------------------------------------------


class Pattern(BaseModel):
    """Single attack pattern entry for the versioned pattern library."""

    id: str
    category: str
    pattern: str
    description: str = ""
    severity_weight: float = Field(0.5, ge=0.0, le=1.0)
    enabled: bool = True


# -- Anomaly Alert (L8 continuous monitoring) ----------------------------------


class AnomalyAlert(BaseModel):
    """Alert raised by the L8 anomaly detection engine.

    Represents a deduplicated, lifecycle-managed alert that may span
    multiple contributing audit events.
    """

    alert_id: str = Field(
        ...,
        description="Unique alert identifier.",
    )
    anomaly_type: str = Field(
        ...,
        description="Type of anomaly (e.g. VOLUME, TEMPORAL, BEHAVIORAL, BTG_ABUSE).",
    )
    severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Alert severity level.",
    )
    user_id: str = Field(
        ...,
        description="User whose behaviour triggered the alert.",
    )
    description: str = Field(
        default="",
        description="Human-readable description of the anomaly.",
    )
    event_ids: list[str] = Field(
        default_factory=list,
        description="Audit event IDs that contributed to this alert.",
    )
    status: AlertStatus = Field(
        default=AlertStatus.OPEN,
        description="Current lifecycle state of the alert.",
    )
    occurrence_count: int = Field(
        default=1,
        ge=1,
        description="Number of times this anomaly has been observed in the dedup window.",
    )
    dedup_key: str = Field(
        default="",
        description="Deduplication key (typically user_id + anomaly_type + time window).",
    )
