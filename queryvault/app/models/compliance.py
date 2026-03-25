"""Compliance and audit models for QueryVault.

Supports regulatory reporting (HIPAA, 42 CFR Part 2, SOX, GDPR, EU AI Act,
ISO 42001) and provides the immutable audit event structure used for
hash-chain integrity verification across the entire pipeline.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from queryvault.app.models.enums import ComplianceStandard, Severity


# -- Compliance Report ---------------------------------------------------------


class ControlResult(BaseModel):
    """Result of evaluating a single compliance control.

    Each control maps to a specific regulatory requirement and is assessed
    against the audit trail for the reporting period.
    """

    control_id: str = Field(
        ...,
        description="Unique control identifier (e.g. 'HIPAA-164.312(a)(1)').",
    )
    control_name: str = Field(
        ...,
        description="Human-readable name of the control.",
    )
    status: str = Field(
        ...,
        description="Evaluation outcome: PASS, FAIL, PARTIAL, or NOT_APPLICABLE.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence items supporting the status determination.",
    )
    remediation: str = Field(
        default="",
        description="Recommended remediation steps if the control failed.",
    )


class ComplianceReport(BaseModel):
    """Full compliance report for a given regulatory standard.

    Generated on demand or on a schedule by the L8 compliance engine,
    covering a specified time range of audit events.
    """

    standard: ComplianceStandard = Field(
        ...,
        description="Regulatory standard this report covers.",
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Overall compliance score (0.0 = non-compliant, 1.0 = fully compliant).",
    )
    controls: list[ControlResult] = Field(
        default_factory=list,
        description="Individual control evaluation results.",
    )
    generated_at: datetime = Field(
        ...,
        description="Timestamp when the report was generated.",
    )
    time_range_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Number of days of audit data analysed.",
    )


# -- Audit Event ---------------------------------------------------------------


class AuditEvent(BaseModel):
    """Immutable audit event emitted by every security zone.

    Forms the backbone of the hash-chain audit trail.  Each event is
    HMAC-signed at the source layer and verified upon ingestion by L8.
    The chain_hash field links each event to its predecessor, enabling
    tamper detection.
    """

    event_id: str = Field(
        ...,
        description="Unique event identifier (UUID).",
    )
    event_type: str = Field(
        ...,
        description="Event type descriptor (e.g. 'QUERY_RECEIVED', 'VALIDATION_BLOCKED').",
    )
    source_zone: str = Field(
        ...,
        description="Security zone or layer that emitted this event (e.g. 'L1', 'L6', 'PRE_MODEL').",
    )
    timestamp: datetime = Field(
        ...,
        description="When the event occurred.",
    )
    request_id: str = Field(
        ...,
        description="Correlation ID linking all events for a single gateway request.",
    )
    user_id: str = Field(
        ...,
        description="User who triggered the event.",
    )
    severity: Severity = Field(
        default=Severity.INFO,
        description="Event severity level.",
    )
    btg_active: bool = Field(
        default=False,
        description="True if Break-the-Glass mode was active when this event occurred.",
    )
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific structured data.",
    )
    chain_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash linking this event to its predecessor in the audit chain.",
    )
