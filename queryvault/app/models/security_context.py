"""
SecurityContext -- Primary Identity Output
==========================================

The SecurityContext is the primary identity and authorisation object that
travels through every layer of the Zero Trust pipeline.  It is built by
the Identity module, cryptographically signed with HMAC-SHA256, cached
in Redis with a TTL, and consumed by all downstream layers.

Layout:
  identity          -- who is this user (JWT-verified claims)
  org_context       -- where do they sit in the organisation (HR/LDAP)
  authorization     -- what can they access (roles, clearance, policies)
  request_metadata  -- how/when/where did the request originate
  emergency         -- break-the-glass state

The PermissionEnvelope is the authoritative access-decision object produced
by the RBAC / Policy Resolution layer.  It defines per-table column
visibility, row filters, join restrictions, and NL rules.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from queryvault.app.models.enums import (
    ClearanceLevel,
    Domain,
    EmergencyMode,
    EmploymentStatus,
    PolicyDecision,
)


# ─────────────────────────────────────────────────────────
# IDENTITY BLOCK
# ─────────────────────────────────────────────────────────

class IdentityBlock(BaseModel):
    """JWT-verified identity claims extracted during L1 processing."""

    model_config = ConfigDict(frozen=True)

    oid: str = Field(
        ...,
        description="Azure AD Object ID (oid) or equivalent subject claim.",
    )
    name: str = Field(
        ...,
        description="Display name from the JWT.",
    )
    email: str = Field(
        ...,
        description="Email address (preferred_username or email claim).",
    )
    jti: str = Field(
        ...,
        description="JWT ID -- unique token identifier for replay detection.",
    )
    mfa_verified: bool = Field(
        default=False,
        description="True if multi-factor authentication was used.",
    )
    auth_methods: list[str] = Field(
        default_factory=list,
        description="Authentication method references (amr claim values).",
    )


# ─────────────────────────────────────────────────────────
# ORG CONTEXT BLOCK (from enrichment -- mock LDAP/HR)
# ─────────────────────────────────────────────────────────

class OrgContextBlock(BaseModel):
    """Organisational context enriched from HR/LDAP systems."""

    model_config = ConfigDict(frozen=True)

    employee_id: str = Field(
        ...,
        description="Internal employee identifier.",
    )
    department: str = Field(
        ...,
        description="Department or organisational unit.",
    )
    facility_ids: list[str] = Field(
        default_factory=list,
        description="Facility identifiers the user is associated with.",
    )
    unit_ids: list[str] = Field(
        default_factory=list,
        description="Unit identifiers within facilities.",
    )
    provider_npi: Optional[str] = Field(
        default=None,
        description="National Provider Identifier (clinical staff only).",
    )
    license_type: Optional[str] = Field(
        default=None,
        description="Medical license type (MD, RN, NP, etc.).",
    )
    employment_status: EmploymentStatus = EmploymentStatus.ACTIVE


# ─────────────────────────────────────────────────────────
# AUTHORIZATION BLOCK
# ─────────────────────────────────────────────────────────

class AuthorizationBlock(BaseModel):
    """Computed authorisation envelope derived from roles and policies."""

    model_config = ConfigDict(frozen=True)

    direct_roles: list[str] = Field(
        default_factory=list,
        description="Roles directly assigned via JWT or directory.",
    )
    effective_roles: list[str] = Field(
        default_factory=list,
        description="Expanded roles after inheritance resolution.",
    )
    groups: list[str] = Field(
        default_factory=list,
        description="Azure AD group memberships.",
    )
    domain: Domain = Field(
        ...,
        description="Primary data domain the user operates in.",
    )
    clearance_level: ClearanceLevel = Field(
        ...,
        description="Maximum data-sensitivity tier the user can access (1-5).",
    )
    sensitivity_cap: ClearanceLevel = Field(
        ...,
        description="Effective sensitivity cap (may be lower than clearance if MFA absent).",
    )
    bound_policies: list[str] = Field(
        default_factory=list,
        description="Policy IDs bound to this user's role set.",
    )


# ─────────────────────────────────────────────────────────
# REQUEST METADATA BLOCK
# ─────────────────────────────────────────────────────────

class RequestMetadataBlock(BaseModel):
    """Request origin and timing metadata."""

    model_config = ConfigDict(frozen=True)

    ip_address: str = Field(
        default="0.0.0.0",
        description="Client IP address.",
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="HTTP User-Agent header.",
    )
    timestamp: datetime = Field(
        ...,
        description="Timestamp when the request was received.",
    )
    session_id: str = Field(
        ...,
        description="Server-generated session identifier.",
    )


# ─────────────────────────────────────────────────────────
# EMERGENCY (BREAK-THE-GLASS) BLOCK
# ─────────────────────────────────────────────────────────

class EmergencyBlock(BaseModel):
    """Break-the-Glass (BTG) state for emergency access escalation."""

    model_config = ConfigDict(frozen=True)

    mode: EmergencyMode = EmergencyMode.NONE
    reason: Optional[str] = Field(
        default=None,
        description="Justification provided for BTG activation.",
    )
    patient_id: Optional[str] = Field(
        default=None,
        description="Patient ID that triggered BTG (for audit trail).",
    )
    activated_at: Optional[datetime] = Field(
        default=None,
        description="When BTG was activated.",
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="When BTG expires.",
    )
    original_clearance: Optional[ClearanceLevel] = Field(
        default=None,
        description="Clearance level before BTG escalation.",
    )


# ─────────────────────────────────────────────────────────
# FULL SECURITY CONTEXT
# ─────────────────────────────────────────────────────────

class SecurityContext(BaseModel):
    """The complete security context -- primary output of the Identity module.

    This immutable object is built by the identity layer, cryptographically
    signed, stored in Redis with a TTL, and consumed by every downstream
    layer on every NL-to-SQL request.

    Normal TTL  = 900 seconds  (15 minutes)
    BTG TTL     = 14400 seconds (4 hours)
    """

    model_config = ConfigDict(frozen=True)

    ctx_id: str = Field(
        ...,
        description="Unique context identifier (ctx_<uuid>).",
    )
    version: str = Field(
        default="2.0",
        description="SecurityContext schema version.",
    )
    identity: IdentityBlock = Field(
        ...,
        description="JWT-verified identity claims.",
    )
    org_context: OrgContextBlock = Field(
        ...,
        description="Organisational context from HR/LDAP enrichment.",
    )
    authorization: AuthorizationBlock = Field(
        ...,
        description="Computed authorisation envelope.",
    )
    request_metadata: RequestMetadataBlock = Field(
        ...,
        description="Request origin and timing metadata.",
    )
    emergency: EmergencyBlock = Field(
        default_factory=EmergencyBlock,
        description="Break-the-Glass emergency state.",
    )
    ttl_seconds: int = Field(
        default=900,
        description="Time-to-live in seconds.",
    )
    created_at: datetime = Field(
        ...,
        description="When this context was created.",
    )
    expires_at: datetime = Field(
        ...,
        description="When this context expires.",
    )


# ─────────────────────────────────────────────────────────
# PERMISSION ENVELOPE (from RBAC / Policy Resolution)
# ─────────────────────────────────────────────────────────

class TablePermission(BaseModel):
    """Per-table access permission resolved by the policy engine."""

    table_id: str = Field(
        ...,
        description="Unique table identifier from the knowledge graph.",
    )
    table_name: str = Field(
        default="",
        description="Human-readable table name.",
    )
    decision: PolicyDecision = Field(
        default=PolicyDecision.DENY,
        description="Access decision for this table.",
    )
    columns: list[dict] = Field(
        default_factory=list,
        description="Per-column visibility decisions.",
    )
    masking_rules: list[str] = Field(
        default_factory=list,
        description="Masking expressions to apply to sensitive columns.",
    )
    max_rows: Optional[int] = Field(
        default=None,
        description="Maximum number of rows the user may retrieve.",
    )
    aggregation_only: bool = Field(
        default=False,
        description="If True, only aggregate queries are permitted.",
    )


class PermissionEnvelope(BaseModel):
    """Authoritative access-decision envelope produced by the policy engine.

    Cryptographically signed with HMAC-SHA256 and has a strict TTL (60s).
    """

    table_permissions: list[TablePermission] = Field(
        default_factory=list,
        description="Per-table access permissions.",
    )
    row_filters: list[str] = Field(
        default_factory=list,
        description="Global row-level filter expressions.",
    )
    join_restrictions: list[dict] = Field(
        default_factory=list,
        description="Cross-domain join restrictions.",
    )
    nl_rules: list[str] = Field(
        default_factory=list,
        description="Natural-language rules injected into the LLM prompt.",
    )
    signature: str = Field(
        default="",
        description="HMAC-SHA256 signature for integrity verification.",
    )
    expires_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 expiry timestamp (resolved_at + 60s).",
    )
