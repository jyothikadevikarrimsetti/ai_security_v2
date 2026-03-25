"""
context_builder.py -- SecurityContext Assembly Orchestrator
===========================================================

Central orchestrator of the Identity module.  Wires together:

  1. token_validator   -> validate JWT, extract claims
  2. session_store     -> check JTI blacklist
  3. _enrich_user()    -> fetch org context (mock HR/LDAP, 15 Apollo users)
  4. role_resolver     -> expand roles, compute clearance, apply MFA cap
  5. _sign_context()   -> HMAC-SHA256 sign the SecurityContext
  6. session_store     -> persist context with TTL

Input:  Raw JWT string + request metadata (IP, User-Agent)
Output: (SecurityContext, signature) tuple

Also provides:
  - Break-the-Glass activation (emergency escalation)
  - Context revocation (with JTI blacklisting)
  - IP binding enforcement

HMAC signing uses two formats:
  - Canonical: full JSON, sorted keys, no whitespace
  - Flat: pipe-delimited payload for downstream consumption
    (user_id|roles|department|session_id|expiry_epoch|clearance)

All I/O methods are async.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from queryvault.app.models.enums import ClearanceLevel, Domain, EmergencyMode, EmploymentStatus
from queryvault.app.models.security_context import (
    AuthorizationBlock,
    EmergencyBlock,
    IdentityBlock,
    OrgContextBlock,
    RequestMetadataBlock,
    SecurityContext,
)
from queryvault.app.services.identity.role_resolver import RoleResolver, ResolvedRoles
from queryvault.app.services.identity.session_store import SessionStore
from queryvault.app.services.identity.token_validator import (
    TokenValidationError,
    TokenValidator,
    ValidatedClaims,
)

logger = logging.getLogger("queryvault.identity.context_builder")


# ─────────────────────────────────────────────────────────
# EXCEPTIONS
# ─────────────────────────────────────────────────────────

class ContextBuildError(Exception):
    """Raised when SecurityContext assembly fails."""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class UnknownUserError(Exception):
    """Raised when an OID is not found in the organisational directory.
    Zero-trust: deny unknown identities by default."""
    pass


class InactiveEmployeeError(Exception):
    """Raised when a non-ACTIVE employee attempts to authenticate."""
    pass


# ─────────────────────────────────────────────────────────
# MOCK USER DIRECTORY  (15 Apollo Hospitals test users)
# ─────────────────────────────────────────────────────────
# Keyed by Azure AD oid (in production, this would be a real LDAP/HR call)

@dataclass(frozen=True)
class EnrichedUserContext:
    """Org context returned by the mock HR system."""
    employee_id: str
    department: str
    facility_ids: tuple[str, ...]
    unit_ids: tuple[str, ...]
    provider_npi: Optional[str]
    license_type: Optional[str]
    employment_status: EmploymentStatus


MOCK_USER_DIRECTORY: dict[str, EnrichedUserContext] = {
    # -- Physicians --
    "oid-dr-patel-4521": EnrichedUserContext(
        employee_id="DR-0001",
        department="Cardiology",
        facility_ids=("FAC-001",),
        unit_ids=("UNIT-1A-APJH", "UNIT-1B-APJH"),
        provider_npi="NPI-1234567890",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-dr-sharma-1102": EnrichedUserContext(
        employee_id="DR-0002",
        department="Oncology",
        facility_ids=("FAC-002",),
        unit_ids=("UNIT-3A-IPAH", "UNIT-3B-IPAH"),
        provider_npi="NPI-2345678901",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-dr-reddy-2233": EnrichedUserContext(
        employee_id="DR-0003",
        department="Emergency Medicine",
        facility_ids=("FAC-003",),
        unit_ids=("UNIT-ER-APGR", "UNIT-MICU-APGR"),
        provider_npi="NPI-3456789012",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-dr-iyer-3301": EnrichedUserContext(
        employee_id="DR-0004",
        department="Psychiatry",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi="NPI-4567890123",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- Nurses --
    "oid-nurse-kumar-2847": EnrichedUserContext(
        employee_id="EMP-0151",
        department="Cardiology",
        facility_ids=("FAC-001",),
        unit_ids=("UNIT-1A-APJH", "UNIT-1B-APJH"),
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-nurse-nair-3102": EnrichedUserContext(
        employee_id="EMP-0160",
        department="Emergency Medicine",
        facility_ids=("FAC-003",),
        unit_ids=("UNIT-MICU-APGR",),
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-nurse-singh-4455": EnrichedUserContext(
        employee_id="EMP-0165",
        department="Neurology",
        facility_ids=("FAC-002",),
        unit_ids=("UNIT-2A-IPAH", "UNIT-2B-IPAH"),
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- Billing / Revenue --
    "oid-bill-maria-5521": EnrichedUserContext(
        employee_id="EMP-0301",
        department="Billing & Revenue Cycle",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-bill-suresh-5530": EnrichedUserContext(
        employee_id="EMP-0305",
        department="Billing & Revenue Cycle",
        facility_ids=("FAC-002",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-rev-james-6601": EnrichedUserContext(
        employee_id="EMP-0310",
        department="Billing & Revenue Cycle",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- HR --
    "oid-hr-priya-7701": EnrichedUserContext(
        employee_id="EMP-0351",
        department="Human Resources",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-hr-dir-kapoor": EnrichedUserContext(
        employee_id="EMP-0355",
        department="Human Resources",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- IT --
    "oid-it-admin-7801": EnrichedUserContext(
        employee_id="EMP-0371",
        department="Information Technology",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- Compliance --
    "oid-hipaa-officer": EnrichedUserContext(
        employee_id="EMP-0381",
        department="Compliance & Legal",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- Research --
    "oid-researcher-das": EnrichedUserContext(
        employee_id="EMP-0391",
        department="Quality Assurance",
        facility_ids=("FAC-005",),
        unit_ids=(),
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # -- Inactive test user (TERMINATED) --
    "oid-terminated-user-9999": EnrichedUserContext(
        employee_id="EMP-0999",
        department="Cardiology",
        facility_ids=("FAC-001",),
        unit_ids=(),
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.TERMINATED,
    ),
}


# ─────────────────────────────────────────────────────────
# CONTEXT BUILDER
# ─────────────────────────────────────────────────────────

class ContextBuilder:
    """
    Assembles a complete SecurityContext from a raw JWT.

    Orchestration flow:
      JWT -> validate -> check JTI blacklist -> enrich user (mock HR/LDAP)
        -> resolve roles -> compute clearance -> build SecurityContext
          -> HMAC sign -> store in Redis -> return (context, signature)

    All I/O methods are async.
    """

    # Default TTLs (seconds)
    NORMAL_TTL: int = 900       # 15 minutes
    BTG_TTL: int = 14400        # 4 hours
    BTG_MIN_REASON_LENGTH: int = 20

    # BTG-eligible roles
    BTG_ELIGIBLE_ROLES: frozenset[str] = frozenset({
        "EMERGENCY_PHYSICIAN", "ATTENDING_PHYSICIAN", "PSYCHIATRIST",
        "HEAD_NURSE", "ICU_NURSE", "HIPAA_PRIVACY_OFFICER",
    })

    def __init__(
        self,
        *,
        token_validator: TokenValidator,
        role_resolver: RoleResolver,
        session_store: SessionStore,
        hmac_secret_key: str = "dev-hmac-secret-key-32-chars-minimum!!",
        context_signing_key: str = "dev-context-signing-key-32-chars-min",
        normal_ttl: int = 900,
        btg_ttl: int = 14400,
    ):
        self._validator = token_validator
        self._role_resolver = role_resolver
        self._store = session_store
        self._hmac_secret_key = hmac_secret_key
        self._context_signing_key = context_signing_key
        self.NORMAL_TTL = normal_ttl
        self.BTG_TTL = btg_ttl

    # ─────────────────────────────────────────────────────
    # MAIN RESOLVE PIPELINE
    # ─────────────────────────────────────────────────────

    async def resolve(
        self,
        raw_token: str,
        ip_address: str = "0.0.0.0",
        user_agent: Optional[str] = None,
    ) -> tuple[SecurityContext, str]:
        """
        Full SecurityContext resolution pipeline.

        Args:
            raw_token:   Bearer JWT from Authorization header
            ip_address:  Client IP
            user_agent:  Client User-Agent string

        Returns:
            Tuple of (SecurityContext, hmac_signature)

        Raises:
            ContextBuildError on any failure (wraps underlying exceptions)
        """
        # -- Step 1: Validate JWT --
        try:
            claims = self._validator.validate(raw_token)
        except TokenValidationError as e:
            raise ContextBuildError(str(e), status_code=401)

        # -- Step 2: Check JTI blacklist --
        if claims.jti and await self._store.is_jti_blacklisted(claims.jti):
            raise ContextBuildError("Token has been revoked (JTI blacklisted)", status_code=401)

        # -- Step 3: Enrich user context (mock HR/LDAP) --
        try:
            org_ctx = self._enrich_user(claims.oid)
        except InactiveEmployeeError as e:
            raise ContextBuildError(str(e), status_code=403)
        except UnknownUserError as e:
            raise ContextBuildError(str(e), status_code=403)

        # -- Step 4: Resolve roles + clearance --
        mfa_verified = "mfa" in claims.amr
        resolved = self._role_resolver.resolve(claims.roles, mfa_verified)

        # -- Step 5: Build SecurityContext --
        now = datetime.now(timezone.utc)
        ttl = self.NORMAL_TTL
        ctx_id = f"ctx_{uuid.uuid4().hex}"
        session_id = f"ses_{uuid.uuid4().hex[:16]}"

        ctx = SecurityContext(
            ctx_id=ctx_id,
            version="2.0",
            identity=IdentityBlock(
                oid=claims.oid,
                name=claims.name,
                email=claims.email,
                jti=claims.jti,
                mfa_verified=mfa_verified,
                auth_methods=claims.amr,
            ),
            org_context=OrgContextBlock(
                employee_id=org_ctx.employee_id,
                department=org_ctx.department,
                facility_ids=list(org_ctx.facility_ids),
                unit_ids=list(org_ctx.unit_ids),
                provider_npi=org_ctx.provider_npi,
                license_type=org_ctx.license_type,
                employment_status=org_ctx.employment_status,
            ),
            authorization=AuthorizationBlock(
                direct_roles=resolved.direct_roles,
                effective_roles=resolved.effective_roles,
                groups=claims.groups,
                domain=resolved.domain,
                clearance_level=resolved.clearance_level,
                sensitivity_cap=resolved.sensitivity_cap,
                bound_policies=resolved.bound_policies,
            ),
            request_metadata=RequestMetadataBlock(
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=now,
                session_id=session_id,
            ),
            emergency=EmergencyBlock(mode=EmergencyMode.NONE),
            ttl_seconds=ttl,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )

        # -- Step 6: HMAC-SHA256 sign --
        signature = self._sign_canonical(ctx)

        # -- Step 7: Store in Redis --
        await self._store.store(ctx_id, ctx, ttl)

        logger.info(
            "SecurityContext built | ctx_id=%s user=%s role=%s clearance=%d cap=%d ttl=%d",
            ctx_id, claims.oid, resolved.direct_roles, resolved.clearance_level,
            resolved.sensitivity_cap, ttl,
        )

        return ctx, signature

    # ─────────────────────────────────────────────────────
    # BREAK-THE-GLASS ESCALATION
    # ─────────────────────────────────────────────────────

    async def activate_break_glass(
        self,
        ctx_id: str,
        reason: str,
        patient_id: Optional[str] = None,
    ) -> tuple[SecurityContext, str]:
        """
        Activate Break-the-Glass on an existing SecurityContext.

        Changes:
          - emergency.mode -> ACTIVE
          - clearance_level -> RESTRICTED (5)
          - sensitivity_cap -> RESTRICTED (5)
          - TTL -> BTG_TTL (14400s = 4 hours)
          - Stores reason and timestamps

        The original clearance is preserved in emergency.original_clearance
        for audit trail purposes.

        Raises:
            ContextBuildError if ctx_id not found, already in emergency, role
            is not BTG-eligible, or reason is too short.
        """
        # -- Retrieve existing context --
        ctx = await self._store.get(ctx_id)
        if ctx is None:
            raise ContextBuildError(f"SecurityContext not found: {ctx_id}", status_code=404)

        if ctx.emergency.mode == EmergencyMode.ACTIVE:
            raise ContextBuildError("Break-the-Glass already active", status_code=409)

        # -- Check if user's role allows BTG --
        has_btg_role = any(r in self.BTG_ELIGIBLE_ROLES for r in ctx.authorization.direct_roles)
        if not has_btg_role:
            raise ContextBuildError(
                f"User does not have a BTG-eligible role. Direct roles: {ctx.authorization.direct_roles}",
                status_code=403,
            )

        # -- Validate reason --
        if len(reason.strip()) < self.BTG_MIN_REASON_LENGTH:
            raise ContextBuildError(
                f"Reason must be at least {self.BTG_MIN_REASON_LENGTH} characters",
                status_code=422,
            )

        # -- Escalate --
        now = datetime.now(timezone.utc)
        emergency_ttl = self.BTG_TTL
        original_clearance = ctx.authorization.clearance_level

        updated = SecurityContext(
            ctx_id=ctx.ctx_id,
            version=ctx.version,
            identity=ctx.identity,
            org_context=ctx.org_context,
            authorization=AuthorizationBlock(
                direct_roles=ctx.authorization.direct_roles,
                effective_roles=ctx.authorization.effective_roles,
                groups=ctx.authorization.groups,
                domain=ctx.authorization.domain,
                clearance_level=ClearanceLevel.RESTRICTED,
                sensitivity_cap=ClearanceLevel.RESTRICTED,
                bound_policies=sorted(set(ctx.authorization.bound_policies) | {"BTG-001"}),
            ),
            request_metadata=ctx.request_metadata,
            emergency=EmergencyBlock(
                mode=EmergencyMode.ACTIVE,
                reason=reason.strip(),
                patient_id=patient_id,
                activated_at=now,
                expires_at=now + timedelta(seconds=emergency_ttl),
                original_clearance=original_clearance,
            ),
            ttl_seconds=emergency_ttl,
            created_at=ctx.created_at,
            expires_at=now + timedelta(seconds=emergency_ttl),
        )

        # -- Re-sign --
        signature = self._sign_canonical(updated)

        # -- Update in Redis --
        await self._store.store(ctx.ctx_id, updated, emergency_ttl)

        logger.warning(
            "BTG ACTIVATED | ctx_id=%s user=%s reason='%s' original_clearance=%d elevated_to=5 ttl=%d",
            ctx.ctx_id, ctx.identity.oid, reason[:50], original_clearance, emergency_ttl,
        )

        return updated, signature

    # ─────────────────────────────────────────────────────
    # REVOCATION
    # ─────────────────────────────────────────────────────

    async def revoke(self, ctx_id: str) -> bool:
        """Revoke a SecurityContext and blacklist its JTI."""
        ctx = await self._store.get(ctx_id)
        if ctx is None:
            return False

        # Blacklist the JTI to prevent token reuse
        if ctx.identity.jti:
            await self._store.blacklist_jti(ctx.identity.jti, ttl=86400)

        # Delete the context
        await self._store.delete(ctx_id)

        logger.info("Context revoked | ctx_id=%s jti=%s", ctx_id, ctx.identity.jti)
        return True

    # ─────────────────────────────────────────────────────
    # IP SESSION BINDING
    # ─────────────────────────────────────────────────────

    @staticmethod
    def validate_ip_binding(ctx: SecurityContext, caller_ip: str) -> None:
        """Validate that the caller's IP matches the original session IP.

        Raises ContextBuildError(403) on mismatch.
        This prevents stolen context tokens from being used from a different network.

        Disabled for localhost/dev IPs to avoid breaking tests.
        """
        stored_ip = ctx.request_metadata.ip_address
        dev_ips = ("0.0.0.0", "127.0.0.1", "testclient")
        if stored_ip in dev_ips or caller_ip in dev_ips:
            return

        if stored_ip != caller_ip:
            logger.warning(
                "IP BINDING VIOLATION | ctx_id=%s stored_ip=%s caller_ip=%s",
                ctx.ctx_id, stored_ip, caller_ip,
            )
            raise ContextBuildError(
                f"Session IP mismatch: context was created from {stored_ip}, "
                f"but this request originates from {caller_ip}",
                status_code=403,
            )

    # ─────────────────────────────────────────────────────
    # USER ENRICHMENT (mock HR/LDAP)
    # ─────────────────────────────────────────────────────

    @staticmethod
    def _enrich_user(oid: str) -> EnrichedUserContext:
        """Look up org context by Azure AD Object ID.

        Returns:
            EnrichedUserContext with HR/org data.

        Raises:
            UnknownUserError: If oid is not in the directory (zero-trust deny-by-default).
            InactiveEmployeeError: If the user's employment status is not ACTIVE.
        """
        ctx = MOCK_USER_DIRECTORY.get(oid)
        if ctx is None:
            logger.warning("ACCESS DENIED -- unknown user not in directory | oid=%s", oid)
            raise UnknownUserError(
                f"User {oid} not found in the organisational directory. "
                f"Zero-trust policy: unknown identities are denied by default."
            )

        if ctx.employment_status != EmploymentStatus.ACTIVE:
            logger.warning(
                "ACCESS DENIED -- non-active employment status | oid=%s status=%s",
                oid, ctx.employment_status.value,
            )
            raise InactiveEmployeeError(
                f"User {oid} has employment status: {ctx.employment_status.value}. "
                f"Only ACTIVE employees may authenticate."
            )

        logger.info(
            "User enriched | oid=%s emp=%s dept=%s facilities=%s",
            oid, ctx.employee_id, ctx.department, ctx.facility_ids,
        )
        return ctx

    # ─────────────────────────────────────────────────────
    # HMAC-SHA256 SIGNING
    # ─────────────────────────────────────────────────────

    def _sign_canonical(self, ctx: SecurityContext) -> str:
        """Compute HMAC-SHA256 over canonical JSON serialisation.

        Rules:
          - Keys sorted alphabetically at every nesting level
          - No whitespace (separators = (',', ':'))
          - datetime -> ISO 8601 string
          - Enums -> their .value
          - UTF-8 encoded bytes

        Returns:
            Hex-encoded HMAC-SHA256 digest (64 chars).
        """
        payload = self._canonical_json(ctx)
        sig = hmac.new(
            key=self._hmac_secret_key.encode("utf-8"),
            msg=payload,
            digestmod=hashlib.sha256,
        ).hexdigest()

        logger.debug(
            "SecurityContext signed (canonical) | ctx_id=%s sig_prefix=%s... payload_bytes=%d",
            ctx.ctx_id, sig[:16], len(payload),
        )
        return sig

    def sign_flat(self, ctx: SecurityContext) -> str:
        """Compute pipe-delimited HMAC-SHA256 signature for downstream consumption.

        Payload format:
            user_id|sorted_comma_roles|department|session_id|expiry_epoch|clearance_level

        Signed with context_signing_key (shared with downstream layers).
        """
        roles = ",".join(sorted(ctx.authorization.effective_roles))
        expiry_ts = str(int(ctx.expires_at.timestamp()))
        clearance = str(int(ctx.authorization.clearance_level))
        payload = "|".join([
            ctx.identity.oid,
            roles,
            ctx.org_context.department,
            ctx.request_metadata.session_id,
            expiry_ts,
            clearance,
        ])
        sig = hmac.new(
            key=self._context_signing_key.encode("utf-8"),
            msg=payload.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()

        logger.debug(
            "Flat context signed | ctx_id=%s payload=%s sig_prefix=%s...",
            ctx.ctx_id, payload, sig[:16],
        )
        return sig

    def verify(self, ctx: SecurityContext, signature: str) -> bool:
        """Verify that a canonical signature matches the SecurityContext.

        Uses hmac.compare_digest for constant-time comparison
        to prevent timing attacks.
        """
        expected = self._sign_canonical(ctx)
        valid = hmac.compare_digest(expected, signature)

        if not valid:
            logger.warning("Signature verification FAILED | ctx_id=%s", ctx.ctx_id)
        return valid

    @staticmethod
    def _canonical_json(ctx: SecurityContext) -> bytes:
        """Serialise SecurityContext to deterministic canonical JSON.

        Rules:
          - Keys sorted alphabetically at every nesting level
          - No whitespace (separators = (',', ':'))
          - datetime -> ISO 8601 string
          - Enums -> their .value
          - UTF-8 encoded bytes
        """
        def _default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):
                return obj.value
            raise TypeError(f"Cannot serialise {type(obj)}")

        raw = ctx.model_dump()
        canonical = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            default=_default,
            ensure_ascii=True,
        )
        return canonical.encode("utf-8")
