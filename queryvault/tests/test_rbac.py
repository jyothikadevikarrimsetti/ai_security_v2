"""Tests for the RBAC & Zero Trust module.

Covers PolicyResolver, DomainFilter, ColumnScoper, RowFilter, and
BreakGlassManager with 15 test cases across deny-by-default, priority
conflict resolution, BTG override, domain filtering, column visibility,
row-filter injection, and break-glass lifecycle.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest

from queryvault.app.models.enums import (
    ClearanceLevel,
    ColumnVisibility,
    Domain,
    EmergencyMode,
    EmploymentStatus,
    PolicyDecision,
)
from queryvault.app.models.security_context import (
    AuthorizationBlock,
    EmergencyBlock,
    IdentityBlock,
    OrgContextBlock,
    PermissionEnvelope,
    RequestMetadataBlock,
    SecurityContext,
    TablePermission,
)
from queryvault.app.services.rbac.break_glass import BreakGlassManager
from queryvault.app.services.rbac.column_scoper import (
    ColumnInfo,
    ColumnPolicy,
    ColumnScoper,
    ColumnVisibility as CVis,
)
from queryvault.app.services.rbac.domain_filter import DomainFilter
from queryvault.app.services.rbac.policy_resolver import (
    ColumnMeta,
    ConditionNode,
    PolicyNode,
    PolicyResolver,
    TableMeta,
)
from queryvault.app.services.rbac.row_filter import RowFilter, RowFilterRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_security_context(
    *,
    roles: list[str] | None = None,
    clearance: ClearanceLevel = ClearanceLevel.CONFIDENTIAL,
    domain: Domain = Domain.CLINICAL,
    department: str = "Cardiology",
    facility_ids: list[str] | None = None,
    unit_ids: list[str] | None = None,
    provider_npi: str | None = "NPI-12345",
    btg_active: bool = False,
    btg_reason: str | None = None,
) -> SecurityContext:
    """Build a SecurityContext for testing with sensible defaults."""
    now = datetime.now(UTC)
    emergency_mode = EmergencyMode.ACTIVE if btg_active else EmergencyMode.NONE

    return SecurityContext(
        ctx_id="ctx_test_001",
        identity=IdentityBlock(
            oid="user-001",
            name="Dr. Test User",
            email="test@hospital.org",
            jti="jti-abc-123",
            mfa_verified=True,
        ),
        org_context=OrgContextBlock(
            employee_id="EMP-001",
            department=department,
            facility_ids=facility_ids or ["FAC-01", "FAC-02"],
            unit_ids=unit_ids or ["UNIT-A"],
            provider_npi=provider_npi,
        ),
        authorization=AuthorizationBlock(
            direct_roles=roles or ["attending_physician"],
            effective_roles=roles or ["attending_physician"],
            domain=domain,
            clearance_level=clearance,
            sensitivity_cap=clearance,
        ),
        request_metadata=RequestMetadataBlock(
            ip_address="10.0.0.1",
            timestamp=now,
            session_id="sess-test-001",
        ),
        emergency=EmergencyBlock(
            mode=emergency_mode,
            reason=btg_reason if btg_active else None,
            activated_at=now if btg_active else None,
            expires_at=(now + timedelta(hours=4)) if btg_active else None,
        ),
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


def _make_emergency_ctx(btg_active: bool = False) -> Any:
    """Return a lightweight emergency-block-like object with btg_active."""

    class _EmergencyProxy:
        def __init__(self, active: bool) -> None:
            self.btg_active = active
            self.mode = EmergencyMode.ACTIVE if active else EmergencyMode.NONE
            self.reason = "Emergency" if active else None

    return _EmergencyProxy(btg_active)


class _ContextProxy:
    """Lightweight stand-in for SecurityContext that exposes btg_active on
    the emergency block (which the real model does not have as a direct
    attribute).  Used only for PolicyResolver tests that need to call
    ``resolve()`` end-to-end.
    """

    def __init__(self, ctx: SecurityContext, btg: bool = False) -> None:
        self.identity = ctx.identity
        self.org_context = ctx.org_context
        self.authorization = ctx.authorization
        self.request_metadata = ctx.request_metadata
        self.emergency = _make_emergency_ctx(btg)
        self.context_id = ctx.ctx_id
        self.ctx_id = ctx.ctx_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def physician_ctx() -> SecurityContext:
    """A physician with CLINICAL domain, clearance 3."""
    return _make_security_context(
        roles=["attending_physician"],
        clearance=ClearanceLevel.CONFIDENTIAL,
        domain=Domain.CLINICAL,
    )


@pytest.fixture
def nurse_ctx() -> SecurityContext:
    """A nurse with CLINICAL domain, clearance 2."""
    return _make_security_context(
        roles=["nurse"],
        clearance=ClearanceLevel.INTERNAL,
        domain=Domain.CLINICAL,
        provider_npi=None,
    )


@pytest.fixture
def admin_ctx() -> SecurityContext:
    """An admin user with broad domain access."""
    return _make_security_context(
        roles=["admin"],
        clearance=ClearanceLevel.HIGHLY_CONFIDENTIAL,
        domain=Domain.ADMINISTRATIVE,
    )


@pytest.fixture
def researcher_ctx() -> SecurityContext:
    """A researcher limited to RESEARCH domain."""
    return _make_security_context(
        roles=["researcher"],
        clearance=ClearanceLevel.INTERNAL,
        domain=Domain.RESEARCH,
        provider_npi=None,
    )


# ---------------------------------------------------------------------------
# 1. PolicyResolver -- deny-by-default
# ---------------------------------------------------------------------------


class TestPolicyResolverDenyByDefault:
    """No policies on a table must result in DENY."""

    def test_no_policies_returns_deny(self):
        """Table with zero policies is denied (deny-by-default invariant)."""
        meta = TableMeta(
            table_id="ehr.encounters",
            table_name="encounters",
            sensitivity_level=2,
        )
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        decision, active, reason = resolver._resolve_table_conflict(meta)

        assert decision == PolicyDecision.DENY
        assert active == []
        assert "deny by default" in reason.lower()

    def test_only_deny_policy_returns_deny(self):
        """A single DENY policy must result in DENY."""
        meta = TableMeta(
            table_id="ehr.encounters",
            table_name="encounters",
            sensitivity_level=2,
            table_policies=[
                PolicyNode(policy_id="pol-deny-1", effect="DENY", priority=100),
            ],
        )
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        decision, active, reason = resolver._resolve_table_conflict(meta)

        assert decision == PolicyDecision.DENY
        assert len(active) == 1
        assert active[0].policy_id == "pol-deny-1"


# ---------------------------------------------------------------------------
# 2. PolicyResolver -- priority-based conflict resolution
# ---------------------------------------------------------------------------


class TestPolicyResolverPriorityConflict:
    """DENY beats ALLOW at equal priority; higher-priority grant wins."""

    def test_deny_wins_at_equal_priority(self):
        """When DENY and ALLOW share the same priority, DENY wins."""
        meta = TableMeta(
            table_id="ehr.patients",
            table_name="patients",
            sensitivity_level=2,
            table_policies=[
                PolicyNode(policy_id="pol-allow", effect="ALLOW", priority=100),
                PolicyNode(policy_id="pol-deny", effect="DENY", priority=100),
            ],
        )
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        decision, _, _ = resolver._resolve_table_conflict(meta)

        assert decision == PolicyDecision.DENY

    def test_higher_priority_allow_beats_lower_deny(self):
        """A higher-priority ALLOW overrides a lower-priority DENY."""
        meta = TableMeta(
            table_id="ehr.patients",
            table_name="patients",
            sensitivity_level=2,
            table_policies=[
                PolicyNode(policy_id="pol-deny", effect="DENY", priority=50),
                PolicyNode(policy_id="pol-allow", effect="ALLOW", priority=150),
            ],
        )
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        decision, active, _ = resolver._resolve_table_conflict(meta)

        assert decision == PolicyDecision.ALLOW
        assert any(p.policy_id == "pol-allow" for p in active)


# ---------------------------------------------------------------------------
# 3. PolicyResolver -- BTG override
# ---------------------------------------------------------------------------


class TestPolicyResolverBTGOverride:
    """BTG can override soft DENYs (priority < 200) but not hard DENYs."""

    def test_btg_overrides_soft_deny(self):
        """BTG flips a DENY with priority < 200 to ALLOW."""
        meta = TableMeta(
            table_id="ehr.encounters",
            table_name="encounters",
            sensitivity_level=3,
            table_policies=[
                PolicyNode(policy_id="pol-deny", effect="DENY", priority=100),
            ],
        )
        ctx = _make_security_context(btg_active=True, btg_reason="Emergency")
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        can_override = resolver._btg_can_override(
            "ehr.encounters", meta, ctx,
        )

        assert can_override is True

    def test_btg_cannot_override_hard_deny(self):
        """BTG must NOT override a hard DENY (priority >= 200)."""
        meta = TableMeta(
            table_id="ehr.encounters",
            table_name="encounters",
            sensitivity_level=3,
            table_policies=[
                PolicyNode(policy_id="pol-hard-deny", effect="DENY", priority=200),
            ],
        )
        ctx = _make_security_context(btg_active=True, btg_reason="Emergency")
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        can_override = resolver._btg_can_override(
            "ehr.encounters", meta, ctx,
        )

        assert can_override is False

    def test_btg_blocked_for_sensitivity5(self):
        """Sensitivity-5 tables are NEVER overridden, even under BTG."""
        meta = TableMeta(
            table_id="ehr.substance_abuse_records",
            table_name="substance_abuse_records",
            sensitivity_level=5,
            table_policies=[
                PolicyNode(policy_id="pol-deny", effect="DENY", priority=50),
            ],
        )
        ctx = _make_security_context(btg_active=True, btg_reason="Emergency")
        resolver = PolicyResolver(graph_client=None, signing_key="test")
        can_override = resolver._btg_can_override(
            "ehr.substance_abuse_records", meta, ctx,
        )

        assert can_override is False


# ---------------------------------------------------------------------------
# 4. DomainFilter -- role-to-domain mapping & silent denial
# ---------------------------------------------------------------------------


class TestDomainFilter:
    """DomainFilter silently drops tables outside the user's role-domains."""

    @pytest.mark.asyncio
    async def test_physician_sees_clinical_tables(self, physician_ctx):
        """Physician with CLINICAL role should see CLINICAL-domain tables."""
        df = DomainFilter()
        tables = [
            {"table_id": "ehr.patients", "domain": "CLINICAL"},
            {"table_id": "fin.invoices", "domain": "FINANCIAL"},
        ]
        result = await df.filter(tables, physician_ctx)

        assert len(result) == 1
        assert result[0]["table_id"] == "ehr.patients"

    @pytest.mark.asyncio
    async def test_admin_sees_multiple_domains(self, admin_ctx):
        """Admin role grants access to CLINICAL, ADMINISTRATIVE, FINANCIAL,
        and IT_OPERATIONS domains."""
        df = DomainFilter()
        tables = [
            {"table_id": "ehr.patients", "domain": "CLINICAL"},
            {"table_id": "hr.employees", "domain": "HR"},
            {"table_id": "fin.invoices", "domain": "FINANCIAL"},
            {"table_id": "ops.servers", "domain": "IT_OPERATIONS"},
        ]
        result = await df.filter(tables, admin_ctx)

        # Admin has CLINICAL, ADMINISTRATIVE, FINANCIAL, IT_OPERATIONS -- not HR
        allowed_ids = {t["table_id"] for t in result}
        assert "ehr.patients" in allowed_ids
        assert "fin.invoices" in allowed_ids
        assert "ops.servers" in allowed_ids
        assert "hr.employees" not in allowed_ids

    @pytest.mark.asyncio
    async def test_no_domain_tag_denied(self, physician_ctx):
        """Tables with no domain tag are silently denied (fail closed)."""
        df = DomainFilter()
        tables = [
            {"table_id": "misc.unknown_table", "domain": ""},
        ]
        result = await df.filter(tables, physician_ctx)

        assert result == []


# ---------------------------------------------------------------------------
# 5. ColumnScoper -- V/M/H/C visibility & PII defaults
# ---------------------------------------------------------------------------


class TestColumnScoper:
    """ColumnScoper assigns VISIBLE/MASKED/HIDDEN/COMPUTED per column."""

    @pytest.mark.asyncio
    async def test_pii_defaults_to_hidden(self):
        """PII column with no explicit policy defaults to HIDDEN."""
        scoper = ColumnScoper()
        columns = [
            ColumnInfo(name="patient_name", data_type="VARCHAR", is_pii=True),
            ColumnInfo(name="visit_date", data_type="DATE", is_pii=False),
        ]
        result = await scoper.scope(
            table="ehr.patients",
            columns=columns,
            policies=[],  # no explicit policies
            clearance=3,
        )

        assert result.hidden_count == 1
        assert len(result.visible) == 1
        assert result.visible[0].name == "visit_date"

    @pytest.mark.asyncio
    async def test_all_four_visibility_levels(self):
        """Explicit policies can set V, M, H, and C visibility states."""
        scoper = ColumnScoper()
        columns = [
            ColumnInfo(name="id", data_type="INT"),
            ColumnInfo(name="ssn", data_type="VARCHAR", is_pii=True),
            ColumnInfo(name="dob", data_type="DATE", is_pii=True),
            ColumnInfo(name="age_bucket", data_type="VARCHAR"),
        ]
        policies = [
            ColumnPolicy(column_name="id", visibility=ColumnVisibility.VISIBLE),
            ColumnPolicy(
                column_name="ssn",
                visibility=ColumnVisibility.MASKED,
                masking_expression="'***-**-' || RIGHT(ssn, 4)",
            ),
            ColumnPolicy(column_name="dob", visibility=ColumnVisibility.HIDDEN),
            ColumnPolicy(
                column_name="age_bucket",
                visibility=ColumnVisibility.COMPUTED,
                computed_expression="FLOOR(DATEDIFF(YEAR, dob, GETDATE()) / 10) * 10",
            ),
        ]
        result = await scoper.scope(
            table="ehr.patients",
            columns=columns,
            policies=policies,
            clearance=3,
        )

        # VISIBLE: id + age_bucket (COMPUTED goes into visible list)
        visible_names = {c.name for c in result.visible}
        assert "id" in visible_names
        assert "age_bucket" in visible_names

        # MASKED: ssn
        masked_names = {c.name for c in result.masked}
        assert "ssn" in masked_names
        assert result.masked[0].masking_expression == "'***-**-' || RIGHT(ssn, 4)"

        # HIDDEN: dob
        assert result.hidden_count == 1


# ---------------------------------------------------------------------------
# 6. RowFilter -- mandatory WHERE injection
# ---------------------------------------------------------------------------


class TestRowFilter:
    """RowFilter injects mandatory WHERE predicates based on role."""

    @pytest.mark.asyncio
    async def test_physician_gets_provider_filter(self, physician_ctx):
        """Attending physician must have provider_id = NPI filter."""
        rf = RowFilter()
        rules = await rf.get_filters(physician_ctx, table="ehr.encounters")

        assert len(rules) >= 1
        col_names = [r.column for r in rules]
        assert "provider_id" in col_names

    @pytest.mark.asyncio
    async def test_value_resolution_from_context(self, physician_ctx):
        """RowFilterRule resolves value from SecurityContext."""
        rule = RowFilterRule(
            column="provider_id",
            operator="=",
            value_source="security_context.org_context.provider_npi",
        )
        predicate = rule.to_sql_predicate(physician_ctx)

        assert "provider_id" in predicate
        assert "NPI-12345" in predicate

    @pytest.mark.asyncio
    async def test_missing_context_value_fails_closed(self):
        """When the context path resolves to None, the predicate fails closed."""
        ctx = _make_security_context(provider_npi=None)
        rule = RowFilterRule(
            column="provider_id",
            operator="=",
            value_source="security_context.org_context.provider_npi",
        )
        predicate = rule.to_sql_predicate(ctx)

        # Fail-closed: no rows should match
        assert "NULL" in predicate
        assert "FALSE" in predicate


# ---------------------------------------------------------------------------
# 7. BreakGlass -- activation, Sensitivity-5 block, mandatory reason
# ---------------------------------------------------------------------------


class TestBreakGlass:
    """BreakGlassManager lifecycle and invariants."""

    @pytest.mark.asyncio
    async def test_activation_returns_4hour_token(self):
        """Activation issues a token that expires in 4 hours."""
        mgr = BreakGlassManager()
        token = await mgr.activate(
            context_id="ctx_test_001",
            reason="Cardiac arrest -- emergency access required",
            patient_id="MRN-00042",
        )

        assert token.active is True
        assert token.reason == "Cardiac arrest -- emergency access required"
        assert token.patient_id == "MRN-00042"

        # Verify 4-hour window
        activated = datetime.fromisoformat(token.activated_at.rstrip("Z"))
        expires = datetime.fromisoformat(token.expires_at.rstrip("Z"))
        delta = expires - activated
        assert abs(delta.total_seconds() - 4 * 3600) < 5  # within 5 seconds tolerance

    @pytest.mark.asyncio
    async def test_sensitivity5_always_blocked(self):
        """Sensitivity-5 tables (42 CFR Part 2) remain blocked even under BTG."""
        mgr = BreakGlassManager()

        assert mgr.is_sensitivity5_blocked("ehr.substance_abuse") is True
        assert mgr.is_sensitivity5_blocked("ehr.psychotherapy_notes") is True
        assert mgr.is_sensitivity5_blocked("ehr.hiv_status_records") is True
        assert mgr.is_sensitivity5_blocked("ehr.genetic_testing_results") is True
        # Non-sensitive table should NOT be blocked
        assert mgr.is_sensitivity5_blocked("ehr.encounters") is False

    @pytest.mark.asyncio
    async def test_empty_reason_raises(self):
        """Activation without a reason must raise ValueError."""
        mgr = BreakGlassManager()

        with pytest.raises(ValueError, match="non-empty reason"):
            await mgr.activate(context_id="ctx_test", reason="")

        with pytest.raises(ValueError, match="non-empty reason"):
            await mgr.activate(context_id="ctx_test", reason="   ")
