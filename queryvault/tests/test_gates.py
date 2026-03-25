"""Comprehensive tests for SAG (SQL Accuracy Guard) gates.

Tests cover:
  - Gate 1 (Structural): table/column authorization, subquery depth limits
  - Gate 2 (Classification): sensitivity vs clearance, Sensitivity-5 denial, PII masking
  - Gate 3 (Behavioral): write ops, UNION SELECT, system tables, dynamic SQL
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from queryvault.app.models.enums import (
    ClearanceLevel,
    Domain,
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
from queryvault.app.services.sag import (
    gate1_structural,
    gate2_classification,
    gate3_behavioral,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def basic_envelope() -> PermissionEnvelope:
    """Envelope granting access to 'patients' and 'visits' tables."""
    return PermissionEnvelope(
        table_permissions=[
            TablePermission(
                table_id="ehr.patients",
                table_name="patients",
                decision=PolicyDecision.ALLOW,
                columns=[
                    {"column_name": "patient_id", "visibility": "VISIBLE"},
                    {"column_name": "full_name", "visibility": "MASKED"},
                    {"column_name": "dob", "visibility": "VISIBLE"},
                    {"column_name": "ssn", "visibility": "HIDDEN"},
                ],
            ),
            TablePermission(
                table_id="ehr.visits",
                table_name="visits",
                decision=PolicyDecision.ALLOW,
                columns=[
                    {"column_name": "visit_id", "visibility": "VISIBLE"},
                    {"column_name": "patient_id", "visibility": "VISIBLE"},
                    {"column_name": "visit_date", "visibility": "VISIBLE"},
                ],
            ),
        ],
        row_filters=[],
    )


@pytest.fixture
def security_context_clearance3() -> SecurityContext:
    """SecurityContext with clearance level 3 (Confidential)."""
    now = datetime.utcnow()
    return SecurityContext(
        ctx_id="ctx_test_001",
        identity=IdentityBlock(
            oid="user-001",
            name="Dr Test",
            email="test@hospital.org",
            jti="jti-001",
            mfa_verified=True,
        ),
        org_context=OrgContextBlock(
            employee_id="EMP001",
            department="Cardiology",
            facility_ids=["FAC01"],
        ),
        authorization=AuthorizationBlock(
            direct_roles=["physician"],
            effective_roles=["physician", "clinical_viewer"],
            domain=Domain.CLINICAL,
            clearance_level=ClearanceLevel.CONFIDENTIAL,
            sensitivity_cap=ClearanceLevel.CONFIDENTIAL,
        ),
        request_metadata=RequestMetadataBlock(
            ip_address="10.0.0.1",
            timestamp=now,
            session_id="sess-001",
        ),
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


@pytest.fixture
def security_context_clearance1() -> SecurityContext:
    """SecurityContext with clearance level 1 (Public)."""
    now = datetime.utcnow()
    return SecurityContext(
        ctx_id="ctx_test_low",
        identity=IdentityBlock(
            oid="user-low",
            name="Receptionist",
            email="front@hospital.org",
            jti="jti-low",
        ),
        org_context=OrgContextBlock(
            employee_id="EMP999",
            department="Front Desk",
            facility_ids=["FAC01"],
        ),
        authorization=AuthorizationBlock(
            direct_roles=["receptionist"],
            effective_roles=["receptionist"],
            domain=Domain.ADMINISTRATIVE,
            clearance_level=ClearanceLevel.PUBLIC,
            sensitivity_cap=ClearanceLevel.PUBLIC,
        ),
        request_metadata=RequestMetadataBlock(
            ip_address="10.0.0.2",
            timestamp=now,
            session_id="sess-low",
        ),
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


def _simple_select(tables, columns, **overrides):
    """Build a minimal parsed_sql dict for a simple SELECT."""
    parsed = {
        "tables": tables,
        "columns": columns,
        "select_columns": columns,
        "cte_names": [],
        "has_group_by": False,
        "has_where": False,
        "where_conditions": [],
        "subquery_depth": 0,
        "statement_count": 1,
        "has_write_ops": False,
        "is_select": True,
        "parse_error": None,
        "joins": [],
        "aggregate_columns": [],
    }
    parsed.update(overrides)
    return parsed


# ===================================================================
# Gate 1 -- Structural Validation
# ===================================================================

class TestGate1Structural:
    """Tests for gate1_structural.run()."""

    def test_authorized_table_passes(self, basic_envelope):
        """SQL referencing only authorized tables should pass."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "patient_id"), ("patients", "dob")],
        )
        result = gate1_structural.run(parsed, basic_envelope)
        assert result.passed is True
        assert len([v for v in result.violations if v.severity == "CRITICAL"]) == 0

    def test_unauthorized_table_blocked(self, basic_envelope):
        """SQL referencing a table not in the envelope should fail."""
        parsed = _simple_select(
            tables=["billing"],
            columns=[("billing", "amount")],
        )
        result = gate1_structural.run(parsed, basic_envelope)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "UNAUTHORIZED_TABLE" in violation_types

    def test_hidden_column_blocked(self, basic_envelope):
        """Accessing a HIDDEN column (ssn) must produce a violation."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "ssn")],
        )
        result = gate1_structural.run(parsed, basic_envelope)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "UNAUTHORIZED_COLUMN" in violation_types

    def test_visible_column_allowed(self, basic_envelope):
        """Accessing a VISIBLE column must pass."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "dob")],
        )
        result = gate1_structural.run(parsed, basic_envelope)
        assert result.passed is True

    def test_subquery_depth_exceeded(self, basic_envelope):
        """Subquery depth exceeding the limit produces a violation."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "patient_id")],
            subquery_depth=5,
        )
        result = gate1_structural.run(parsed, basic_envelope, max_subquery_depth=3)
        violation_types = [v.type for v in result.violations]
        assert "EXCESSIVE_SUBQUERY_DEPTH" in violation_types

    def test_subquery_depth_within_limit(self, basic_envelope):
        """Subquery depth within the limit should not produce a violation."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "patient_id")],
            subquery_depth=2,
        )
        result = gate1_structural.run(parsed, basic_envelope, max_subquery_depth=3)
        assert result.passed is True
        violation_types = [v.type for v in result.violations]
        assert "EXCESSIVE_SUBQUERY_DEPTH" not in violation_types

    def test_write_operation_flagged(self, basic_envelope):
        """Parsed SQL with has_write_ops=True must be flagged."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[],
            has_write_ops=True,
            is_select=False,
        )
        result = gate1_structural.run(parsed, basic_envelope)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "WRITE_OPERATION" in violation_types


# ===================================================================
# Gate 2 -- Data Classification
# ===================================================================

class TestGate2Classification:
    """Tests for gate2_classification.run()."""

    def test_sensitivity_within_clearance(
        self, basic_envelope, security_context_clearance3
    ):
        """Column with sensitivity <= clearance should pass."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "dob")],
        )
        # dob heuristic => sensitivity 3, user clearance 3
        result = gate2_classification.run(
            parsed, basic_envelope, security_context_clearance3,
        )
        assert result.passed is True

    def test_sensitivity_exceeds_clearance(
        self, basic_envelope, security_context_clearance1
    ):
        """Column sensitivity > user clearance should fail."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "dob")],
        )
        # dob heuristic => sensitivity 3, user clearance 1
        result = gate2_classification.run(
            parsed, basic_envelope, security_context_clearance1,
        )
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "SENSITIVITY_EXCEEDED" in violation_types

    def test_sensitivity5_always_denied(
        self, basic_envelope, security_context_clearance3
    ):
        """Sensitivity-5 columns (e.g. substance_abuse) are always denied."""
        envelope = PermissionEnvelope(
            table_permissions=[
                TablePermission(
                    table_id="ehr.behavioral",
                    table_name="behavioral",
                    decision=PolicyDecision.ALLOW,
                    columns=[
                        {"column_name": "substance_abuse", "visibility": "VISIBLE"},
                    ],
                ),
            ],
        )
        parsed = _simple_select(
            tables=["behavioral"],
            columns=[("behavioral", "substance_abuse")],
        )
        result = gate2_classification.run(
            parsed, envelope, security_context_clearance3,
        )
        assert result.passed is False
        descs = [v.description for v in result.violations]
        assert any("level 5" in d for d in descs)

    def test_pii_masking_compliance(
        self, basic_envelope, security_context_clearance3
    ):
        """A MASKED column in SELECT should produce an UNMASKED_PII_COLUMN warning."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "full_name")],
            select_columns=[("patients", "full_name")],
        )
        result = gate2_classification.run(
            parsed, basic_envelope, security_context_clearance3,
        )
        violation_types = [v.type for v in result.violations]
        assert "UNMASKED_PII_COLUMN" in violation_types
        # This is HIGH severity, not CRITICAL, so gate still passes
        assert result.passed is True


# ===================================================================
# Gate 3 -- Behavioral Analysis
# ===================================================================

class TestGate3Behavioral:
    """Tests for gate3_behavioral.run()."""

    def test_clean_select_passes(self):
        """A clean SELECT should pass gate 3."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "patient_id")],
        )
        raw_sql = "SELECT patient_id FROM patients WHERE facility_id = 'FAC01'"
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is True

    def test_insert_blocked(self):
        """INSERT INTO should be flagged as a write operation."""
        parsed = _simple_select(tables=[], columns=[], has_write_ops=True)
        raw_sql = "INSERT INTO patients (patient_id) VALUES ('X')"
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "WRITE_OPERATION" in violation_types

    def test_update_blocked(self):
        """UPDATE ... SET should be flagged."""
        parsed = _simple_select(tables=[], columns=[], has_write_ops=True)
        raw_sql = "UPDATE patients SET full_name = 'hacked' WHERE 1=1"
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is False
        assert any(v.type == "WRITE_OPERATION" for v in result.violations)

    def test_delete_blocked(self):
        """DELETE FROM should be flagged."""
        parsed = _simple_select(tables=[], columns=[], has_write_ops=True)
        raw_sql = "DELETE FROM patients WHERE patient_id = '123'"
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is False
        assert any(v.type == "WRITE_OPERATION" for v in result.violations)

    def test_union_select_blocked(self):
        """UNION SELECT should be flagged as exfiltration."""
        parsed = _simple_select(
            tables=["patients"],
            columns=[("patients", "patient_id")],
            has_union=True,
        )
        raw_sql = (
            "SELECT patient_id FROM patients "
            "UNION SELECT username FROM admin_users"
        )
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "UNION_EXFILTRATION" in violation_types

    def test_system_table_access_blocked(self):
        """Access to information_schema should be flagged."""
        parsed = _simple_select(
            tables=["information_schema.tables"],
            columns=[("information_schema.tables", "table_name")],
        )
        raw_sql = "SELECT table_name FROM information_schema.tables"
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "SYSTEM_TABLE_ACCESS" in violation_types

    def test_dynamic_sql_blocked(self):
        """Dynamic SQL via EXEC / sp_executesql should be flagged."""
        parsed = _simple_select(tables=[], columns=[])
        raw_sql = "EXEC sp_executesql N'SELECT * FROM patients'"
        result = gate3_behavioral.run(parsed, raw_sql)
        assert result.passed is False
        violation_types = [v.type for v in result.violations]
        assert "DYNAMIC_SQL" in violation_types

    def test_gate_result_has_latency(self):
        """GateResult should carry a non-negative latency_ms value."""
        parsed = _simple_select(tables=["t"], columns=[])
        result = gate3_behavioral.run(parsed, "SELECT 1")
        assert result.latency_ms >= 0
        assert result.gate_name == "gate3_behavioral"
