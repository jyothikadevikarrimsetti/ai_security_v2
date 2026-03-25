"""Tests for the Compliance & Audit Engine (CAE).

Covers:
  - AuditStore: append, hash-chain integrity, immutability triggers, dedup window
  - ComplianceReporter: report generation for all 7 regulatory standards
  - AnomalyDetector: volume spike, temporal anomaly, validation block spike
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from queryvault.app.models.compliance import AuditEvent, ComplianceReport, ControlResult
from queryvault.app.models.enums import ComplianceStandard, Severity
from queryvault.app.services.compliance.audit_store import AuditStore
from queryvault.app.services.compliance.compliance_reporter import ComplianceReporter
from queryvault.app.services.compliance.anomaly_detector import AnomalyDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    *,
    event_id: str | None = None,
    event_type: str = "QUERY_RECEIVED",
    source_zone: str = "PRE_MODEL",
    user_id: str = "user-1",
    request_id: str | None = None,
    severity: Severity = Severity.INFO,
    btg_active: bool = False,
    payload: dict | None = None,
    timestamp: datetime | None = None,
) -> AuditEvent:
    """Create a minimal AuditEvent with sensible defaults."""
    return AuditEvent(
        event_id=event_id or str(uuid.uuid4()),
        event_type=event_type,
        source_zone=source_zone,
        timestamp=timestamp or datetime.now(timezone.utc),
        request_id=request_id or str(uuid.uuid4()),
        user_id=user_id,
        severity=severity,
        btg_active=btg_active,
        payload=payload or {},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path):
    """Yield a temporary database path inside a temp directory."""
    return str(tmp_path / "audit_test.db")


@pytest.fixture()
def audit_store(tmp_db):
    """Return an initialised AuditStore backed by a temp SQLite database."""
    store = AuditStore()
    asyncio.get_event_loop().run_until_complete(store.initialize(tmp_db))
    return store


@pytest.fixture()
def anomaly_detector():
    """Return a fresh AnomalyDetector with default thresholds."""
    return AnomalyDetector()


# ---------------------------------------------------------------------------
# AuditStore tests
# ---------------------------------------------------------------------------


class TestAuditStore:
    """Tests for the immutable, append-only hash-chain audit store."""

    @pytest.mark.asyncio
    async def test_append_and_query(self, audit_store: AuditStore):
        """Appending an event stores it and query retrieves it."""
        event = _make_event(user_id="doctor-a")
        stored = await audit_store.append(event)

        assert stored.chain_hash is not None
        assert len(stored.chain_hash) == 64  # SHA-256 hex digest

        events, total = await audit_store.query(limit=10)
        assert total == 1
        assert events[0].event_id == event.event_id

    @pytest.mark.asyncio
    async def test_hash_chain_integrity(self, audit_store: AuditStore):
        """Each event's hash depends on its predecessor -- chain must verify."""
        for i in range(5):
            await audit_store.append(
                _make_event(event_type=f"EVENT_{i}", source_zone="PRE_MODEL")
            )

        valid = await audit_store.verify_hash_chain()
        assert valid is True

    @pytest.mark.asyncio
    async def test_hash_chain_per_zone(self, audit_store: AuditStore):
        """Independent hash chains are maintained per source_zone."""
        for zone in ("PRE_MODEL", "POST_MODEL", "EXECUTION"):
            for _ in range(3):
                await audit_store.append(_make_event(source_zone=zone))

        assert await audit_store.verify_hash_chain(source_zone="PRE_MODEL") is True
        assert await audit_store.verify_hash_chain(source_zone="POST_MODEL") is True
        assert await audit_store.verify_hash_chain(source_zone="EXECUTION") is True
        # Full verification across all zones
        assert await audit_store.verify_hash_chain() is True

    @pytest.mark.asyncio
    async def test_immutability_rejects_update(self, audit_store: AuditStore):
        """Database triggers must reject UPDATE on audit_events."""
        event = _make_event()
        await audit_store.append(event)

        conn = audit_store._get_conn()
        with pytest.raises(Exception, match="TAMPER_ALERT"):
            conn.execute(
                "UPDATE audit_events SET user_id = 'hacker' WHERE event_id = ?",
                (event.event_id,),
            )

    @pytest.mark.asyncio
    async def test_immutability_rejects_delete(self, audit_store: AuditStore):
        """Database triggers must reject DELETE on audit_events."""
        event = _make_event()
        await audit_store.append(event)

        conn = audit_store._get_conn()
        with pytest.raises(Exception, match="TAMPER_ALERT"):
            conn.execute(
                "DELETE FROM audit_events WHERE event_id = ?",
                (event.event_id,),
            )

    @pytest.mark.asyncio
    async def test_dedup_within_window(self, audit_store: AuditStore):
        """Duplicate event_id within the 15-minute window is silently skipped."""
        fixed_id = str(uuid.uuid4())
        e1 = _make_event(event_id=fixed_id, event_type="FIRST")
        e2 = _make_event(event_id=fixed_id, event_type="DUPLICATE")

        await audit_store.append(e1)
        await audit_store.append(e2)  # Should be skipped

        events, total = await audit_store.query(limit=10)
        assert total == 1
        assert events[0].event_type == "FIRST"


# ---------------------------------------------------------------------------
# ComplianceReporter tests
# ---------------------------------------------------------------------------


class TestComplianceReporter:
    """Tests for the seven-framework compliance report generator."""

    @pytest.mark.asyncio
    async def test_generate_report_all_standards(self, audit_store: AuditStore):
        """A report can be generated for each of the 7 supported standards."""
        # Seed audit store with representative events so controls can evaluate
        event_types = [
            "AUTH_VERIFIED",
            "POLICY_EVALUATION",
            "MASKING_APPLIED",
            "VALIDATION_BLOCKED",
            "DISCLOSURE_LOGGED",
            "ANOMALY_DETECTED",
            "BTG_ACTIVATION",
        ]
        for etype in event_types:
            await audit_store.append(_make_event(event_type=etype))

        reporter = ComplianceReporter(audit_store)

        all_standards = [
            ComplianceStandard.HIPAA_PRIVACY,
            ComplianceStandard.HIPAA_SECURITY,
            ComplianceStandard.CFR42_PART2,
            ComplianceStandard.SOX,
            ComplianceStandard.GDPR,
            ComplianceStandard.EU_AI_ACT,
            ComplianceStandard.ISO_42001,
        ]

        for standard in all_standards:
            report = await reporter.generate(standard, time_range_days=30)

            assert isinstance(report, ComplianceReport)
            assert report.standard == standard
            assert 0.0 <= report.score <= 1.0
            assert len(report.controls) > 0
            assert report.time_range_days == 30
            assert report.generated_at is not None

    @pytest.mark.asyncio
    async def test_report_structure_and_control_results(self, audit_store: AuditStore):
        """Each control result has required fields and valid status values."""
        await audit_store.append(_make_event(event_type="AUTH_VERIFIED"))
        await audit_store.append(_make_event(event_type="POLICY_EVALUATION"))

        reporter = ComplianceReporter(audit_store)
        report = await reporter.generate(ComplianceStandard.HIPAA_SECURITY)

        for ctrl in report.controls:
            assert isinstance(ctrl, ControlResult)
            assert ctrl.control_id  # non-empty
            assert ctrl.control_name  # non-empty
            assert ctrl.status in ("PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE")
            assert isinstance(ctrl.evidence, list)
            assert isinstance(ctrl.remediation, str)

    @pytest.mark.asyncio
    async def test_report_score_reflects_pass_ratio(self, audit_store: AuditStore):
        """Score should equal the ratio of PASS controls to total controls."""
        # Seed with events that satisfy some but not all checks
        await audit_store.append(_make_event(event_type="AUTH_VERIFIED"))

        reporter = ComplianceReporter(audit_store)
        report = await reporter.generate(ComplianceStandard.HIPAA_SECURITY)

        passed = sum(1 for c in report.controls if c.status == "PASS")
        total = len(report.controls)
        expected_score = round(passed / max(total, 1), 3)
        assert report.score == expected_score


# ---------------------------------------------------------------------------
# AnomalyDetector tests
# ---------------------------------------------------------------------------


class TestAnomalyDetector:
    """Tests for the statistical and rule-based anomaly detection engine."""

    def test_temporal_anomaly_off_hours(self, anomaly_detector: AnomalyDetector):
        """An event outside work hours (19:00-07:00 UTC) triggers TEMPORAL alert."""
        # 03:00 UTC is well outside the default 07:00-19:00 window
        off_hours = datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc)
        event = _make_event(timestamp=off_hours, btg_active=False)

        alerts = anomaly_detector.analyze(event)
        temporal_alerts = [a for a in alerts if a.anomaly_type == "TEMPORAL"]

        assert len(temporal_alerts) == 1
        assert temporal_alerts[0].severity == Severity.MEDIUM

    def test_temporal_anomaly_suppressed_during_btg(self, anomaly_detector: AnomalyDetector):
        """Off-hours access during BTG sessions should NOT trigger a temporal alert."""
        off_hours = datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc)
        event = _make_event(timestamp=off_hours, btg_active=True)

        alerts = anomaly_detector.analyze(event)
        temporal_alerts = [a for a in alerts if a.anomaly_type == "TEMPORAL"]

        assert len(temporal_alerts) == 0

    def test_validation_block_spike(self, anomaly_detector: AnomalyDetector):
        """Three or more VALIDATION_BLOCK events in 1 hour triggers a spike alert."""
        base_time = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Send 3 validation block events within the same hour
        for i in range(3):
            event = _make_event(
                event_type="VALIDATION_BLOCK",
                timestamp=base_time + timedelta(minutes=i * 5),
                user_id="suspect-user",
            )
            alerts = anomaly_detector.analyze(event)

        spike_alerts = [a for a in alerts if a.anomaly_type == "VALIDATION_BLOCK_SPIKE"]
        assert len(spike_alerts) == 1
        assert spike_alerts[0].severity == Severity.HIGH

    def test_volume_anomaly_with_sufficient_history(self, anomaly_detector: AnomalyDetector):
        """A sudden query volume spike should trigger a VOLUME anomaly alert
        when there is enough baseline history for z-score calculation."""
        user_id = "volume-test-user"

        # Build a baseline of low-activity hourly buckets (3 events each).
        # Each bucket is in a distinct hour so the ring buffer accumulates history.
        base_time = datetime(2025, 6, 10, 0, 0, 0, tzinfo=timezone.utc)
        for hour_offset in range(10):
            bucket_time = base_time + timedelta(hours=hour_offset)
            for _ in range(3):
                anomaly_detector.analyze(
                    _make_event(
                        user_id=user_id,
                        timestamp=bucket_time,
                    )
                )
            # Force the current-hour tracker to flush by moving to next bucket
            anomaly_detector._increment_user_count(
                user_id,
                bucket_time + timedelta(hours=1),
            )

        # Now generate a large spike in a new hour (50 events vs baseline ~3)
        spike_time = base_time + timedelta(hours=20)
        volume_alerts: list = []
        for _ in range(50):
            alerts = anomaly_detector.analyze(
                _make_event(user_id=user_id, timestamp=spike_time)
            )
            volume_alerts.extend(a for a in alerts if a.anomaly_type == "VOLUME")

        assert len(volume_alerts) > 0
        # At least one should be HIGH or CRITICAL
        severities = {a.severity for a in volume_alerts}
        assert severities & {Severity.HIGH, Severity.CRITICAL}
