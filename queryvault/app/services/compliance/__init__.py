"""QueryVault Compliance & Audit Engine (Module 3).

Maintains immutable audit trails, generates regulatory compliance reports,
detects anomalies, manages alert lifecycles, and enforces data retention.

Components:
  CAE-001  AuditStore           Immutable append-only hash-chain audit log
  CAE-002  ComplianceReporter   Seven-framework one-click compliance reports
  CAE-003  ViolationDashboard   Real-time violation data aggregation
  CAE-004  AnomalyDetector      Six-model anomaly detection engine
  CAE-006  AlertManager         Alert lifecycle (dedup, escalation, dispatch)
  CAE-007  RetentionManager     Configurable regulatory data retention
"""

from queryvault.app.services.compliance.alert_manager import AlertManager
from queryvault.app.services.compliance.anomaly_detector import AnomalyDetector
from queryvault.app.services.compliance.audit_store import AuditStore
from queryvault.app.services.compliance.compliance_reporter import ComplianceReporter
from queryvault.app.services.compliance.retention_manager import RetentionManager
from queryvault.app.services.compliance.violation_dashboard import ViolationDashboard

__all__ = [
    "AlertManager",
    "AnomalyDetector",
    "AuditStore",
    "ComplianceReporter",
    "RetentionManager",
    "ViolationDashboard",
]
