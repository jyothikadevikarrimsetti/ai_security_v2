"""Enumerations for the QueryVault AI Security Framework.

Defines the canonical set of enums shared across every security zone:
identity, threat detection, policy resolution, validation, audit, and compliance.
"""

from enum import Enum, IntEnum


class ThreatLevel(str, Enum):
    """Severity level assigned to a classified threat signal."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class ThreatCategory(str, Enum):
    """Category of a detected threat in the NL-to-SQL pipeline."""

    INJECTION = "INJECTION"
    PROBING = "PROBING"
    ESCALATION = "ESCALATION"
    EXFILTRATION = "EXFILTRATION"


class ColumnVisibility(str, Enum):
    """Per-column visibility state resolved by L4 policy engine."""

    VISIBLE = "VISIBLE"
    MASKED = "MASKED"
    HIDDEN = "HIDDEN"
    COMPUTED = "COMPUTED"


class Severity(str, Enum):
    """Event severity used across audit and alerting subsystems."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertStatus(str, Enum):
    """Lifecycle state of an anomaly alert."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class ComplianceStandard(str, Enum):
    """Supported regulatory and compliance frameworks."""

    HIPAA_PRIVACY = "HIPAA_PRIVACY"
    HIPAA_SECURITY = "HIPAA_SECURITY"
    CFR42_PART2 = "42_CFR_PART_2"
    SOX = "SOX"
    GDPR = "GDPR"
    EU_AI_ACT = "EU_AI_ACT"
    ISO_42001 = "ISO_42001"


class SecurityZone(str, Enum):
    """Security zones in the QueryVault pipeline.

    Each zone represents a distinct phase where security controls are applied:
      PRE_MODEL     -- threat scanning before the NL-to-SQL model runs
      MODEL_BOUNDARY -- controls at the model invocation boundary
      POST_MODEL    -- SQL validation after the model generates output
      EXECUTION     -- runtime guardrails during SQL execution
      CONTINUOUS    -- ongoing audit, anomaly detection, and compliance
    """

    PRE_MODEL = "PRE_MODEL"
    MODEL_BOUNDARY = "MODEL_BOUNDARY"
    POST_MODEL = "POST_MODEL"
    EXECUTION = "EXECUTION"
    CONTINUOUS = "CONTINUOUS"


class GateResult(str, Enum):
    """Outcome of a single validation gate in L6."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class PolicyDecision(str, Enum):
    """Binary access decision emitted by the L4 policy engine."""

    ALLOW = "ALLOW"
    DENY = "DENY"


# ─────────────────────────────────────────────────────────
# IDENTITY & CONTEXT ENUMS
# ─────────────────────────────────────────────────────────

class ClearanceLevel(IntEnum):
    """Data sensitivity clearance levels.

    Maps to the 5-tier data classification:
      1 = Public        (facility names, department names)
      2 = Internal      (staff schedules, equipment)
      3 = Confidential  (patient names, MRN, diagnosis codes)
      4 = Highly Conf.  (Aadhaar, DOB, salary, bank accounts)
      5 = Restricted    (psychotherapy notes, substance abuse, HIV)
    """

    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    HIGHLY_CONFIDENTIAL = 4
    RESTRICTED = 5


class Domain(str, Enum):
    """Organisational data domains -- enforced as isolation boundaries."""

    CLINICAL = "CLINICAL"
    FINANCIAL = "FINANCIAL"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    RESEARCH = "RESEARCH"
    COMPLIANCE = "COMPLIANCE"
    IT_OPERATIONS = "IT_OPERATIONS"


class EmergencyMode(str, Enum):
    """Break-the-Glass (BTG) state."""

    NONE = "NONE"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"


class EmploymentStatus(str, Enum):
    """Employment lifecycle status used for access gating."""

    ACTIVE = "ACTIVE"
    ON_LEAVE = "ON_LEAVE"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
