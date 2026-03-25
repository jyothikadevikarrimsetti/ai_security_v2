"""Adaptive Query Defense (AQD) -- Module 1 of the QueryVault security framework.

Real-time threat interception for the NL-to-SQL pipeline:

  AQD-001  InjectionScanner        -- 200+ pattern prompt injection detection
  AQD-002  SchemaProbingDetector   -- Redis-backed schema enumeration detection
  AQD-003  BehavioralFingerprint   -- per-user behavioral profiling & anomaly detection
  AQD-004  SQLInjectionAnalyzer    -- post-LLM SQL AST analysis
  AQD-005  AlertEngine             -- multi-channel alert delivery
  AQD-006  ThreatClassifier        -- weighted signal aggregation & classification
  AQD-007  PatternLibrary          -- versioned, extensible attack pattern store
"""

from queryvault.app.services.aqd.alert_engine import AlertEngine
from queryvault.app.services.aqd.behavioral_fingerprint import BehavioralFingerprint
from queryvault.app.services.aqd.injection_scanner import InjectionScanner
from queryvault.app.services.aqd.pattern_library import PatternLibrary
from queryvault.app.services.aqd.schema_probing_detector import SchemaProbingDetector
from queryvault.app.services.aqd.sql_injection_analyzer import SQLInjectionAnalyzer
from queryvault.app.services.aqd.threat_classifier import ThreatClassifier

__all__ = [
    "AlertEngine",
    "BehavioralFingerprint",
    "InjectionScanner",
    "PatternLibrary",
    "SchemaProbingDetector",
    "SQLInjectionAnalyzer",
    "ThreatClassifier",
]
