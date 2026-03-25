"""AQD-006: Threat Classifier.

Aggregates three AQD signal sources into a unified ThreatClassification:

Signal Weights
--------------
- Injection scan   : 50 %
- Schema probing   : 30 %
- Behavioral score : 20 %

Classification Types
--------------------
- INJECTION     -- prompt or SQL injection detected
- PROBING       -- schema reconnaissance detected
- ESCALATION    -- privilege escalation attempt
- EXFILTRATION  -- combined injection + behavioral anomaly

Severity Levels
---------------
- CRITICAL  -- composite >= 0.8 or any signal triggers a block
- HIGH      -- composite >= 0.6
- MEDIUM    -- composite >= 0.4
- LOW       -- composite >= 0.2
- NONE      -- composite < 0.2

Escalation Logic
----------------
If injection risk_score > 0.3 AND behavioral is_anomalous, the
category is promoted to EXFILTRATION and the level is raised to
at least HIGH.
"""

from __future__ import annotations

import structlog

from queryvault.app.models.enums import ThreatCategory, ThreatLevel
from queryvault.app.models.threat import (
    BehavioralScore,
    InjectionScanResult,
    ProbingSignal,
    ThreatClassification,
)

logger = structlog.get_logger(__name__)

# Signal weights for composite scoring
_W_INJECTION = 0.50
_W_PROBING = 0.30
_W_BEHAVIORAL = 0.20


class ThreatClassifier:
    """Combines AQD signals into a unified threat classification."""

    def classify(
        self,
        injection_result: InjectionScanResult,
        probing_signal: ProbingSignal,
        behavioral_score: BehavioralScore,
    ) -> ThreatClassification:
        """Classify the overall threat from all AQD signals.

        Parameters
        ----------
        injection_result:
            Output of ``InjectionScanner.scan()``.
        probing_signal:
            Output of ``SchemaProbingDetector.check()``.
        behavioral_score:
            Output of ``BehavioralFingerprint.check()``.

        Returns
        -------
        ThreatClassification
        """
        reasons: list[str] = []
        category: ThreatCategory | None = None
        should_block = False

        # -- Injection -------------------------------------------------
        if injection_result.is_blocked:
            category = ThreatCategory.INJECTION
            should_block = True
            reasons.append(
                f"Prompt injection detected "
                f"(score={injection_result.risk_score:.2f}, "
                f"flags={injection_result.flags})"
            )

        # -- Schema probing --------------------------------------------
        if probing_signal.is_probing:
            if not category:
                category = ThreatCategory.PROBING
            should_block = True
            reasons.append(
                f"Schema probing detected "
                f"({probing_signal.recent_probing_count} "
                f"probing queries in window)"
            )

        # -- Behavioral anomaly ----------------------------------------
        if behavioral_score.is_anomalous:
            if not category:
                category = ThreatCategory.ESCALATION
            reasons.append(
                f"Behavioral anomaly "
                f"(score={behavioral_score.anomaly_score:.2f}, "
                f"flags={behavioral_score.flags})"
            )
            # Behavioral alone does not block -- it elevates severity

        # -- Weighted composite ----------------------------------------
        composite = (
            injection_result.risk_score * _W_INJECTION
            + probing_signal.score * _W_PROBING
            + behavioral_score.anomaly_score * _W_BEHAVIORAL
        )

        # -- Severity mapping ------------------------------------------
        if should_block or composite >= 0.8:
            level = ThreatLevel.CRITICAL
        elif composite >= 0.6:
            level = ThreatLevel.HIGH
        elif composite >= 0.4:
            level = ThreatLevel.MEDIUM
        elif composite >= 0.2:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.NONE

        # -- Escalation: injection + behavioral = EXFILTRATION ---------
        if injection_result.risk_score > 0.3 and behavioral_score.is_anomalous:
            category = ThreatCategory.EXFILTRATION
            reasons.append(
                "Combined injection + behavioral anomaly suggests exfiltration"
            )
            if level in (ThreatLevel.NONE, ThreatLevel.LOW, ThreatLevel.MEDIUM):
                level = ThreatLevel.HIGH

        # -- Logging ---------------------------------------------------
        if level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            logger.warning(
                "threat_classified",
                level=level.value,
                category=category.value if category else None,
                composite=f"{composite:.2f}",
                reasons=reasons,
            )

        return ThreatClassification(
            level=level,
            category=category,
            score=round(composite, 3),
            reasons=reasons,
            should_block=should_block,
            injection=injection_result,
            probing=probing_signal,
            behavioral=behavioral_score,
        )
