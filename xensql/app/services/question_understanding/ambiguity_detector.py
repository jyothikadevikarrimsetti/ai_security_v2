"""Ambiguity Detector -- detect ambiguous queries before pipeline execution.

Identifies questions that are too vague, missing context, have multiple
interpretations, or are too short to produce reliable SQL.

Returns structured results with clarification suggestions.

XenSQL pipeline concern only -- no auth, RBAC, or security logic.
"""

from __future__ import annotations

import re

import structlog

from xensql.app.models.enums import AmbiguityType

logger = structlog.get_logger(__name__)


# -- Detection patterns -------------------------------------------------------

# Pronouns that reference prior context but are meaningless without it
_CONTEXT_PRONOUNS = re.compile(
    r"\b(that|those|these|it|them|the same|the previous|the above|the last)\b",
    re.IGNORECASE,
)

# Extremely vague question patterns
_VAGUE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"^(show|get|give|tell|list)\s+(me\s+)?(everything|all|data|stuff|info|information)\s*$",
        r"^what\s+(is|are)\s+(there|available)\s*\??$",
        r"^(help|query|search|find)\s*\??$",
        r"^(data|report|results?)\s*\??$",
    ]
]

# Patterns suggesting multiple possible interpretations
_MULTI_INTENT_MARKERS = re.compile(
    r"\b(or|either|maybe|perhaps|could be|might be|possibly)\b",
    re.IGNORECASE,
)

# Overly broad scope indicators
_BROAD_SCOPE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\beverything\b",
        r"\ball\s+(the\s+)?data\b",
        r"\bany\s+and\s+all\b",
        r"\bwhatever\b",
    ]
]


# -- Result models (lightweight, no Pydantic dependency) ----------------------


class ClarificationOption:
    """A suggested clarification for an ambiguous question."""

    __slots__ = ("label", "rephrased_question")

    def __init__(self, label: str, rephrased_question: str) -> None:
        self.label = label
        self.rephrased_question = rephrased_question

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "rephrased_question": self.rephrased_question}


class AmbiguityResult:
    """Result of ambiguity detection on the input question."""

    __slots__ = (
        "is_ambiguous",
        "ambiguity_type",
        "confidence",
        "reason",
        "clarifications",
    )

    def __init__(
        self,
        is_ambiguous: bool = False,
        ambiguity_type: AmbiguityType | None = None,
        confidence: float = 0.0,
        reason: str = "",
        clarifications: list[ClarificationOption] | None = None,
    ) -> None:
        self.is_ambiguous = is_ambiguous
        self.ambiguity_type = ambiguity_type
        self.confidence = confidence
        self.reason = reason
        self.clarifications = clarifications or []

    def to_dict(self) -> dict:
        return {
            "is_ambiguous": self.is_ambiguous,
            "ambiguity_type": self.ambiguity_type.value if self.ambiguity_type else None,
            "confidence": self.confidence,
            "reason": self.reason,
            "clarifications": [c.to_dict() for c in self.clarifications],
        }


# -- Ambiguity detector -------------------------------------------------------


class AmbiguityDetector:
    """Rule-based ambiguity detector for natural-language questions.

    Detects four types of ambiguity:
    - VAGUE_QUESTION: Question is too broad or unspecific
    - MISSING_CONTEXT: References prior conversation without context
    - MULTIPLE_INTENTS: Contains conflicting intent signals
    - SHORT_QUESTION: Too few words to determine clear intent

    Usage:
        detector = AmbiguityDetector(threshold=0.8)
        result = detector.analyze("show me everything")
        if result.is_ambiguous:
            print(result.reason)
    """

    def __init__(self, threshold: float = 0.8) -> None:
        """Initialize detector.

        Args:
            threshold: Minimum confidence to flag as ambiguous (0.0-1.0).
        """
        self._threshold = threshold

    def analyze(
        self,
        question: str,
        has_prior_context: bool = False,
    ) -> AmbiguityResult:
        """Analyze a question for ambiguity.

        Args:
            question: The natural-language question.
            has_prior_context: Whether conversation history exists for this session.

        Returns:
            AmbiguityResult with detection outcome and clarification suggestions.
        """
        question = question.strip()
        if not question:
            return AmbiguityResult(
                is_ambiguous=True,
                ambiguity_type=AmbiguityType.VAGUE_QUESTION,
                confidence=1.0,
                reason="Empty question provided.",
            )

        signals: list[tuple[AmbiguityType, float, str, list[ClarificationOption]]] = []

        # 1. Check for vague questions
        self._check_vague(question, signals)

        # 2. Check for unresolved context references
        self._check_missing_context(question, has_prior_context, signals)

        # 3. Check for multiple-intent markers
        self._check_multiple_intents(question, signals)

        # 4. Check question length
        self._check_short_question(question, signals)

        # 5. Check overly broad scope
        self._check_broad_scope(question, signals)

        if not signals:
            return AmbiguityResult(is_ambiguous=False)

        # Pick highest confidence signal
        best = max(signals, key=lambda s: s[1])
        amb_type, confidence, reason, clarifications = best

        is_ambiguous = confidence >= self._threshold

        if is_ambiguous:
            logger.info(
                "ambiguity_detected",
                type=amb_type.value,
                confidence=confidence,
                question_preview=question[:80],
            )

        return AmbiguityResult(
            is_ambiguous=is_ambiguous,
            ambiguity_type=amb_type,
            confidence=confidence,
            reason=reason,
            clarifications=clarifications,
        )

    # -- Individual checks ----------------------------------------------------

    def _check_vague(
        self,
        question: str,
        signals: list[tuple[AmbiguityType, float, str, list[ClarificationOption]]],
    ) -> None:
        """Check for vague/unspecific questions."""
        for pattern in _VAGUE_PATTERNS:
            if pattern.search(question):
                signals.append((
                    AmbiguityType.VAGUE_QUESTION,
                    0.9,
                    "Question is too vague -- please specify what data you need.",
                    [
                        ClarificationOption(
                            label="Be specific",
                            rephrased_question="Show me [specific metric] for [specific entity]",
                        ),
                    ],
                ))
                return

    def _check_missing_context(
        self,
        question: str,
        has_prior_context: bool,
        signals: list[tuple[AmbiguityType, float, str, list[ClarificationOption]]],
    ) -> None:
        """Check for unresolved context references without conversation history."""
        if has_prior_context:
            return

        pronoun_matches = _CONTEXT_PRONOUNS.findall(question)
        if pronoun_matches:
            refs = ", ".join(sorted(set(m.lower() for m in pronoun_matches)))
            signals.append((
                AmbiguityType.MISSING_CONTEXT,
                0.85,
                f"References to prior context ({refs}) but no conversation history exists.",
                [
                    ClarificationOption(
                        label="Provide full context",
                        rephrased_question=f"{question} (please specify what you are referring to)",
                    ),
                ],
            ))

    def _check_multiple_intents(
        self,
        question: str,
        signals: list[tuple[AmbiguityType, float, str, list[ClarificationOption]]],
    ) -> None:
        """Check for questions with conflicting intent signals."""
        multi_matches = _MULTI_INTENT_MARKERS.findall(question)
        if len(multi_matches) >= 2:
            signals.append((
                AmbiguityType.MULTIPLE_INTENTS,
                0.7,
                "Question contains multiple possible interpretations.",
                [
                    ClarificationOption(
                        label="Clarify intent",
                        rephrased_question="Please rephrase as a single, specific question.",
                    ),
                ],
            ))

    def _check_short_question(
        self,
        question: str,
        signals: list[tuple[AmbiguityType, float, str, list[ClarificationOption]]],
    ) -> None:
        """Check for very short questions that lack specificity."""
        word_count = len(question.split())
        if word_count <= 2 and not any(p.search(question) for p in _VAGUE_PATTERNS):
            signals.append((
                AmbiguityType.SHORT_QUESTION,
                0.6,
                "Very short question -- additional context may improve results.",
                [
                    ClarificationOption(
                        label="Add detail",
                        rephrased_question=f"{question} -- can you add more context?",
                    ),
                ],
            ))

    def _check_broad_scope(
        self,
        question: str,
        signals: list[tuple[AmbiguityType, float, str, list[ClarificationOption]]],
    ) -> None:
        """Check for overly broad scope indicators."""
        for pattern in _BROAD_SCOPE_PATTERNS:
            if pattern.search(question):
                signals.append((
                    AmbiguityType.VAGUE_QUESTION,
                    0.75,
                    "Question scope is too broad -- try narrowing to specific tables or metrics.",
                    [
                        ClarificationOption(
                            label="Narrow scope",
                            rephrased_question="Show me [specific columns] from [specific table] where [condition]",
                        ),
                    ],
                ))
                return
