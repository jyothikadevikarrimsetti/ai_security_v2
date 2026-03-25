"""Intent Classifier -- rule-based keyword classifier with domain hint extraction.

No LLM API calls. Pure pattern matching with keyword weights.
Classifies into 8 intents and extracts domain hints.

XenSQL pipeline concern only -- no auth, RBAC, or security logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from xensql.app.models.enums import DomainType, IntentType
from xensql.app.models.intent import IntentResult

logger = structlog.get_logger(__name__)


# -- Keyword rule definitions -------------------------------------------------


@dataclass(frozen=True)
class IntentRule:
    """A keyword pattern -> intent mapping with weight."""

    intent: IntentType
    keywords: list[str]
    weight: float = 1.0


# Intent rules -- ordered by specificity (most specific first)
INTENT_RULES: list[IntentRule] = [
    # EXPLANATION -- natural-language explanation requests
    IntentRule(
        intent=IntentType.EXPLANATION,
        keywords=[
            "explain", "why", "reason", "cause", "how come",
            "what caused", "root cause", "justify", "rationale",
            "break down", "walk me through", "elaborate",
        ],
        weight=1.25,
    ),
    # JOIN_QUERY -- explicit join / relationship language
    IntentRule(
        intent=IntentType.JOIN_QUERY,
        keywords=[
            "join", "combine", "merge", "relate", "relationship",
            "between", "linked", "connected", "associated",
            "with their", "along with", "together with", "and their",
            "cross-reference", "match.*with", "correlate",
        ],
        weight=1.2,
    ),
    # TREND -- time-series language
    IntentRule(
        intent=IntentType.TREND,
        keywords=[
            "trend", "over time", "monthly", "weekly", "daily",
            "yearly", "quarterly", "growth", "decline", "change",
            "time series", "historical", "progression", "trajectory",
            "year over year", "month over month", "last.*months",
            "last.*weeks", "last.*days", "past.*year", "since",
            "timeline", "longitudinal",
        ],
        weight=1.1,
    ),
    # AGGREGATION -- aggregate function language
    IntentRule(
        intent=IntentType.AGGREGATION,
        keywords=[
            "count", "total", "sum", "average", "avg", "mean",
            "median", "maximum", "minimum", "max", "min",
            "how many", "number of", "percentage", "percent",
            "ratio", "rate", "distribution", "breakdown",
            "grouped by", "group by", "per", "each",
            "aggregate", "statistics", "summary",
            "across all", "across.*facilit", "length of stay",
            "readmission", "occupancy", "utilization", "throughput",
        ],
        weight=1.15,
    ),
    # COMPARISON -- comparative language
    IntentRule(
        intent=IntentType.COMPARISON,
        keywords=[
            "compare", "comparison", "versus", "vs", "difference",
            "between", "higher", "lower", "more", "less", "greater",
            "top", "bottom", "best", "worst", "rank", "ranking",
            "most", "least", "better", "worse", "outperform",
        ],
        weight=1.0,
    ),
    # EXISTENCE_CHECK -- yes/no existence language
    IntentRule(
        intent=IntentType.EXISTENCE_CHECK,
        keywords=[
            "is there", "are there", "does.*exist", "do.*have",
            "has.*any", "check if", "verify", "whether",
            "is.*available", "can I find", "do we have",
        ],
        weight=0.9,
    ),
    # DEFINITION -- metadata / schema language
    IntentRule(
        intent=IntentType.DEFINITION,
        keywords=[
            "what is", "define", "definition", "describe",
            "what does.*mean", "schema", "structure", "columns",
            "fields", "what are the", "metadata", "data dictionary",
            "table.*contain", "what.*stored in",
        ],
        weight=0.9,
    ),
    # DATA_LOOKUP -- default / simple query language
    IntentRule(
        intent=IntentType.DATA_LOOKUP,
        keywords=[
            "show", "list", "get", "find", "retrieve", "display",
            "look up", "lookup", "select", "fetch", "return",
            "what", "which", "where", "who", "when", "give me",
            "pull", "extract", "view", "see",
        ],
        weight=0.8,
    ),
]


# -- Domain hint patterns -----------------------------------------------------

DOMAIN_PATTERNS: dict[DomainType, list[str]] = {
    DomainType.CLINICAL: [
        "patient", "diagnosis", "treatment", "clinical", "medical",
        "encounter", "admission", "discharge", "vital", "procedure",
        "condition", "symptom", "allergy", "immunization",
        "observation", "care", "provider", "doctor", "nurse",
        "surgeon", "specialist", "referral", "chart",
        "ICD", "CPT", "SNOMED", "LOINC",
    ],
    DomainType.BILLING: [
        "billing", "claim", "charge", "payment", "invoice",
        "insurance", "coverage", "copay", "deductible", "payer",
        "revenue", "reimbursement", "adjustment", "denial",
        "remittance", "cost", "price", "fee",
        "DRG", "HCPCS", "modifier",
    ],
    DomainType.PHARMACY: [
        "pharmacy", "medication", "drug", "prescription", "prescribed", "dose",
        "dosage", "formulary", "dispensing", "refill", "NDC",
        "controlled substance", "narcotics", "opioid",
        "antibiotic", "contraindication", "interaction",
    ],
    DomainType.LABORATORY: [
        "lab", "laboratory", "test", "result", "specimen",
        "culture", "sensitivity", "blood", "urine", "pathology",
        "CBC", "BMP", "CMP", "A1C", "HbA1c", "panel",
        "glucose", "hemoglobin", "platelet", "enzyme",
    ],
    DomainType.HR: [
        "employee", "staff", "human resource", "HR", "payroll",
        "salary", "compensation", "benefit", "FTE", "credential",
        "license", "certification", "training", "performance",
        "attendance", "PTO", "leave",
    ],
    DomainType.SCHEDULING: [
        "schedule", "appointment", "slot", "calendar", "booking",
        "availability", "time slot", "reschedule", "cancel",
        "waitlist", "queue", "rotation", "shift", "on-call",
    ],
    DomainType.FINANCIAL: [
        "financial", "finance", "profit", "loss", "P&L", "EBITDA",
        "balance sheet", "income statement", "cash flow", "margin",
        "budget", "forecast", "expense", "asset", "liability",
        "equity", "ROI", "ROE", "ROA",
    ],
}


# -- Intent classifier --------------------------------------------------------


class IntentClassifier:
    """Rule-based intent classifier with domain hint extraction.

    No LLM calls. Uses keyword pattern matching with configurable weights
    to classify questions into one of 8 intent types.
    """

    def classify(self, question: str) -> IntentResult:
        """Classify the question into an intent and extract domain hints.

        Returns the best matching intent with confidence and matched keywords.
        """
        lower = question.lower().strip()

        # Score each intent
        scores: dict[IntentType, tuple[float, list[str]]] = {}
        for rule in INTENT_RULES:
            matched = _match_keywords(lower, rule.keywords)
            if matched:
                score = len(matched) * rule.weight
                existing_score = scores.get(rule.intent, (0.0, []))
                if score > existing_score[0]:
                    scores[rule.intent] = (score, matched)

        # Select best intent
        if scores:
            best_intent = max(scores, key=lambda k: scores[k][0])
            best_score, best_keywords = scores[best_intent]

            # Normalize confidence to [0, 1]
            max_possible = max(len(r.keywords) * r.weight for r in INTENT_RULES)
            confidence = min(best_score / max(max_possible * 0.3, 1.0), 1.0)
        else:
            best_intent = IntentType.DATA_LOOKUP
            best_keywords = []
            confidence = 0.3

        # Collect secondary intents (all that scored, excluding the primary)
        secondary = [
            i for i, (s, _) in scores.items() if i != best_intent and s > 0
        ]

        # Extract domain hints
        domains = self._extract_domain_hints(lower)

        logger.debug(
            "intent_classified",
            intent=best_intent.value,
            confidence=round(confidence, 3),
            keywords=best_keywords[:5],
            domains=[d.value for d in domains],
        )

        return IntentResult(
            intent=best_intent,
            confidence=round(confidence, 3),
            matched_keywords=best_keywords[:10],
            domain_hints=domains,
            secondary_intents=secondary,
        )

    def _extract_domain_hints(self, text: str) -> list[DomainType]:
        """Extract domain hints from question text."""
        hints: dict[DomainType, int] = {}

        for domain, patterns in DOMAIN_PATTERNS.items():
            count = sum(1 for p in patterns if _word_match(text, p))
            if count >= 1:
                hints[domain] = count

        # Sort by match count descending, return top 3
        sorted_hints = sorted(hints, key=lambda d: hints[d], reverse=True)
        return sorted_hints[:3]


# -- Helpers ------------------------------------------------------------------


def _match_keywords(text: str, keywords: list[str]) -> list[str]:
    """Match keywords against text, supporting simple regex patterns."""
    matched: list[str] = []
    for kw in keywords:
        try:
            if ".*" in kw or "(" in kw:
                if re.search(kw, text):
                    matched.append(kw)
            elif kw in text:
                matched.append(kw)
        except re.error:
            if kw in text:
                matched.append(kw)
    return matched


def _word_match(text: str, pattern: str) -> bool:
    """Case-insensitive word boundary match."""
    try:
        return bool(re.search(rf"\b{re.escape(pattern.lower())}\b", text))
    except re.error:
        return pattern.lower() in text
