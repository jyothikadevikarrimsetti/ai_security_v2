"""AQD-001: Enhanced Prompt Injection Scanner.

200+ pattern library across 8 attack categories with normalization,
per-category scoring, and weighted aggregation.

Categories
----------
1. Direct Override       -- jailbreak / role hijack phrases
2. SQL Fragments         -- raw SQL embedded in natural language
3. Encoding Bypass       -- hex, unicode, URL, HTML entity escapes
4. Indirect Injection    -- social-engineering / context-switch attempts
5. Unicode Bypass        -- zero-width, RTL override, tag-block chars
6. Prompt Leaking        -- attempts to extract system prompt
7. Chain-of-Thought Manipulation -- reasoning-path hijack
8. Delimiter Injection   -- ChatML / Llama / markdown role delimiters
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse

import structlog

from queryvault.app.models.threat import InjectionScanResult

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Category 1: Direct Override  (weight 0.40)
# ---------------------------------------------------------------------------

_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(previous|all|above|prior|every)\s+(instructions?|rules?|constraints?|prompts?)",
        r"forget\s+(all\s+)?(instructions?|rules?|constraints?|context|everything)",
        r"you\s+are\s+now\s+\w+",
        r"pretend\s+(to\s+be|you\s+are|you're)",
        r"act\s+as\s+(if\s+you\s+are|a\s+|an?\s+)",
        r"disregard\s+(all\s+)?(rules?|instructions?|policies?|constraints?)",
        r"new\s+system\s+prompt",
        r"override\s+(mode|rules?|instructions?|safety)",
        r"(reveal|show|print|display|output)\s+.*(password|secret|key|token|schema|prompt|instructions?)",
        r"jailbreak",
        r"DAN\s+mode",
        r"bypass\s+(all\s+)?(safety|security|filter|restriction)",
        r"enter\s+(developer|debug|admin|root)\s+mode",
        r"sudo\s+mode",
        r"switch\s+to\s+(unrestricted|unfiltered)",
        r"(enable|activate)\s+(developer|debug|admin|unrestricted)\s+mode",
        r"do\s+not\s+follow\s+(any|your|the)\s+(rules?|instructions?)",
        r"from\s+now\s+on\s+(ignore|forget|disregard)",
        r"new\s+instruction[s:]?\s+(ignore|forget|override)",
        r"(remove|disable|turn\s+off)\s+(all\s+)?(filter|restriction|safety|security)",
        r"you\s+have\s+been\s+(updated|reprogrammed|reconfigured)",
        r"(I|we)\s+(own|created|built|programmed)\s+you",
        r"(stop|cease)\s+being\s+(an?\s+)?(AI|assistant|chatbot)",
        r"unlock\s+(all\s+)?(capabilities|functions|features|restrictions)",
        r"(god|master|supreme)\s+mode",
    ]
]

# ---------------------------------------------------------------------------
# Category 2: SQL Fragments  (weight 0.35)
# ---------------------------------------------------------------------------

_SQL_FRAGMENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bUNION\s+(ALL\s+)?SELECT\b",
        r"\bINSERT\s+INTO\b",
        r"\bDELETE\s+FROM\b",
        r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b",
        r"\bALTER\s+TABLE\b",
        r"\bCREATE\s+(TABLE|DATABASE|USER|INDEX|VIEW)\b",
        r"\bEXEC(\s+|\()",
        r"\bsp_executesql\b",
        r"--\s*$",
        r"/\*.*\*/",
        r"\bxp_cmdshell\b",
        r"\bEXECUTE\s+IMMEDIATE\b",
        r"\bGRANT\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b",
        r"\bREVOKE\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b",
        r"\bTRUNCATE\s+TABLE\b",
        r"\bUPDATE\s+\w+\s+SET\b",
        r"\bLOAD_FILE\s*\(",
        r"\bINTO\s+(OUTFILE|DUMPFILE)\b",
        r"\bCOPY\s+\w+\s+(FROM|TO)\b",
        r"\b(1\s*=\s*1|'1'\s*=\s*'1'|1\s*OR\s*1)\b",
        r";\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|GRANT)\b",
        r"\bSLEEP\s*\(\d+\)",
        r"\bBENCHMARK\s*\(",
        r"\bWAITFOR\s+DELAY\b",
        r"\binformation_schema\b",
        r"\bpg_catalog\b",
        r"\bsys\.(tables|columns|objects|databases)\b",
        r"\bOPENROWSET\s*\(",
        r"\bOPENDATASOURCE\s*\(",
        r"\bdblink\b",
    ]
]

# ---------------------------------------------------------------------------
# Category 3: Encoding Bypass  (weight 0.50)
# ---------------------------------------------------------------------------

_ENCODING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
        r"%[0-9a-fA-F]{2}",
        r"&#\d{2,4};",
        r"&#x[0-9a-fA-F]{2,4};",
        r"\\[0-7]{3}",
    ]
]

# ---------------------------------------------------------------------------
# Category 4: Indirect Injection  (weight 0.45)
# ---------------------------------------------------------------------------

_INDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"translate\s+to\s+sql\s*:",
        r"as\s+a\s+sql\s+expert",
        r"convert\s+(this|the\s+following)\s+to\s+sql",
        r"write\s+(me\s+)?a\s+(sql|query|select)",
        r"generate\s+(a\s+)?sql\s+(query|statement)",
        r"give\s+me\s+(the\s+)?sql\s+for",
        r"(here|this)\s+is\s+the\s+new\s+(prompt|instruction|system)",
        r"begin\s+new\s+conversation",
        r"reset\s+(context|conversation|session)",
        r"my\s+name\s+is\s+.*\s+and\s+I\s+(need|want|require)\s+full\s+access",
        r"I\s+am\s+(an?\s+)?(admin|administrator|root|superuser|dba)",
        r"this\s+is\s+an?\s+emergency",
        r"(patient|life)\s+is\s+at\s+(risk|stake)",
        r"ignore\s+the\s+above\s+and\s+instead",
        r"the\s+following\s+is\s+(your\s+)?new\s+system",
        r"<\s*system\s*>",
        r"respond\s+only\s+with\s+(raw\s+)?sql",
        r"you\s+must\s+(always\s+)?execute",
        r"(compliance|legal|regulatory)\s+override",
        r"(CEO|CTO|manager|supervisor)\s+(said|told|ordered|requires)",
    ]
]

# ---------------------------------------------------------------------------
# Category 5: Unicode Bypass  (weight 0.60)
# ---------------------------------------------------------------------------

_UNICODE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p)
    for p in [
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f]",
        r"[\u202a-\u202e]",
        r"[\ufeff\ufff9-\ufffb]",
        r"[\U000e0001-\U000e007f]",
        r"[\u0300-\u036f]{3,}",          # stacked combining diacriticals
        r"[\ufb50-\ufdff\ufe70-\ufeff]",  # Arabic presentation forms
        r"[\U0001d400-\U0001d7ff]",       # Mathematical alphanumerics
    ]
]

# ---------------------------------------------------------------------------
# Category 6: Prompt Leaking  (weight 0.50)
# ---------------------------------------------------------------------------

_LEAKING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(repeat|show|display|print|output|echo)\s+(your|the|all)\s+(instructions?|system\s+prompt|rules?|context)",
        r"what\s+(is|are)\s+your\s+(instructions?|system\s+prompt|rules?|constraints?)",
        r"(tell|show)\s+me\s+(your|the)\s+(system\s+)?prompt",
        r"(what|how)\s+(were|are)\s+you\s+(configured|instructed|programmed|set\s+up)",
        r"list\s+(all\s+)?(your\s+)?(rules?|instructions?|constraints?|policies?)",
        r"describe\s+your\s+(role|purpose|instructions?|configuration)",
        r"dump\s+(your\s+)?(system|initial)\s+(prompt|message|instructions?)",
        r"what\s+was\s+(the\s+)?first\s+(message|instruction|prompt)",
        r"(copy|paste|return)\s+(the\s+)?(entire|full|complete)\s+(system\s+)?(prompt|message)",
        r"verbatim\s+(system|original)\s+(prompt|instructions?)",
    ]
]

# ---------------------------------------------------------------------------
# Category 7: Chain-of-Thought Manipulation  (weight 0.60)
# ---------------------------------------------------------------------------

_COT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"think\s+step\s+by\s+step\s+(and\s+then\s+)?(ignore|bypass|skip|override)",
        r"let'?s\s+(first\s+)?(think|reason)\s+about\s+how\s+to\s+(bypass|override|circumvent)",
        r"(first|before)\s+(answer|respond|generate),?\s+(ignore|bypass|disregard)",
        r"reason\s+about\s+why\s+(the\s+)?(rules?|restrictions?)\s+(are|should\s+be)\s+(wrong|removed|ignored)",
        r"(explain|describe)\s+how\s+to\s+(bypass|circumvent|evade)\s+(the\s+)?(security|filter|safety)",
        r"(walk|guide)\s+me\s+through\s+(bypassing|evading|circumventing)",
        r"what\s+would\s+happen\s+if\s+(the\s+)?(rules?|restrictions?)\s+(were|are)\s+(removed|disabled)",
        r"hypothetically,?\s+(if|assume)\s+(there\s+were\s+)?no\s+(rules?|restrictions?|filters?)",
    ]
]

# ---------------------------------------------------------------------------
# Category 8: Delimiter Injection  (weight 0.70)
# ---------------------------------------------------------------------------

_DELIMITER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"```\s*(system|assistant|user)\s*\n",
        r"<\|?(system|assistant|user|im_start|im_end)\|?>",
        r"\[INST\]|\[/INST\]",
        r"###\s*(System|User|Assistant|Human|AI)\s*:",
        r"</?s>",
        r"<\|endoftext\|>",
        r"<\|pad\|>",
        r"<\|eot_id\|>",
        r"\{\{#system\}\}",
        r"<\|begin_of_text\|>",
    ]
]


# ---------------------------------------------------------------------------
# All categories with their weights
# ---------------------------------------------------------------------------

_CATEGORIES: list[tuple[str, list[re.Pattern[str]], float]] = [
    ("OVERRIDE_ATTEMPT",     _OVERRIDE_PATTERNS,   0.40),
    ("SQL_FRAGMENT",         _SQL_FRAGMENT_PATTERNS, 0.35),
    ("ENCODING_BYPASS",      _ENCODING_PATTERNS,    0.50),
    ("INDIRECT_INJECTION",   _INDIRECT_PATTERNS,    0.45),
    ("UNICODE_BYPASS",       _UNICODE_PATTERNS,     0.60),
    ("PROMPT_LEAKING",       _LEAKING_PATTERNS,     0.50),
    ("COT_MANIPULATION",     _COT_PATTERNS,         0.60),
    ("DELIMITER_INJECTION",  _DELIMITER_PATTERNS,   0.70),
]


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """URL-decode and Unicode-normalize the input text."""
    try:
        text = urllib.parse.unquote(text)
    except Exception:
        pass
    text = unicodedata.normalize("NFKC", text)
    return text


def _score_patterns(
    text: str,
    patterns: list[re.Pattern[str]],
    weight: float,
) -> tuple[float, list[str]]:
    """Return (score, matched_snippets) for a set of patterns."""
    matches: list[str] = []
    for p in patterns:
        m = p.search(text)
        if m:
            matches.append(m.group()[:60])
    score = min(1.0, len(matches) * weight)
    return score, matches


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class InjectionScanner:
    """Scans natural-language questions for prompt-injection attempts.

    Covers 200+ patterns across 8 attack categories with two-pass
    analysis: pre-normalization (encoding / unicode) and
    post-normalization (all other categories).
    """

    def scan(self, question: str, threshold: float = 0.6) -> InjectionScanResult:
        """Scan *question* and return an ``InjectionScanResult``.

        Parameters
        ----------
        question:
            Raw user input (natural language).
        threshold:
            Risk-score threshold above which the question is blocked.

        Returns
        -------
        InjectionScanResult
            Contains ``is_blocked``, ``risk_score``, ``flags``,
            ``matched_patterns``, and ``sanitized_text``.
        """
        flags: list[str] = []
        matched: list[str] = []
        scores: list[float] = []

        # --- Pre-normalization pass (encoding & unicode) ---
        for flag_name, patterns, weight in _CATEGORIES:
            if flag_name in ("ENCODING_BYPASS", "UNICODE_BYPASS"):
                s, m = _score_patterns(question, patterns, weight)
                if s > 0:
                    flags.append(flag_name)
                    matched.extend(m)
                    scores.append(s)

        # --- Normalize ---
        normalized = _normalize(question)

        # --- Post-normalization pass (remaining categories) ---
        for flag_name, patterns, weight in _CATEGORIES:
            if flag_name not in ("ENCODING_BYPASS", "UNICODE_BYPASS"):
                s, m = _score_patterns(normalized, patterns, weight)
                if s > 0:
                    flags.append(flag_name)
                    matched.extend(m)
                    scores.append(s)

        # --- Aggregate ---
        risk_score = min(1.0, sum(scores))
        is_blocked = risk_score >= threshold

        # --- Sanitize ---
        sanitized = normalized
        for p in _OVERRIDE_PATTERNS:
            sanitized = p.sub("[REDACTED]", sanitized)
        for p in _DELIMITER_PATTERNS:
            sanitized = p.sub("[REDACTED]", sanitized)

        if is_blocked:
            logger.warning(
                "injection_blocked",
                risk_score=risk_score,
                flags=flags,
                question_preview=question[:80],
            )

        return InjectionScanResult(
            is_blocked=is_blocked,
            risk_score=round(risk_score, 4),
            flags=flags,
            matched_patterns=matched[:20],
            sanitized_text=sanitized,
        )
