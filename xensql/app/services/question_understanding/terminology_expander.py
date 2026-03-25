"""Terminology Expander -- expand domain abbreviations before embedding.

Performs additive expansion: original term is preserved, expansion appended.
E.g., "BP readings" -> "BP (blood pressure) readings"

Supports healthcare and finance domains. Loads terms from YAML config.

XenSQL pipeline concern only -- no auth, RBAC, or security logic.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger(__name__)

# Default config path relative to the xensql package root
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "abbreviations.yaml"


class TerminologyExpander:
    """Expand domain abbreviations in natural-language questions.

    Abbreviations are loaded from a YAML configuration file organized
    by domain (healthcare, finance, etc.). Expansion is additive:
    the original term is kept and the full form is appended in parentheses.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._abbreviations: dict[str, str] = {}
        path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        self._load_config(path)

    def _load_config(self, path: Path) -> None:
        """Load abbreviations from YAML config file."""
        if not path.exists():
            logger.warning("abbreviations_config_not_found", path=str(path))
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data: dict[str, Any] = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.error("abbreviations_config_load_error", error=str(exc))
            return

        # Flatten all domain sections into a single lookup dict
        count = 0
        for domain_name, terms in data.items():
            if isinstance(terms, dict):
                for abbr, expansion in terms.items():
                    if isinstance(expansion, str):
                        self._abbreviations[str(abbr)] = expansion
                        count += 1

        logger.info(
            "terminology_config_loaded",
            path=str(path),
            term_count=count,
            domains=list(data.keys()),
        )

    @property
    def term_count(self) -> int:
        """Number of loaded abbreviation terms."""
        return len(self._abbreviations)

    def expand(self, question: str) -> str:
        """Expand abbreviations in the question text.

        Additive expansion: original term is preserved, expansion appended.
        E.g., "Check BP and A1C" -> "Check BP (blood pressure) and A1C (hemoglobin A1C glycated hemoglobin)"

        Args:
            question: The natural-language question to expand.

        Returns:
            The question with abbreviations expanded.
        """
        if not self._abbreviations or not question.strip():
            return question

        words = question.split()
        result_parts: list[str] = []

        for word in words:
            # Strip punctuation for matching, keep original for output
            clean = re.sub(r"[^\w/&]", "", word)

            expansion = self._lookup(clean)

            if expansion:
                result_parts.append(f"{word} ({expansion})")
            else:
                result_parts.append(word)

        return " ".join(result_parts)

    def _lookup(self, term: str) -> str | None:
        """Look up an abbreviation, trying multiple case strategies."""
        # Exact match
        expansion = self._abbreviations.get(term)
        if expansion:
            return expansion

        # Uppercase match (e.g., "bp" -> "BP")
        expansion = self._abbreviations.get(term.upper())
        if expansion:
            return expansion

        # Title-case match (e.g., "hgb" -> "Hgb")
        expansion = self._abbreviations.get(term.capitalize())
        if expansion:
            return expansion

        # Strip trailing 's' for plurals (e.g., "MRNs" -> "MRN")
        if term.endswith("s") and len(term) > 2:
            stripped = term.rstrip("s")
            return (
                self._abbreviations.get(stripped)
                or self._abbreviations.get(stripped.upper())
                or self._abbreviations.get(stripped.capitalize())
            )

        return None

    def add_terms(self, terms: dict[str, str]) -> None:
        """Programmatically add additional abbreviation terms.

        Useful for tenant-specific or dynamically discovered terminology.
        """
        self._abbreviations.update(terms)
        logger.debug("terminology_terms_added", count=len(terms))
