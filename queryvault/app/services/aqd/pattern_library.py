"""AQD-007: Versioned Attack Pattern Library.

Provides a versioned, extensible store of attack patterns loaded from a
JSON file (``data/attack_patterns.json``).  Each pattern belongs to a
category with a severity weight and can be toggled on/off per deployment.

File Format (``data/attack_patterns.json``)
-------------------------------------------
::

    {
        "version": "1.0.0",
        "categories": {
            "direct_override": {"weight": 0.40},
            "sql_fragment":    {"weight": 0.35},
            ...
        },
        "patterns": [
            {
                "id": "OVR-001",
                "category": "direct_override",
                "pattern": "ignore\\\\s+previous\\\\s+instructions",
                "description": "Attempts to override system prompt",
                "severity_weight": 0.8,
                "enabled": true
            },
            ...
        ]
    }
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from queryvault.app.models.threat import Pattern

logger = structlog.get_logger(__name__)

# Default location relative to repository root.
_DEFAULT_PATH = "data/attack_patterns.json"


class PatternLibrary:
    """Versioned, file-backed attack-pattern store.

    Parameters
    ----------
    path:
        Path to the JSON pattern file.  Defaults to
        ``data/attack_patterns.json`` resolved from the current
        working directory.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else Path(_DEFAULT_PATH)
        self._version: str = "0.0.0"
        self._patterns: list[Pattern] = []
        self._category_weights: dict[str, float] = {}
        self._by_category: dict[str, list[Pattern]] = {}

    # -- public properties --------------------------------------------------

    @property
    def version(self) -> str:
        """Semantic version of the currently loaded pattern set."""
        return self._version

    @property
    def pattern_count(self) -> int:
        """Total number of loaded patterns (including disabled)."""
        return len(self._patterns)

    @property
    def categories(self) -> list[str]:
        """List of known category names."""
        return list(self._by_category.keys())

    # -- loading ------------------------------------------------------------

    def load(self, path: str | Path | None = None) -> None:
        """Load (or reload) patterns from a JSON file.

        Parameters
        ----------
        path:
            Override path.  When *None* the path supplied at construction
            time is used.

        Raises
        ------
        FileNotFoundError
            If the pattern file does not exist.
        ValueError
            If the JSON structure is invalid.
        """
        target = Path(path) if path else self._path

        if not target.exists():
            raise FileNotFoundError(f"Pattern file not found: {target}")

        with target.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        if not isinstance(data, dict):
            raise ValueError("Pattern file root must be a JSON object")

        self._version = data.get("version", "0.0.0")

        # Category weights
        raw_cats = data.get("categories", {})
        self._category_weights = {
            name: meta.get("weight", 0.5)
            for name, meta in raw_cats.items()
        }

        # Patterns
        raw_patterns = data.get("patterns", [])
        self._patterns = []
        self._by_category = {}

        for entry in raw_patterns:
            try:
                p = Pattern(
                    id=entry["id"],
                    category=entry["category"],
                    pattern=entry["pattern"],
                    description=entry.get("description", ""),
                    severity_weight=entry.get("severity_weight", 0.5),
                    enabled=entry.get("enabled", True),
                )
                self._patterns.append(p)
                self._by_category.setdefault(p.category, []).append(p)
            except Exception as exc:
                logger.warning(
                    "pattern_load_skip",
                    entry_id=entry.get("id", "unknown"),
                    error=str(exc),
                )

        logger.info(
            "pattern_library_loaded",
            version=self._version,
            total=len(self._patterns),
            categories=list(self._by_category.keys()),
            path=str(target),
        )

    # -- querying -----------------------------------------------------------

    def get_patterns(self, category: str) -> list[Pattern]:
        """Return all *enabled* patterns for *category*.

        Parameters
        ----------
        category:
            Category name (e.g. ``"direct_override"``).

        Returns
        -------
        list[Pattern]
            Enabled patterns in the requested category.
        """
        return [
            p for p in self._by_category.get(category, []) if p.enabled
        ]

    def get_all_patterns(self, enabled_only: bool = True) -> list[Pattern]:
        """Return all loaded patterns, optionally filtered to enabled."""
        if enabled_only:
            return [p for p in self._patterns if p.enabled]
        return list(self._patterns)

    def get_category_weight(self, category: str) -> float:
        """Return the configured weight for *category* (default 0.5)."""
        return self._category_weights.get(category, 0.5)
