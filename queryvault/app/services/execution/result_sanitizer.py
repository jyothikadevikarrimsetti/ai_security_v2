"""Result Sanitizer -- last-line-of-defense PII scanning and masking.

EXECUTION security zone: scans every cell of every row returned from the
database, regardless of whether SQL-level masking was applied. This catches
edge cases that masking expressions might miss (NULLs, dialect differences,
data quality issues, unexpected column content).

Masking formats:
  SSN      -> ***-**-XXXX  (last 4 preserved)
  Aadhaar  -> XXXX XXXX XXXX  (last 4 preserved)
  Phone    -> ***-***-XXXX  (last 4 preserved)
  Email    -> F***@domain  (first char + domain preserved)

False-positive avoidance:
  - Skips numeric/date/boolean columns (no string PII possible)
  - Skips known-safe columns: MRN, ICD codes, procedure_code, etc.
  - Phone pattern excluded for medical-code columns
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from queryvault.app.models.enums import Severity

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# PII type enum (local to this module -- not shared across zones)
# ---------------------------------------------------------------------------


class PIIType:
    """PII categories detected by the sanitizer."""

    SSN = "SSN"
    AADHAAR = "AADHAAR"
    PHONE = "PHONE"
    EMAIL = "EMAIL"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SanitizationEvent:
    """Record of a single PII detection and masking event."""

    row_index: int
    column_name: str
    pii_type: str
    original_snippet: str  # first 6 chars + "..."
    masked_value: str


@dataclass
class SanitizationReport:
    """Summary of all PII detections during result sanitization."""

    events: list[SanitizationEvent] = field(default_factory=list)
    rows_scanned: int = 0
    columns_checked: int = 0
    cells_scanned: int = 0

    @property
    def pii_detected(self) -> int:
        """Total number of PII instances found and masked."""
        return len(self.events)

    @property
    def severity(self) -> Severity:
        """Severity based on PII detection count."""
        if self.pii_detected == 0:
            return Severity.INFO
        if self.pii_detected <= 3:
            return Severity.LOW
        if self.pii_detected <= 10:
            return Severity.MEDIUM
        return Severity.HIGH


# ---------------------------------------------------------------------------
# Column metadata (lightweight -- only what the sanitizer needs)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ColumnMeta:
    """Minimal column metadata for sanitizer filtering."""

    name: str
    type: str = "VARCHAR"


# ---------------------------------------------------------------------------
# PII patterns (pre-compiled)
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (PIIType.SSN, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (PIIType.AADHAAR, re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
    (PIIType.PHONE, re.compile(r"\b(?:\+\d{1,3}[\s-]?)?\d{10,12}\b")),
    (PIIType.EMAIL, re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        re.IGNORECASE,
    )),
]

# Columns known to contain numeric identifiers that look like phone numbers
_EXCLUDE_COLUMN_PATTERNS = re.compile(
    r"(mrn|encounter_id|claim_id|icd|procedure_code|diagnosis_code"
    r"|zipcode|zip_code|postal_code|npi|dea|tax_id)",
    re.IGNORECASE,
)

# Column types that cannot contain string PII
_NUMERIC_DATE_TYPES = frozenset({
    "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "MEDIUMINT",
    "FLOAT", "DOUBLE", "REAL", "NUMERIC", "DECIMAL",
    "BOOLEAN", "BOOL",
    "DATE", "TIMESTAMP", "TIMESTAMPTZ", "DATETIME", "TIME",
})


# ---------------------------------------------------------------------------
# Masking functions
# ---------------------------------------------------------------------------


def _mask_ssn(value: str, match: re.Match[str]) -> str:
    """Mask SSN: ***-**-XXXX (preserve last 4)."""
    last4 = match.group(0)[-4:]
    return value[:match.start()] + f"***-**-{last4}" + value[match.end():]


def _mask_aadhaar(value: str, match: re.Match[str]) -> str:
    """Mask Aadhaar: XXXX XXXX XXXX (preserve last 4)."""
    raw = re.sub(r"\s", "", match.group(0))
    last4 = raw[-4:]
    return value[:match.start()] + f"XXXX XXXX {last4}" + value[match.end():]


def _mask_phone(value: str, match: re.Match[str]) -> str:
    """Mask phone: ***-***-XXXX (preserve last 4)."""
    raw = re.sub(r"[\s\-+]", "", match.group(0))
    last4 = raw[-4:] if len(raw) >= 4 else raw
    return value[:match.start()] + f"***-***-{last4}" + value[match.end():]


def _mask_email(value: str, match: re.Match[str]) -> str:
    """Mask email: F***@domain (preserve first char and domain)."""
    email = match.group(0)
    at_idx = email.find("@")
    if at_idx < 0:
        return value
    first_char = email[0] if email else "*"
    domain = email[at_idx + 1:]
    masked = f"{first_char}***@{domain}"
    return value[:match.start()] + masked + value[match.end():]


_MASKERS: dict[str, Any] = {
    PIIType.SSN: _mask_ssn,
    PIIType.AADHAAR: _mask_aadhaar,
    PIIType.PHONE: _mask_phone,
    PIIType.EMAIL: _mask_email,
}


# ---------------------------------------------------------------------------
# Column filtering helpers
# ---------------------------------------------------------------------------


def _should_scan_column(col_type: str) -> bool:
    """Return True if the column type could contain string PII."""
    return col_type.upper() not in _NUMERIC_DATE_TYPES


def _should_check_phone_for_column(col_name: str) -> bool:
    """Phone pattern has high false-positive rate on medical IDs. Skip those."""
    return not bool(_EXCLUDE_COLUMN_PATTERNS.search(col_name))


# ---------------------------------------------------------------------------
# ResultSanitizer class
# ---------------------------------------------------------------------------


class ResultSanitizer:
    """Last-line-of-defense PII scanner for query results.

    Scans every string cell in the result set for PII patterns and
    replaces detected values with masked versions. Produces a
    SanitizationReport documenting all detections.

    Usage:
        sanitizer = ResultSanitizer()
        sanitized_rows, report = sanitizer.sanitize(rows, columns)
    """

    def __init__(self) -> None:
        self._patterns = _PATTERNS
        self._maskers = _MASKERS

    def sanitize(
        self,
        rows: list[list[Any]],
        columns: list[Any],
    ) -> tuple[list[list[Any]], SanitizationReport]:
        """Scan and mask PII in result rows.

        Args:
            rows: List of rows (each row is a list of cell values).
                  Modified in-place for efficiency.
            columns: Column metadata. Each element must have 'name' and
                     'type' attributes (or dict keys).

        Returns:
            Tuple of (sanitized_rows, SanitizationReport).
        """
        report = SanitizationReport()
        report.rows_scanned = len(rows)

        # Resolve column metadata
        col_metas = self._resolve_columns(columns)

        # Determine which columns to scan (skip numeric/date types)
        scannable: list[tuple[int, str]] = []
        for i, col in enumerate(col_metas):
            if _should_scan_column(col.type):
                scannable.append((i, col.name))
        report.columns_checked = len(scannable)

        # Scan every cell
        for row_idx, row in enumerate(rows):
            for col_idx, col_name in scannable:
                if col_idx >= len(row):
                    continue

                cell = row[col_idx]
                if not isinstance(cell, str) or not cell:
                    continue

                report.cells_scanned += 1
                original = cell
                modified = cell

                for pii_type, pattern in self._patterns:
                    # Skip phone checks for known-ID columns
                    if pii_type == PIIType.PHONE and not _should_check_phone_for_column(col_name):
                        continue

                    match = pattern.search(modified)
                    if match:
                        masker = self._maskers.get(pii_type)
                        if masker:
                            modified = masker(modified, match)
                            snippet = (
                                original[:6] + "..."
                                if len(original) > 6
                                else original
                            )
                            report.events.append(SanitizationEvent(
                                row_index=row_idx,
                                column_name=col_name,
                                pii_type=pii_type,
                                original_snippet=snippet,
                                masked_value=modified,
                            ))
                            logger.warning(
                                "pii_detected_and_masked",
                                row=row_idx,
                                column=col_name,
                                pii_type=pii_type,
                            )

                if modified != original:
                    row[col_idx] = modified

        if report.pii_detected > 0:
            logger.info(
                "sanitization_complete",
                pii_events=report.pii_detected,
                rows_scanned=report.rows_scanned,
                severity=report.severity.value,
            )

        return rows, report

    @staticmethod
    def _resolve_columns(columns: list[Any]) -> list[ColumnMeta]:
        """Convert column metadata from various formats to ColumnMeta."""
        result: list[ColumnMeta] = []
        for col in columns:
            if isinstance(col, ColumnMeta):
                result.append(col)
            elif hasattr(col, "name") and hasattr(col, "type"):
                result.append(ColumnMeta(name=col.name, type=col.type or "VARCHAR"))
            elif isinstance(col, dict):
                result.append(ColumnMeta(
                    name=col.get("name", ""),
                    type=col.get("type", "VARCHAR"),
                ))
            else:
                result.append(ColumnMeta(name=str(col), type="VARCHAR"))
        return result
