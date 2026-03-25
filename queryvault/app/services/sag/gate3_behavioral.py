"""SAG-003 -- Gate 3: Behavioral Analysis.

Detects exploit patterns and malicious SQL constructs using both
AST-level analysis (via the parsed_sql dict) and regex pattern
matching on the raw SQL string.

This gate operates INDEPENDENTLY of the Permission Envelope --
it analyses SQL purely for dangerous behavioural patterns.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local data classes
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    type: str
    table: str = ""
    column: str = ""
    description: str = ""
    severity: str = "CRITICAL"


@dataclass
class GateResult:
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    gate_name: str = "gate3_behavioral"
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_WRITE_OP_RE = re.compile(
    r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|"
    r"DROP\s+(TABLE|DATABASE|INDEX|VIEW)|"
    r"ALTER\s+(TABLE|DATABASE|USER)|"
    r"CREATE\s+(TABLE|DATABASE|USER|INDEX|VIEW|FUNCTION)|"
    r"TRUNCATE\s+TABLE|MERGE\s+INTO)\b",
    re.IGNORECASE,
)

_SYSTEM_TABLE_RE = re.compile(
    r"\b(information_schema\.\w+|sys\.\w+|pg_catalog\.\w+|"
    r"pg_class|pg_tables|pg_columns|"
    r"SYSCOLUMNS|SYSOBJECTS|SYSCOMMENTS|"
    r"ALL_TABLES|ALL_TAB_COLUMNS|DBA_TABLES|"
    r"USER_TABLES|SYSINDEXES|xp_cmdshell|"
    r"openrowset|opendatasource)\b",
    re.IGNORECASE,
)

_DYNAMIC_SQL_RE = re.compile(
    r"\b(EXEC\s*\(|EXEC\s+[@\w]|sp_executesql|"
    r"EXECUTE\s+IMMEDIATE|PREPARE\s+\w+|EXECUTE\s+\w+|"
    r"DO\s+\$\$|EVAL\s*\()",
    re.IGNORECASE,
)

_FILE_OP_RE = re.compile(
    r"\b(INTO\s+(OUTFILE|DUMPFILE)|"
    r"COPY\s+.+\s+TO\s*'|"
    r"BULK\s+INSERT|"
    r"OPENROWSET\s*\(|OPENDATASOURCE\s*\()\b",
    re.IGNORECASE,
)

_PRIVILEGE_RE = re.compile(
    r"\b(GRANT\s+|REVOKE\s+|SET\s+ROLE|"
    r"ALTER\s+USER|CREATE\s+USER|DROP\s+USER|"
    r"ALTER\s+ROLE|CREATE\s+ROLE)\b",
    re.IGNORECASE,
)

_COMMENT_RE = re.compile(r"(--[^\n]*|/\*.*?\*/)", re.DOTALL)

_STACKED_QUERIES_RE = re.compile(r";\s*\w", re.DOTALL)


# ---------------------------------------------------------------------------
# Gate 3 runner
# ---------------------------------------------------------------------------

def run(parsed_sql: dict, raw_sql: str) -> GateResult:
    """Execute Gate 3 behavioural analysis.

    Parameters
    ----------
    parsed_sql : dict
        Parsed SQL dictionary with keys: has_write_ops, has_union,
        statement_count, tables, select_columns, joins, has_where, etc.
    raw_sql : str
        The original SQL string for regex-based checks.

    Returns
    -------
    GateResult
    """
    start = time.monotonic()
    violations: list[Violation] = []

    # -- Write operations (AST + regex) ----------------------------------------
    if parsed_sql.get("has_write_ops") or _WRITE_OP_RE.search(raw_sql):
        violations.append(Violation(
            type="WRITE_OPERATION",
            description=(
                "Write operation detected "
                "(INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/TRUNCATE)"
            ),
            severity="CRITICAL",
        ))

    # -- UNION exfiltration ----------------------------------------------------
    if parsed_sql.get("has_union"):
        violations.append(Violation(
            type="UNION_EXFILTRATION",
            description="UNION SELECT detected -- potential data exfiltration attempt",
            severity="CRITICAL",
        ))

    # -- Stacked queries -------------------------------------------------------
    stmt_count = parsed_sql.get("statement_count", 1)
    if stmt_count > 1 or _STACKED_QUERIES_RE.search(raw_sql):
        violations.append(Violation(
            type="STACKED_QUERIES",
            description=f"Multiple SQL statements detected (stacked queries, count={stmt_count})",
            severity="CRITICAL",
        ))

    # -- System table access ---------------------------------------------------
    if _SYSTEM_TABLE_RE.search(raw_sql):
        violations.append(Violation(
            type="SYSTEM_TABLE_ACCESS",
            description=(
                "System table access detected "
                "(information_schema / sys.* / pg_catalog)"
            ),
            severity="CRITICAL",
        ))

    # -- Dynamic SQL -----------------------------------------------------------
    if _DYNAMIC_SQL_RE.search(raw_sql):
        violations.append(Violation(
            type="DYNAMIC_SQL",
            description="Dynamic SQL detected (EXEC / sp_executesql / EXECUTE IMMEDIATE)",
            severity="CRITICAL",
        ))

    # -- File operations -------------------------------------------------------
    if _FILE_OP_RE.search(raw_sql):
        violations.append(Violation(
            type="FILE_OPERATION",
            description="File operation detected (INTO OUTFILE / COPY TO / BULK INSERT)",
            severity="CRITICAL",
        ))

    # -- Privilege escalation --------------------------------------------------
    if _PRIVILEGE_RE.search(raw_sql):
        violations.append(Violation(
            type="PRIVILEGE_ESCALATION",
            description="Privilege escalation detected (GRANT / REVOKE / SET ROLE)",
            severity="CRITICAL",
        ))

    # -- SQL comment injection -------------------------------------------------
    if _COMMENT_RE.search(raw_sql):
        violations.append(Violation(
            type="COMMENT_INJECTION",
            description="SQL comments detected -- stripping and re-validating recommended",
            severity="MEDIUM",
        ))

    # -- Cartesian products (CROSS JOIN without ON/WHERE) ----------------------
    joins: list[dict] = parsed_sql.get("joins", [])
    tables: list[str] = parsed_sql.get("tables", [])
    has_where = parsed_sql.get("has_where", False)

    if len(tables) > 1:
        for join_info in joins:
            join_kind = str(join_info.get("kind", "")).upper()
            has_on = join_info.get("has_on", False)
            has_using = join_info.get("has_using", False)
            if not has_on and not has_using:
                if join_kind in ("CROSS", "") and not has_where:
                    violations.append(Violation(
                        type="CARTESIAN_PRODUCT",
                        description=(
                            "Potential cartesian product detected "
                            "(JOIN without ON condition)"
                        ),
                        severity="HIGH",
                    ))
                    break

    # -- Excessive columns (>50) -----------------------------------------------
    select_columns = parsed_sql.get("select_columns", [])
    if len(select_columns) > 50:
        violations.append(Violation(
            type="EXCESSIVE_COLUMNS",
            description=f"Excessive columns in SELECT ({len(select_columns)} > 50)",
            severity="MEDIUM",
        ))

    # -- Determine pass / fail -------------------------------------------------
    critical = [v for v in violations if v.severity == "CRITICAL"]
    passed = len(critical) == 0

    latency_ms = (time.monotonic() - start) * 1000
    logger.debug(
        "Gate 3 (behavioral) complete: passed=%s violations=%d latency=%.2fms",
        passed, len(violations), latency_ms,
    )

    return GateResult(
        passed=passed,
        violations=violations,
        latency_ms=latency_ms,
    )
