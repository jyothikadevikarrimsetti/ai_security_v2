"""Query Executor -- read-only database execution with mock mode.

EXECUTION security zone: executes validated SQL against PostgreSQL or MySQL
databases using connection pooling. All execution is strictly read-only.
Mock mode provides synthetic data for development and testing.

Supported backends:
  - PostgreSQL via asyncpg (connection pooling)
  - MySQL via aiomysql (connection pooling)
  - Mock mode for dev/test (synthetic data generation)
"""

from __future__ import annotations

import asyncio
import random
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ColumnInfo:
    """Metadata for a single result column."""

    name: str
    type: str
    masked: bool = False


@dataclass
class ExecutionResult:
    """Output of a query execution."""

    rows: list[list[Any]] = field(default_factory=list)
    columns: list[ColumnInfo] = field(default_factory=list)
    row_count: int = 0
    execution_time_ms: float = 0.0
    truncated: bool = False
    database: str = ""
    engine: str = ""


@dataclass
class DatabaseConfig:
    """Connection configuration for a target database."""

    engine: str = "postgresql"  # "postgresql" or "mysql"
    host: str = "localhost"
    port: int = 5432
    user: str = ""
    password: str = ""
    database: str = ""
    ssl_mode: str = "require"
    pool_min_size: int = 2
    pool_max_size: int = 10
    connect_timeout: int = 10


# ---------------------------------------------------------------------------
# Type OID mapping helpers
# ---------------------------------------------------------------------------

_PG_TYPE_MAP: dict[int, str] = {
    16: "BOOLEAN", 20: "BIGINT", 21: "SMALLINT", 23: "INTEGER",
    25: "TEXT", 700: "REAL", 701: "DOUBLE", 1043: "VARCHAR",
    1082: "DATE", 1114: "TIMESTAMP", 1184: "TIMESTAMPTZ",
    1700: "NUMERIC", 2950: "UUID", 1042: "CHAR",
}


def _pg_type_name(oid: int) -> str:
    """Map PostgreSQL type OID to a readable name."""
    return _PG_TYPE_MAP.get(oid, "VARCHAR")


# ---------------------------------------------------------------------------
# Write-statement detection (fail-secure)
# ---------------------------------------------------------------------------

_WRITE_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|MERGE|REPLACE)\b",
    re.IGNORECASE,
)


def _assert_read_only(sql: str) -> None:
    """Reject any SQL that contains write operations. Fail-secure."""
    if _WRITE_PATTERN.search(sql):
        raise PermissionError(
            "Write operations are not permitted. "
            "Only read-only SELECT queries may be executed."
        )


# ---------------------------------------------------------------------------
# QueryExecutor -- real database execution
# ---------------------------------------------------------------------------


class QueryExecutor:
    """Read-only SQL executor with connection pooling.

    Supports PostgreSQL (asyncpg) and MySQL (aiomysql). Every query is
    verified to be read-only before execution. Connection pools are
    lazily initialised and cached per database config.
    """

    def __init__(self) -> None:
        self._pg_pools: dict[str, Any] = {}   # dsn -> asyncpg.Pool
        self._mysql_pools: dict[str, Any] = {}  # dsn -> aiomysql.Pool
        self._lock = asyncio.Lock()

    # -- Pool management ----------------------------------------------------

    async def _get_pg_pool(self, config: DatabaseConfig) -> Any:
        """Get or create an asyncpg connection pool."""
        import asyncpg as _asyncpg

        dsn = (
            f"postgresql://{config.user}:{config.password}"
            f"@{config.host}:{config.port}/{config.database}"
        )
        if dsn not in self._pg_pools:
            async with self._lock:
                if dsn not in self._pg_pools:
                    ssl_ctx = None
                    if config.ssl_mode and config.ssl_mode != "disable":
                        ssl_ctx = ssl.create_default_context()
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE

                    pool = await _asyncpg.create_pool(
                        dsn,
                        min_size=config.pool_min_size,
                        max_size=config.pool_max_size,
                        timeout=config.connect_timeout,
                        ssl=ssl_ctx,
                    )
                    self._pg_pools[dsn] = pool
                    logger.info(
                        "pg_pool_created",
                        database=config.database,
                        min_size=config.pool_min_size,
                        max_size=config.pool_max_size,
                    )
        return self._pg_pools[dsn]

    async def _get_mysql_pool(self, config: DatabaseConfig) -> Any:
        """Get or create an aiomysql connection pool."""
        import aiomysql as _aiomysql

        key = f"{config.host}:{config.port}/{config.database}"
        if key not in self._mysql_pools:
            async with self._lock:
                if key not in self._mysql_pools:
                    pool = await _aiomysql.create_pool(
                        host=config.host,
                        port=config.port,
                        user=config.user,
                        password=config.password,
                        db=config.database,
                        minsize=config.pool_min_size,
                        maxsize=config.pool_max_size,
                        connect_timeout=config.connect_timeout,
                        charset="utf8mb4",
                        autocommit=True,
                    )
                    self._mysql_pools[key] = pool
                    logger.info(
                        "mysql_pool_created",
                        database=config.database,
                        min_size=config.pool_min_size,
                        max_size=config.pool_max_size,
                    )
        return self._mysql_pools[key]

    # -- Execution ----------------------------------------------------------

    async def execute(
        self,
        sql: str,
        database_config: DatabaseConfig,
        resource_limits: dict[str, Any] | None = None,
    ) -> ExecutionResult:
        """Execute read-only SQL and return structured results.

        Args:
            sql: Validated SQL query (must be read-only SELECT).
            database_config: Target database connection settings.
            resource_limits: Optional dict with timeout_seconds and max_rows.

        Returns:
            ExecutionResult with rows, columns, row_count, and timing.

        Raises:
            PermissionError: If the SQL contains write operations.
            asyncio.TimeoutError: If the query exceeds the timeout.
            ConnectionError: If the database is unreachable.
        """
        _assert_read_only(sql)

        limits = resource_limits or {}
        timeout_seconds = limits.get("timeout_seconds", 30)
        max_rows = limits.get("max_rows", 10_000)

        start = time.monotonic()

        engine = database_config.engine.lower()
        if engine == "postgresql":
            result = await self._execute_postgresql(
                sql, database_config, max_rows, timeout_seconds,
            )
        elif engine == "mysql":
            result = await self._execute_mysql(
                sql, database_config, max_rows, timeout_seconds,
            )
        else:
            raise ValueError(f"Unsupported database engine: {engine}")

        result.execution_time_ms = (time.monotonic() - start) * 1000
        result.database = database_config.database
        result.engine = engine
        return result

    async def _execute_postgresql(
        self,
        sql: str,
        config: DatabaseConfig,
        max_rows: int,
        timeout_seconds: int,
    ) -> ExecutionResult:
        """Execute against PostgreSQL using asyncpg pool."""
        pool = await self._get_pg_pool(config)

        async with pool.acquire() as conn:
            records = await asyncio.wait_for(
                conn.fetch(sql),
                timeout=timeout_seconds,
            )

            columns: list[ColumnInfo] = []
            if records:
                col_names = list(records[0].keys())
                columns = [
                    ColumnInfo(name=name, type="VARCHAR", masked=False)
                    for name in col_names
                ]

            truncated = len(records) > max_rows
            if truncated:
                records = records[:max_rows]

            rows: list[list[Any]] = []
            for record in records:
                row = []
                for val in record.values():
                    if val is not None and not isinstance(val, (str, int, float, bool)):
                        row.append(str(val))
                    else:
                        row.append(val)
                rows.append(row)

            logger.info(
                "pg_query_executed",
                database=config.database,
                rows=len(rows),
                truncated=truncated,
            )

            return ExecutionResult(
                rows=rows,
                columns=columns,
                row_count=len(rows),
                truncated=truncated,
            )

    async def _execute_mysql(
        self,
        sql: str,
        config: DatabaseConfig,
        max_rows: int,
        timeout_seconds: int,
    ) -> ExecutionResult:
        """Execute against MySQL using aiomysql pool."""
        pool = await self._get_mysql_pool(config)

        async with pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await asyncio.wait_for(
                    cursor.execute(sql),
                    timeout=timeout_seconds,
                )
                desc = cursor.description or []
                columns = [
                    ColumnInfo(name=d[0], type="VARCHAR", masked=False)
                    for d in desc
                ]

                records = await cursor.fetchmany(max_rows + 1)
                truncated = len(records) > max_rows
                if truncated:
                    records = records[:max_rows]

                rows: list[list[Any]] = []
                for rec in records:
                    row = []
                    for val in rec:
                        if val is not None and not isinstance(val, (str, int, float, bool)):
                            row.append(str(val))
                        else:
                            row.append(val)
                    rows.append(row)

                logger.info(
                    "mysql_query_executed",
                    database=config.database,
                    rows=len(rows),
                    truncated=truncated,
                )

                return ExecutionResult(
                    rows=rows,
                    columns=columns,
                    row_count=len(rows),
                    truncated=truncated,
                )

    # -- Cleanup ------------------------------------------------------------

    async def close(self) -> None:
        """Close all connection pools."""
        for pool in self._pg_pools.values():
            await pool.close()
        for pool in self._mysql_pools.values():
            pool.close()
            await pool.wait_closed()
        self._pg_pools.clear()
        self._mysql_pools.clear()
        logger.info("executor_pools_closed")


# ---------------------------------------------------------------------------
# MockExecutor -- synthetic data for dev/test
# ---------------------------------------------------------------------------

_SYNTHETIC_VALUES: dict[str, list[Any]] = {
    "mrn":                ["MRN-10001", "MRN-10002", "MRN-10003", "MRN-10004", "MRN-10005"],
    "full_name":          ["J. Patel", "A. Kumar", "R. Singh", "S. Sharma", "P. Iyer"],
    "patient_name":       ["J. Patel", "A. Kumar", "R. Singh", "S. Sharma", "P. Iyer"],
    "admission_date":     ["2026-01-15T08:30:00Z", "2026-01-16T14:22:00Z", "2026-02-01T09:00:00Z"],
    "discharge_date":     ["2026-01-18T11:00:00Z", "2026-01-19T16:30:00Z", None],
    "unit_id":            ["3B", "ICU", "CARDIO", "ORTHO", "NEURO"],
    "encounter_id":       ["ENC-0001", "ENC-0002", "ENC-0003", "ENC-0004"],
    "encounter_type":     ["INPATIENT", "OUTPATIENT", "EMERGENCY"],
    "treating_provider_id": ["DR-4521", "DR-3310", "DR-7842"],
    "department":         ["CARDIOLOGY", "ICU", "NEUROLOGY", "ORTHOPEDICS"],
    "claim_id":           ["CLM-AA001", "CLM-AA002", "CLM-BB001"],
    "total_amount":       [12500.00, 8900.50, 34200.00, 7650.75],
    "service_date":       ["2026-01-10", "2026-01-11", "2026-01-14"],
    "count":              [42, 17, 8, 103, 29],
    "count(*)":           [42, 17, 8],
    "admission_id":       ["ADM-001", "ADM-002", "ADM-003"],
    "diagnosis_code":     ["I21.0", "J18.1", "N18.3", "E11.9"],
    "diagnosis_name":     ["STEMI", "Pneumonia", "CKD stage 3", "Type 2 DM"],
}

_DEFAULT_SYNTHETIC = ["sample_value_1", "sample_value_2", "sample_value_3"]


def _infer_column_type(col_name: str) -> str:
    """Infer SQL type from a column name for mock data."""
    name = col_name.lower()
    if any(k in name for k in ("date", "time", "_at", "_on")):
        return "TIMESTAMP"
    if any(k in name for k in ("amount", "total", "cost", "fee", "price")):
        return "NUMERIC"
    if any(k in name for k in ("count", "num", "qty")):
        return "INTEGER"
    if any(k in name for k in ("id",)):
        return "VARCHAR"
    return "VARCHAR"


def _extract_columns_from_sql(sql: str) -> list[str]:
    """Best-effort column name extraction from a SELECT statement."""
    sql_upper = sql.upper().strip()

    # SELECT *
    if re.match(r"SELECT\s+(\w+\.)?\*", sql_upper):
        return ["id", "name", "value", "created_at"]

    # Extract between SELECT and FROM
    m = re.search(
        r"SELECT\s+(DISTINCT\s+)?(.+?)\s+FROM\b",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return ["col1", "col2"]

    col_str = m.group(2)
    # Normalise aggregate functions
    col_str = re.sub(r"COUNT\s*\(\s*\*\s*\)", "count(*)", col_str, flags=re.IGNORECASE)
    col_str = re.sub(
        r"\b(?:COUNT|SUM|AVG|MIN|MAX)\s*\([^)]+\)\s+(?:AS\s+)?(\w+)?",
        lambda m_: m_.group(1) or "aggregate",
        col_str,
        flags=re.IGNORECASE,
    )

    cols: list[str] = []
    for part in col_str.split(","):
        part = part.strip()
        alias_m = re.search(r"\bAS\s+(\w+)\s*$", part, re.IGNORECASE)
        if alias_m:
            cols.append(alias_m.group(1).lower())
        else:
            name = part.split(".")[-1].strip()
            name = re.sub(r"[^a-z0-9_*()]", "", name.lower())
            if name:
                cols.append(name)

    return cols if cols else ["col1", "col2"]


class MockExecutor:
    """Synthetic data executor for development and testing.

    Parses SQL to infer column names and generates plausible rows
    without any database connection.
    """

    def __init__(self, latency_ms: int = 50) -> None:
        self._latency_ms = latency_ms

    async def execute(
        self,
        sql: str,
        database_config: DatabaseConfig | None = None,
        resource_limits: dict[str, Any] | None = None,
    ) -> ExecutionResult:
        """Simulate query execution with synthetic data.

        Args:
            sql: SQL query to simulate.
            database_config: Ignored in mock mode.
            resource_limits: Optional dict with max_rows.

        Returns:
            ExecutionResult with synthetic rows.
        """
        _assert_read_only(sql)

        limits = resource_limits or {}
        max_rows = limits.get("max_rows", 10_000)

        start = time.monotonic()
        await asyncio.sleep(self._latency_ms / 1000.0)

        col_names = _extract_columns_from_sql(sql)
        columns = [
            ColumnInfo(name=c, type=_infer_column_type(c), masked=False)
            for c in col_names
        ]

        # Determine row count from SQL LIMIT / TOP clause
        limit_m = re.search(r"\bLIMIT\s+(\d+)\b", sql, re.IGNORECASE)
        sql_limit = int(limit_m.group(1)) if limit_m else 20
        top_m = re.search(r"\bTOP\s+(\d+)\b", sql, re.IGNORECASE)
        if top_m:
            sql_limit = min(sql_limit, int(top_m.group(1)))

        target_rows = min(random.randint(3, 10), sql_limit, max_rows)

        rows: list[list[Any]] = []
        for _ in range(target_rows):
            row: list[Any] = []
            for col in columns:
                key = col.name.lower()
                pool = _SYNTHETIC_VALUES.get(key, _DEFAULT_SYNTHETIC)
                row.append(random.choice(pool))
            rows.append(row)

        truncated = target_rows >= max_rows
        elapsed_ms = (time.monotonic() - start) * 1000

        logger.debug(
            "mock_execution_complete",
            columns=len(columns),
            rows=len(rows),
            latency_ms=f"{elapsed_ms:.1f}",
        )

        return ExecutionResult(
            rows=rows,
            columns=columns,
            row_count=len(rows),
            execution_time_ms=elapsed_ms,
            truncated=truncated,
            database="mock",
            engine="mock",
        )
