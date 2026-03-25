"""KG-001 Schema Crawler -- read-only multi-DB schema extraction.

Crawls database system catalogs to discover tables, columns, data types,
primary keys, foreign keys, indexes, and approximate row counts.  Compares
discovered state against the existing graph and produces a diff.  Tables
that disappear from the source are soft-deleted (deactivated), never
hard-deleted.

Supported engines: PostgreSQL, SQL Server, Oracle, MySQL.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

from xensql.app.models.enums import SQLDialect
from xensql.app.models.schema import ColumnInfo, ForeignKey, TableInfo

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Extracted metadata (intermediate representation before graph upsert)
# ---------------------------------------------------------------------------

@dataclass
class ExtractedColumn:
    """Raw column metadata pulled from the system catalog."""

    name: str
    data_type: str
    is_pk: bool = False
    is_nullable: bool = True
    ordinal_position: int = 0
    description: str = ""


@dataclass
class ExtractedIndex:
    """Index metadata from the system catalog."""

    index_name: str
    columns: list[str] = field(default_factory=list)
    is_unique: bool = False


@dataclass
class ExtractedForeignKey:
    """FK constraint extracted from the catalog."""

    source_column: str
    target_table: str
    target_column: str
    constraint_name: str = ""


@dataclass
class ExtractedTable:
    """Complete table metadata from a single crawl pass."""

    schema_name: str
    table_name: str
    columns: list[ExtractedColumn] = field(default_factory=list)
    foreign_keys: list[ExtractedForeignKey] = field(default_factory=list)
    indexes: list[ExtractedIndex] = field(default_factory=list)
    row_count_approx: int = 0
    description: str = ""


@dataclass
class ExtractedSchema:
    """All tables discovered across one or more schemas in a database."""

    database_name: str
    dialect: SQLDialect
    schemas: dict[str, list[ExtractedTable]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Crawl result
# ---------------------------------------------------------------------------

@dataclass
class CrawlResult:
    """Summary returned by SchemaCrawler.crawl()."""

    tables_discovered: int = 0
    tables_updated: int = 0
    tables_deactivated: int = 0
    columns_discovered: int = 0
    foreign_keys_discovered: int = 0
    indexes_discovered: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    # The raw extraction for downstream consumers (graph_store, change_detector)
    extracted: ExtractedSchema | None = None


# ---------------------------------------------------------------------------
# Database config
# ---------------------------------------------------------------------------

@dataclass
class DatabaseConfig:
    """Connection details for a source database to crawl."""

    name: str
    dialect: SQLDialect
    connection_string: str
    schema_filter: list[str] | None = None


# ---------------------------------------------------------------------------
# Abstract crawler interface
# ---------------------------------------------------------------------------

class BaseCrawler(ABC):
    """Engine-specific schema extraction interface.

    Implementations must be strictly read-only -- no DDL, no DML.
    """

    @abstractmethod
    async def extract(
        self,
        connection_string: str,
        schema_filter: list[str] | None = None,
    ) -> ExtractedSchema:
        """Extract all schema metadata from the source database."""
        ...


# ---------------------------------------------------------------------------
# PostgreSQL crawler
# ---------------------------------------------------------------------------

class PostgreSQLCrawler(BaseCrawler):
    """Crawls PostgreSQL using asyncpg and information_schema / pg_catalog."""

    async def extract(
        self,
        connection_string: str,
        schema_filter: list[str] | None = None,
    ) -> ExtractedSchema:
        logger.info("postgresql_crawl_start", schema_filter=schema_filter)

        try:
            import asyncpg
        except ImportError:
            raise RuntimeError(
                "asyncpg is required for PostgreSQL crawling: pip install asyncpg"
            )

        conn = await asyncpg.connect(connection_string)
        try:
            schema = ExtractedSchema(database_name="", dialect=SQLDialect.POSTGRESQL)

            # Build schema filter clause
            schema_clause = ""
            args: list[Any] = []
            if schema_filter:
                placeholders = ", ".join(f"${i + 1}" for i in range(len(schema_filter)))
                schema_clause = f"AND t.table_schema IN ({placeholders})"
                args = list(schema_filter)
            else:
                schema_clause = (
                    "AND t.table_schema NOT IN ('pg_catalog', 'information_schema')"
                )

            # 1. Tables
            table_rows = await conn.fetch(f"""
                SELECT t.table_schema, t.table_name,
                       obj_description(
                           (t.table_schema || '.' || t.table_name)::regclass
                       ) AS description
                FROM information_schema.tables t
                WHERE t.table_type = 'BASE TABLE'
                  {schema_clause}
                ORDER BY t.table_schema, t.table_name
            """, *args)

            tables_by_schema: dict[str, dict[str, ExtractedTable]] = {}
            for row in table_rows:
                s = row["table_schema"]
                tname = row["table_name"]
                tables_by_schema.setdefault(s, {})[tname] = ExtractedTable(
                    schema_name=s,
                    table_name=tname,
                    description=row["description"] or "",
                )

            # 2. Columns
            col_rows = await conn.fetch(f"""
                SELECT c.table_schema, c.table_name, c.column_name,
                       c.data_type, c.is_nullable, c.ordinal_position,
                       col_description(
                           (c.table_schema || '.' || c.table_name)::regclass,
                           c.ordinal_position
                       ) AS description
                FROM information_schema.columns c
                JOIN information_schema.tables t
                  ON c.table_schema = t.table_schema
                 AND c.table_name = t.table_name
                WHERE t.table_type = 'BASE TABLE'
                  {schema_clause}
                ORDER BY c.table_schema, c.table_name, c.ordinal_position
            """, *args)

            for row in col_rows:
                s, tname = row["table_schema"], row["table_name"]
                tbl = tables_by_schema.get(s, {}).get(tname)
                if tbl:
                    tbl.columns.append(ExtractedColumn(
                        name=row["column_name"],
                        data_type=row["data_type"],
                        is_nullable=row["is_nullable"] == "YES",
                        ordinal_position=row["ordinal_position"],
                        description=row["description"] or "",
                    ))

            # 3. Primary keys
            pk_rows = await conn.fetch(f"""
                SELECT tc.table_schema, tc.table_name, kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  {schema_clause.replace('t.table_schema', 'tc.table_schema')}
            """, *args)

            for row in pk_rows:
                tbl = tables_by_schema.get(row["table_schema"], {}).get(row["table_name"])
                if tbl:
                    for col in tbl.columns:
                        if col.name == row["column_name"]:
                            col.is_pk = True
                            break

            # 4. Foreign keys
            fk_rows = await conn.fetch(f"""
                SELECT tc.table_schema, tc.table_name, tc.constraint_name,
                       kcu.column_name AS source_column,
                       ccu.table_name AS target_table,
                       ccu.column_name AS target_column
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  {schema_clause.replace('t.table_schema', 'tc.table_schema')}
            """, *args)

            for row in fk_rows:
                tbl = tables_by_schema.get(row["table_schema"], {}).get(row["table_name"])
                if tbl:
                    tbl.foreign_keys.append(ExtractedForeignKey(
                        constraint_name=row["constraint_name"],
                        source_column=row["source_column"],
                        target_table=row["target_table"],
                        target_column=row["target_column"],
                    ))

            # 5. Indexes
            idx_rows = await conn.fetch(f"""
                SELECT schemaname, tablename, indexname,
                       array_agg(attname ORDER BY attnum) AS columns,
                       indisunique
                FROM pg_indexes
                JOIN pg_class ON pg_class.relname = indexname
                JOIN pg_index ON pg_index.indexrelid = pg_class.oid
                JOIN pg_attribute ON pg_attribute.attrelid = pg_index.indrelid
                 AND pg_attribute.attnum = ANY(pg_index.indkey)
                WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
                GROUP BY schemaname, tablename, indexname, indisunique
            """)

            for row in idx_rows:
                tbl = tables_by_schema.get(row["schemaname"], {}).get(row["tablename"])
                if tbl:
                    tbl.indexes.append(ExtractedIndex(
                        index_name=row["indexname"],
                        columns=list(row["columns"]),
                        is_unique=row["indisunique"],
                    ))

            # 6. Approximate row counts
            for s, table_map in tables_by_schema.items():
                for tname, tbl in table_map.items():
                    count_rows = await conn.fetch(
                        "SELECT reltuples::bigint AS approx "
                        "FROM pg_class "
                        "WHERE relname = $1 AND relnamespace = "
                        "(SELECT oid FROM pg_namespace WHERE nspname = $2)",
                        tname, s,
                    )
                    if count_rows:
                        tbl.row_count_approx = max(0, count_rows[0]["approx"])

            # Assemble into schema dict
            for s, table_map in tables_by_schema.items():
                schema.schemas[s] = list(table_map.values())

            logger.info(
                "postgresql_crawl_complete",
                schemas=len(schema.schemas),
                tables=sum(len(ts) for ts in schema.schemas.values()),
            )
            return schema
        finally:
            await conn.close()


# ---------------------------------------------------------------------------
# SQL Server crawler
# ---------------------------------------------------------------------------

class SQLServerCrawler(BaseCrawler):
    """Crawls SQL Server using INFORMATION_SCHEMA views.

    Requires aioodbc at runtime.  The queries shown use parameterised
    INFORMATION_SCHEMA access -- no dynamic SQL, no xp_* procedures.
    """

    async def extract(
        self,
        connection_string: str,
        schema_filter: list[str] | None = None,
    ) -> ExtractedSchema:
        logger.info("sqlserver_crawl_start", schema_filter=schema_filter)

        try:
            import aioodbc
        except ImportError:
            raise RuntimeError(
                "aioodbc is required for SQL Server crawling: pip install aioodbc"
            )

        schema = ExtractedSchema(database_name="", dialect=SQLDialect.SQLSERVER)

        async with aioodbc.connect(dsn=connection_string) as conn:
            async with conn.cursor() as cur:

                # 1. Tables
                if schema_filter:
                    placeholders = ", ".join("?" for _ in schema_filter)
                    await cur.execute(
                        f"SELECT TABLE_SCHEMA, TABLE_NAME "
                        f"FROM INFORMATION_SCHEMA.TABLES "
                        f"WHERE TABLE_TYPE = 'BASE TABLE' "
                        f"AND TABLE_SCHEMA IN ({placeholders})",
                        *schema_filter,
                    )
                else:
                    await cur.execute(
                        "SELECT TABLE_SCHEMA, TABLE_NAME "
                        "FROM INFORMATION_SCHEMA.TABLES "
                        "WHERE TABLE_TYPE = 'BASE TABLE'"
                    )

                tables_by_schema: dict[str, dict[str, ExtractedTable]] = {}
                for row in await cur.fetchall():
                    s, tname = row[0], row[1]
                    tables_by_schema.setdefault(s, {})[tname] = ExtractedTable(
                        schema_name=s, table_name=tname,
                    )

                # 2. Columns
                await cur.execute(
                    "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, "
                    "DATA_TYPE, IS_NULLABLE, ORDINAL_POSITION "
                    "FROM INFORMATION_SCHEMA.COLUMNS"
                )
                for row in await cur.fetchall():
                    s, tname = row[0], row[1]
                    tbl = tables_by_schema.get(s, {}).get(tname)
                    if tbl:
                        tbl.columns.append(ExtractedColumn(
                            name=row[2],
                            data_type=row[3],
                            is_nullable=row[4] == "YES",
                            ordinal_position=row[5],
                        ))

                # 3. Primary keys
                await cur.execute(
                    "SELECT tc.TABLE_SCHEMA, tc.TABLE_NAME, ccu.COLUMN_NAME "
                    "FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc "
                    "JOIN INFORMATION_SCHEMA.CONSTRAINT_COLUMN_USAGE ccu "
                    "  ON tc.CONSTRAINT_NAME = ccu.CONSTRAINT_NAME "
                    "WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'"
                )
                for row in await cur.fetchall():
                    tbl = tables_by_schema.get(row[0], {}).get(row[1])
                    if tbl:
                        for col in tbl.columns:
                            if col.name == row[2]:
                                col.is_pk = True
                                break

                # 4. Foreign keys
                await cur.execute(
                    "SELECT rc.CONSTRAINT_NAME, "
                    "  kcu1.TABLE_SCHEMA, kcu1.TABLE_NAME, kcu1.COLUMN_NAME, "
                    "  kcu2.TABLE_NAME AS REF_TABLE, "
                    "  kcu2.COLUMN_NAME AS REF_COLUMN "
                    "FROM INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc "
                    "JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu1 "
                    "  ON rc.CONSTRAINT_NAME = kcu1.CONSTRAINT_NAME "
                    "JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu2 "
                    "  ON rc.UNIQUE_CONSTRAINT_NAME = kcu2.CONSTRAINT_NAME"
                )
                for row in await cur.fetchall():
                    tbl = tables_by_schema.get(row[1], {}).get(row[2])
                    if tbl:
                        tbl.foreign_keys.append(ExtractedForeignKey(
                            constraint_name=row[0],
                            source_column=row[3],
                            target_table=row[4],
                            target_column=row[5],
                        ))

                # 5. Approximate row counts via sys.dm_db_partition_stats
                await cur.execute(
                    "SELECT SCHEMA_NAME(t.schema_id) AS schema_name, "
                    "  t.name AS table_name, "
                    "  SUM(p.rows) AS row_count "
                    "FROM sys.tables t "
                    "JOIN sys.dm_db_partition_stats p "
                    "  ON t.object_id = p.object_id AND p.index_id IN (0, 1) "
                    "GROUP BY t.schema_id, t.name"
                )
                for row in await cur.fetchall():
                    tbl = tables_by_schema.get(row[0], {}).get(row[1])
                    if tbl:
                        tbl.row_count_approx = row[2]

        for s, table_map in tables_by_schema.items():
            schema.schemas[s] = list(table_map.values())

        logger.info(
            "sqlserver_crawl_complete",
            schemas=len(schema.schemas),
            tables=sum(len(ts) for ts in schema.schemas.values()),
        )
        return schema


# ---------------------------------------------------------------------------
# Oracle crawler (stub)
# ---------------------------------------------------------------------------

class OracleCrawler(BaseCrawler):
    """Oracle crawler using ALL_TABLES / ALL_TAB_COLUMNS / ALL_CONSTRAINTS."""

    async def extract(
        self,
        connection_string: str,
        schema_filter: list[str] | None = None,
    ) -> ExtractedSchema:
        raise NotImplementedError(
            "Oracle crawler not yet implemented.  "
            "Requires oracledb async driver querying ALL_TABLES, ALL_TAB_COLUMNS, "
            "ALL_CONSTRAINTS, ALL_CONS_COLUMNS."
        )


# ---------------------------------------------------------------------------
# MySQL crawler (stub)
# ---------------------------------------------------------------------------

class MySQLCrawler(BaseCrawler):
    """MySQL crawler using information_schema."""

    async def extract(
        self,
        connection_string: str,
        schema_filter: list[str] | None = None,
    ) -> ExtractedSchema:
        raise NotImplementedError(
            "MySQL crawler not yet implemented.  "
            "Requires aiomysql querying information_schema.TABLES, "
            "information_schema.COLUMNS, information_schema.KEY_COLUMN_USAGE."
        )


# ---------------------------------------------------------------------------
# Crawler factory
# ---------------------------------------------------------------------------

_CRAWLER_REGISTRY: dict[SQLDialect, type[BaseCrawler]] = {
    SQLDialect.POSTGRESQL: PostgreSQLCrawler,
    SQLDialect.SQLSERVER: SQLServerCrawler,
    SQLDialect.ORACLE: OracleCrawler,
    SQLDialect.MYSQL: MySQLCrawler,
}


def _get_crawler(dialect: SQLDialect) -> BaseCrawler:
    cls = _CRAWLER_REGISTRY.get(dialect)
    if not cls:
        raise ValueError(f"Unsupported SQL dialect: {dialect}")
    return cls()


# ---------------------------------------------------------------------------
# SchemaCrawler -- orchestration layer
# ---------------------------------------------------------------------------

class SchemaCrawler:
    """Orchestrates a crawl: extract -> diff -> return CrawlResult.

    The caller (typically a service layer or scheduled job) is responsible
    for persisting results to the graph via GraphStore.
    """

    def __init__(
        self,
        graph_store: Any | None = None,
    ) -> None:
        self._graph_store = graph_store

    async def crawl(self, database_config: DatabaseConfig) -> CrawlResult:
        """Run a full crawl against the given database.

        Returns a CrawlResult containing discovery counts and the raw
        extracted schema.  If a graph_store is configured, the method also
        diffs against the existing graph and applies upserts / deactivations.
        """
        start = time.monotonic()
        result = CrawlResult()

        try:
            crawler = _get_crawler(database_config.dialect)
            extracted = await crawler.extract(
                database_config.connection_string,
                database_config.schema_filter,
            )
            extracted.database_name = database_config.name
            result.extracted = extracted

            # Tally discoveries
            for tables in extracted.schemas.values():
                for tbl in tables:
                    result.tables_discovered += 1
                    result.columns_discovered += len(tbl.columns)
                    result.foreign_keys_discovered += len(tbl.foreign_keys)
                    result.indexes_discovered += len(tbl.indexes)

            # Diff against existing graph state if graph_store is available
            if self._graph_store is not None:
                await self._sync_to_graph(database_config.name, extracted, result)

            logger.info(
                "crawl_complete",
                database=database_config.name,
                dialect=database_config.dialect.value,
                tables_discovered=result.tables_discovered,
                tables_updated=result.tables_updated,
                tables_deactivated=result.tables_deactivated,
                duration_s=round(time.monotonic() - start, 2),
            )

        except Exception as exc:
            result.errors.append(str(exc))
            logger.error(
                "crawl_failed",
                database=database_config.name,
                error=str(exc),
            )

        result.duration_seconds = round(time.monotonic() - start, 3)
        return result

    # ---- private helpers ----

    async def _sync_to_graph(
        self,
        database_name: str,
        extracted: ExtractedSchema,
        result: CrawlResult,
    ) -> None:
        """Diff extracted schema against graph and apply upserts / deactivations."""
        gs = self._graph_store

        existing_tables = await gs.get_tables(database_name)
        existing_fqns = {t.table_id for t in existing_tables}
        discovered_fqns: set[str] = set()

        for schema_name, tables in extracted.schemas.items():
            for ext_tbl in tables:
                table_fqn = f"{database_name}.{schema_name}.{ext_tbl.table_name}"
                discovered_fqns.add(table_fqn)

                table_info = TableInfo(
                    table_id=table_fqn,
                    database_name=database_name,
                    schema_name=schema_name,
                    table_name=ext_tbl.table_name,
                    description=ext_tbl.description,
                    row_count=ext_tbl.row_count_approx,
                )
                await gs.upsert_table(table_info)

                if table_fqn in existing_fqns:
                    result.tables_updated += 1

                # Upsert columns
                columns = [
                    ColumnInfo(
                        column_id=f"{table_fqn}.{c.name}",
                        column_name=c.name,
                        data_type=c.data_type,
                        description=c.description,
                        is_pk=c.is_pk,
                    )
                    for c in ext_tbl.columns
                ]
                await gs.upsert_columns(table_fqn, columns)

        # Soft-delete tables that are no longer in the source
        gone_fqns = existing_fqns - discovered_fqns
        for fqn in gone_fqns:
            await gs.deactivate_table(fqn)
            result.tables_deactivated += 1
            logger.warning(
                "table_deactivated",
                table_fqn=fqn,
                reason="not_found_in_source_database",
            )
