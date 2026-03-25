"""KG-005 Graph Store -- Neo4j storage for the schema catalog.

CRUD operations for databases, tables, columns, foreign keys, and domains.
All Cypher queries are parameterized (no string interpolation, no injection
risk).  Uses read/write driver separation and connection pooling via
the Neo4j async driver.

This store handles ONLY schema catalog data.  Policy, access control, and
classification nodes/relationships belong to QueryVault's graph_client.
"""

from __future__ import annotations

import re
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import structlog
from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction, AsyncSession

from xensql.app.models.enums import DomainType, SQLDialect
from xensql.app.models.schema import ColumnInfo, ForeignKey, TableInfo

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Fulltext query sanitizer (prevent Lucene injection)
# ---------------------------------------------------------------------------

def _sanitize_fulltext_query(query: str, max_length: int = 200) -> str:
    """Strip Lucene special characters from a fulltext search query.

    Neo4j fulltext indexes use Lucene under the hood.  Reserved characters
    like brackets, colons, etc. cause ParseException if passed unsanitized.
    """
    cleaned = re.sub(r'\[.*?\]', ' ', query)
    cleaned = re.sub(r'[+\-&|!(){}^"~*?:\\/]', ' ', cleaned)
    cleaned = ' '.join(cleaned.split())[:max_length]
    return cleaned or '*'


# ---------------------------------------------------------------------------
# Connection config
# ---------------------------------------------------------------------------

class GraphStoreConfig:
    """Connection settings for the Neo4j graph store."""

    def __init__(
        self,
        uri: str,
        read_user: str,
        read_password: str,
        write_user: str,
        write_password: str,
        database: str = "neo4j",
        max_pool_size: int = 50,
        encrypted: bool = False,
    ) -> None:
        self.uri = uri
        self.read_user = read_user
        self.read_password = read_password
        self.write_user = write_user
        self.write_password = write_password
        self.database = database
        self.max_pool_size = max_pool_size
        self.encrypted = encrypted


# ---------------------------------------------------------------------------
# GraphStore
# ---------------------------------------------------------------------------

class GraphStore:
    """Neo4j-backed storage for the XenSQL schema catalog.

    Provides async CRUD for:
    - Database nodes
    - Table nodes (with domain tagging)
    - Column nodes
    - Foreign key relationships
    - Fulltext search over table names and descriptions

    All queries use parameterized Cypher.  Read operations use the read
    driver; write operations use the write driver.
    """

    def __init__(self, config: GraphStoreConfig) -> None:
        self._config = config
        self._read_driver: AsyncDriver | None = None
        self._write_driver: AsyncDriver | None = None

    # ---- Lifecycle ----

    async def connect(self) -> None:
        """Initialize read and write driver pools."""
        common: dict[str, Any] = {
            "max_connection_pool_size": self._config.max_pool_size,
            "connection_acquisition_timeout": 30,
            "max_transaction_retry_time": 10,
        }

        if self._config.encrypted:
            common["encrypted"] = True

        self._read_driver = AsyncGraphDatabase.driver(
            self._config.uri,
            auth=(self._config.read_user, self._config.read_password),
            **common,
        )
        self._write_driver = AsyncGraphDatabase.driver(
            self._config.uri,
            auth=(self._config.write_user, self._config.write_password),
            **common,
        )

        await self._read_driver.verify_connectivity()
        await self._write_driver.verify_connectivity()
        logger.info("graph_store_connected", uri=self._config.uri)

    async def close(self) -> None:
        """Shutdown both driver pools."""
        if self._read_driver:
            await self._read_driver.close()
        if self._write_driver:
            await self._write_driver.close()
        logger.info("graph_store_disconnected")

    @asynccontextmanager
    async def _read_session(self) -> AsyncIterator[AsyncSession]:
        if not self._read_driver:
            raise RuntimeError("GraphStore read driver not initialized")
        async with self._read_driver.session(
            database=self._config.database,
            default_access_mode="READ",
        ) as session:
            yield session

    @asynccontextmanager
    async def _write_session(self) -> AsyncIterator[AsyncSession]:
        if not self._write_driver:
            raise RuntimeError("GraphStore write driver not initialized")
        async with self._write_driver.session(
            database=self._config.database,
            default_access_mode="WRITE",
        ) as session:
            yield session

    async def _execute_read(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a parameterized read query, return records as dicts."""
        async with self._read_session() as session:
            result = await session.run(query, parameters or {})
            return [record.data() async for record in result]

    async def _execute_write(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a parameterized write query, return records as dicts."""
        async with self._write_session() as session:
            result = await session.run(query, parameters or {})
            return [record.data() async for record in result]

    async def _execute_write_tx(
        self,
        queries: list[tuple[str, dict[str, Any]]],
    ) -> None:
        """Execute multiple write queries in a single transaction."""
        async with self._write_session() as session:
            async def _tx_work(tx: AsyncManagedTransaction) -> None:
                for query, params in queries:
                    await tx.run(query, params)
            await session.execute_write(_tx_work)

    # ---- Health ----

    async def health_check(self) -> bool:
        """Return True if the read driver can execute a trivial query."""
        try:
            records = await self._execute_read("RETURN 1 AS health")
            return len(records) == 1 and records[0].get("health") == 1
        except Exception as exc:
            logger.error("graph_store_health_check_failed", error=str(exc))
            return False

    # ---- Database CRUD ----

    async def get_databases(self) -> list[dict[str, Any]]:
        """Return all active database nodes with summary metadata."""
        query = """
        MATCH (db:Database)
        WHERE db.is_active = true
        OPTIONAL MATCH (db)-[:HAS_SCHEMA]->(s:Schema)-[:HAS_TABLE]->(t:Table)
        WHERE t.is_active = true
        OPTIONAL MATCH (t)-[:BELONGS_TO_DOMAIN]->(d:Domain)
        WITH db,
             count(DISTINCT t) AS table_count,
             collect(DISTINCT d.name) AS domains
        RETURN db.name AS name,
               db.engine AS engine,
               db.description AS description,
               table_count,
               domains
        ORDER BY db.name
        """
        return await self._execute_read(query)

    async def upsert_database(
        self,
        name: str,
        engine: SQLDialect,
        description: str = "",
    ) -> None:
        """Create or update a Database node."""
        query = """
        MERGE (db:Database {name: $name})
        ON CREATE SET
            db.engine = $engine,
            db.description = $description,
            db.is_active = true,
            db.created_at = datetime()
        ON MATCH SET
            db.engine = $engine,
            db.description = $description,
            db.is_active = true,
            db.updated_at = datetime()
        """
        await self._execute_write(query, {
            "name": name,
            "engine": engine.value,
            "description": description,
        })

    # ---- Table CRUD ----

    async def get_tables(self, database: str) -> list[TableInfo]:
        """Return all active tables for a database."""
        query = """
        MATCH (db:Database {name: $database})-[:HAS_SCHEMA]->(s:Schema)-[:HAS_TABLE]->(t:Table)
        WHERE t.is_active = true
        OPTIONAL MATCH (t)-[:BELONGS_TO_DOMAIN]->(d:Domain)
        RETURN t.fqn AS fqn,
               t.name AS name,
               t.description AS description,
               s.name AS schema_name,
               db.name AS database_name,
               d.name AS domain,
               t.row_count_approx AS row_count
        ORDER BY t.fqn
        """
        records = await self._execute_read(query, {"database": database})
        results: list[TableInfo] = []
        for r in records:
            domain = None
            if r.get("domain"):
                try:
                    domain = DomainType(r["domain"])
                except ValueError:
                    pass
            results.append(TableInfo(
                table_id=r["fqn"],
                database_name=r.get("database_name", ""),
                schema_name=r.get("schema_name", ""),
                table_name=r["name"],
                description=r.get("description", ""),
                domain=domain,
                row_count=r.get("row_count"),
            ))
        return results

    async def upsert_table(self, table: TableInfo) -> None:
        """Create or update a Table node with schema and domain relationships.

        Expects table.table_id to be the fully-qualified name
        (database.schema.table).
        """
        # Ensure Schema node exists and is linked to Database
        parts = table.table_id.split(".")
        if len(parts) >= 3:
            db_name = parts[0]
            schema_name = parts[1]
            schema_fqn = f"{db_name}.{schema_name}"
        else:
            db_name = table.database_name
            schema_name = table.schema_name
            schema_fqn = f"{db_name}.{schema_name}" if db_name and schema_name else ""

        queries: list[tuple[str, dict[str, Any]]] = []

        # Upsert schema node
        if schema_fqn:
            queries.append((
                """
                MERGE (db:Database {name: $db_name})
                ON CREATE SET db.is_active = true
                MERGE (s:Schema {fqn: $schema_fqn})
                ON CREATE SET s.name = $schema_name, s.is_active = true
                MERGE (db)-[:HAS_SCHEMA]->(s)
                """,
                {
                    "db_name": db_name,
                    "schema_fqn": schema_fqn,
                    "schema_name": schema_name,
                },
            ))

        # Upsert table node
        domain_value = table.domain.value if table.domain else None
        queries.append((
            """
            MERGE (t:Table {fqn: $fqn})
            ON CREATE SET
                t.name = $name,
                t.description = $description,
                t.domain = $domain,
                t.row_count_approx = $row_count,
                t.is_active = true,
                t.created_at = datetime()
            ON MATCH SET
                t.name = $name,
                t.description = $description,
                t.domain = $domain,
                t.row_count_approx = $row_count,
                t.is_active = true,
                t.updated_at = datetime()
            """,
            {
                "fqn": table.table_id,
                "name": table.table_name,
                "description": table.description,
                "domain": domain_value,
                "row_count": table.row_count,
            },
        ))

        # Link table to schema
        if schema_fqn:
            queries.append((
                """
                MATCH (s:Schema {fqn: $schema_fqn})
                MATCH (t:Table {fqn: $table_fqn})
                MERGE (s)-[:HAS_TABLE]->(t)
                """,
                {"schema_fqn": schema_fqn, "table_fqn": table.table_id},
            ))

        # Link table to domain
        if domain_value:
            queries.append((
                """
                MERGE (d:Domain {name: $domain})
                WITH d
                MATCH (t:Table {fqn: $table_fqn})
                MERGE (t)-[:BELONGS_TO_DOMAIN]->(d)
                """,
                {"domain": domain_value, "table_fqn": table.table_id},
            ))

        await self._execute_write_tx(queries)

    async def deactivate_table(self, table_fqn: str) -> None:
        """Soft-delete a table (set is_active = false).  Never hard-delete."""
        query = """
        MATCH (t:Table {fqn: $fqn})
        SET t.is_active = false, t.deactivated_at = datetime()
        """
        await self._execute_write(query, {"fqn": table_fqn})
        logger.info("table_deactivated", table_fqn=table_fqn)

    # ---- Column CRUD ----

    async def get_table_columns(self, table_id: str) -> list[ColumnInfo]:
        """Return all active columns for a table."""
        query = """
        MATCH (t:Table {fqn: $table_fqn})-[:HAS_COLUMN]->(c:Column)
        WHERE c.is_active = true
        RETURN c.fqn AS fqn,
               c.name AS name,
               c.data_type AS data_type,
               c.is_pk AS is_pk,
               c.is_nullable AS is_nullable,
               c.description AS description
        ORDER BY c.ordinal_position, c.name
        """
        records = await self._execute_read(query, {"table_fqn": table_id})
        return [
            ColumnInfo(
                column_id=r["fqn"],
                column_name=r["name"],
                data_type=r.get("data_type", ""),
                description=r.get("description", ""),
                is_pk=r.get("is_pk", False),
            )
            for r in records
        ]

    async def upsert_columns(
        self,
        table_id: str,
        columns: list[ColumnInfo],
    ) -> None:
        """Create or update Column nodes for a table.

        Columns that exist in the graph but are absent from the input list
        are deactivated (soft-deleted).
        """
        if not columns:
            return

        queries: list[tuple[str, dict[str, Any]]] = []

        discovered_fqns: set[str] = set()

        for i, col in enumerate(columns):
            col_fqn = col.column_id or f"{table_id}.{col.column_name}"
            discovered_fqns.add(col_fqn)

            queries.append((
                """
                MATCH (t:Table {fqn: $table_fqn})
                MERGE (c:Column {fqn: $col_fqn})
                ON CREATE SET
                    c.name = $name,
                    c.data_type = $data_type,
                    c.is_pk = $is_pk,
                    c.description = $description,
                    c.ordinal_position = $ordinal,
                    c.is_active = true,
                    c.created_at = datetime()
                ON MATCH SET
                    c.name = $name,
                    c.data_type = $data_type,
                    c.is_pk = $is_pk,
                    c.description = $description,
                    c.ordinal_position = $ordinal,
                    c.is_active = true,
                    c.updated_at = datetime()
                MERGE (t)-[:HAS_COLUMN]->(c)
                """,
                {
                    "table_fqn": table_id,
                    "col_fqn": col_fqn,
                    "name": col.column_name,
                    "data_type": col.data_type,
                    "is_pk": col.is_pk,
                    "description": col.description,
                    "ordinal": i,
                },
            ))

        await self._execute_write_tx(queries)

        # Deactivate columns that are no longer present
        existing_cols = await self.get_table_columns(table_id)
        for existing in existing_cols:
            existing_fqn = existing.column_id or f"{table_id}.{existing.column_name}"
            if existing_fqn not in discovered_fqns:
                await self._execute_write(
                    """
                    MATCH (c:Column {fqn: $fqn})
                    SET c.is_active = false, c.deactivated_at = datetime()
                    """,
                    {"fqn": existing_fqn},
                )
                logger.info("column_deactivated", column_fqn=existing_fqn)

    # ---- Foreign Key CRUD ----

    async def get_foreign_keys(
        self, table_ids: list[str]
    ) -> list[ForeignKey]:
        """Return all foreign keys for the given tables."""
        if not table_ids:
            return []

        query = """
        UNWIND $table_fqns AS tfqn
        MATCH (t:Table {fqn: tfqn})-[:HAS_COLUMN]->(src:Column)
              -[:FOREIGN_KEY_TO]->(tgt:Column)<-[:HAS_COLUMN]-(t2:Table)
        RETURN t.fqn AS from_table,
               src.name AS from_column,
               t2.fqn AS to_table,
               tgt.name AS to_column
        """
        records = await self._execute_read(query, {"table_fqns": table_ids})
        return [
            ForeignKey(
                from_table=r["from_table"],
                from_column=r["from_column"],
                to_table=r["to_table"],
                to_column=r["to_column"],
            )
            for r in records
        ]

    async def upsert_foreign_key(
        self,
        from_column_fqn: str,
        to_column_fqn: str,
        constraint_name: str = "",
    ) -> None:
        """Create a FOREIGN_KEY_TO relationship between two column nodes."""
        query = """
        MATCH (src:Column {fqn: $src_fqn})
        MATCH (tgt:Column {fqn: $tgt_fqn})
        MERGE (src)-[fk:FOREIGN_KEY_TO]->(tgt)
        ON CREATE SET fk.constraint_name = $constraint_name,
                      fk.created_at = datetime()
        """
        await self._execute_write(query, {
            "src_fqn": from_column_fqn,
            "tgt_fqn": to_column_fqn,
            "constraint_name": constraint_name,
        })

    # ---- Search ----

    async def search_tables(
        self,
        query: str,
        limit: int = 20,
    ) -> list[TableInfo]:
        """Fulltext search over table names and descriptions.

        Requires a Neo4j fulltext index named 'table_search' on
        Table nodes covering the 'name' and 'description' properties.
        """
        safe_query = _sanitize_fulltext_query(query)

        cypher = """
        CALL db.index.fulltext.queryNodes('table_search', $query_text)
        YIELD node, score
        WHERE node.is_active = true
        WITH node AS t, score
        ORDER BY score DESC
        LIMIT $limit
        OPTIONAL MATCH (s:Schema)-[:HAS_TABLE]->(t)
        OPTIONAL MATCH (db:Database)-[:HAS_SCHEMA]->(s)
        OPTIONAL MATCH (t)-[:BELONGS_TO_DOMAIN]->(d:Domain)
        RETURN t.fqn AS fqn,
               t.name AS name,
               t.description AS description,
               s.name AS schema_name,
               db.name AS database_name,
               d.name AS domain,
               t.row_count_approx AS row_count
        """
        records = await self._execute_read(cypher, {
            "query_text": safe_query,
            "limit": limit,
        })
        results: list[TableInfo] = []
        for r in records:
            domain = None
            if r.get("domain"):
                try:
                    domain = DomainType(r["domain"])
                except ValueError:
                    pass
            results.append(TableInfo(
                table_id=r["fqn"],
                database_name=r.get("database_name", ""),
                schema_name=r.get("schema_name", ""),
                table_name=r["name"],
                description=r.get("description", ""),
                domain=domain,
                row_count=r.get("row_count"),
            ))
        return results

    # ---- Graph stats ----

    async def get_node_counts(self) -> dict[str, int]:
        """Return counts of active nodes by label (schema catalog only)."""
        query = """
        CALL {
            MATCH (n:Database) WHERE n.is_active = true
            RETURN 'Database' AS label, count(n) AS cnt
            UNION ALL
            MATCH (n:Schema) RETURN 'Schema' AS label, count(n) AS cnt
            UNION ALL
            MATCH (n:Table) WHERE n.is_active = true
            RETURN 'Table' AS label, count(n) AS cnt
            UNION ALL
            MATCH (n:Column) WHERE n.is_active = true
            RETURN 'Column' AS label, count(n) AS cnt
            UNION ALL
            MATCH (n:Domain) RETURN 'Domain' AS label, count(n) AS cnt
        }
        RETURN label, cnt
        """
        records = await self._execute_read(query)
        return {r["label"]: r["cnt"] for r in records}
