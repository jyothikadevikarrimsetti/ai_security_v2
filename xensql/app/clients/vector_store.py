"""pgvector async vector store for XenSQL.

Provides cosine similarity search over schema embeddings stored in
PostgreSQL with the pgvector extension. Uses HNSW indexes for
approximate nearest neighbor queries.

Adapted to work with the existing schema_embeddings table which has:
  id (bigint), entity_type (varchar), entity_fqn (varchar),
  source_text (text), is_active (boolean), embedding (vector),
  created_at (timestamptz), source_hash (text)

entity_fqn format: 'DatabaseName.SchemaName.TableName[.ColumnName]'
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from xensql.app.config import Settings

logger = structlog.get_logger(__name__)


class SearchResult:
    """A single search result from the vector store."""

    __slots__ = ("id", "score", "table_name", "metadata")

    def __init__(
        self,
        id: str,
        score: float,
        table_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.id = id
        self.score = score
        self.table_name = table_name
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "score": self.score,
            "table_name": self.table_name,
            "metadata": self.metadata,
        }


def _extract_table_name(entity_fqn: str) -> str:
    """Extract table name from entity_fqn like 'ApolloHIS.ApolloHIS.tablename.colname'."""
    parts = entity_fqn.split(".")
    if len(parts) >= 3:
        return parts[2]
    return entity_fqn


def _extract_database_name(entity_fqn: str) -> str:
    """Extract database name from entity_fqn like 'ApolloHIS.ApolloHIS.tablename'."""
    parts = entity_fqn.split(".")
    if parts:
        return parts[0]
    return ""


class VectorStore:
    """Async pgvector operations for schema embedding search.

    Usage:
        store = VectorStore(settings)
        await store.connect()
        results = await store.search(embedding, top_k=10)
        await store.close()
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool = None
        self._real_tables: set[str] = set()

    async def connect(self) -> None:
        """Create the asyncpg connection pool and verify table exists."""
        try:
            import asyncpg

            self._pool = await asyncpg.create_pool(
                self._settings.pgvector_dsn,
                min_size=self._settings.pgvector_pool_min,
                max_size=self._settings.pgvector_pool_max,
            )
            await self._ensure_table()
            await self._load_real_tables()
            logger.info("pgvector_connected", dsn=self._settings.pgvector_dsn.split("@")[-1], real_tables=sorted(self._real_tables))
        except Exception as exc:
            logger.warning("pgvector_connection_failed", error=str(exc))
            self._pool = None

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _ensure_table(self) -> None:
        """Verify the embeddings table exists and has required columns.

        The table may have been created by an external ingestion process
        with a different column layout (entity_fqn, source_text, etc.).
        We detect the actual schema and adapt queries accordingly.
        """
        if self._pool is None:
            return

        table = self._settings.pgvector_table

        async with self._pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector;")

            # Check if the table already exists
            exists = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
                "WHERE table_name = $1)",
                table,
            )

            if exists:
                # Check which schema variant we have
                has_entity_fqn = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM information_schema.columns "
                    "WHERE table_name = $1 AND column_name = 'entity_fqn')",
                    table,
                )
                self._legacy_schema = bool(has_entity_fqn)
                if self._legacy_schema:
                    logger.info(
                        "pgvector_using_legacy_schema",
                        table=table,
                        note="entity_fqn/source_text columns detected",
                    )
                return

            # Table doesn't exist -- create with our expected schema
            dim = self._settings.embedding_dimensions
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    id TEXT PRIMARY KEY,
                    embedding vector({dim}),
                    table_name TEXT NOT NULL DEFAULT '',
                    database_name TEXT NOT NULL DEFAULT '',
                    metadata JSONB NOT NULL DEFAULT '{{}}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)
            # HNSW index for cosine distance
            await conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{table}_hnsw
                ON {table}
                USING hnsw (embedding vector_cosine_ops)
                WITH (m = 16, ef_construction = 200);
            """)
            self._legacy_schema = False

    async def _load_real_tables(self) -> None:
        """Discover which tables actually exist in the database.

        This lets us filter out embedding candidates for tables that were
        ingested from a different schema but don't exist in the live DB.
        """
        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
                )
                self._real_tables = {row["table_name"].lower() for row in rows}
                # Exclude meta tables
                self._real_tables.discard("schema_embeddings")
                self._real_tables.discard("table_embeddings")
                self._real_tables.discard("api_access_log")
                logger.info("real_tables_loaded", count=len(self._real_tables), tables=sorted(self._real_tables))
        except Exception as exc:
            logger.warning("real_tables_load_failed", error=str(exc))
            self._real_tables = set()

    async def search(
        self,
        embedding: list[float],
        top_k: int = 10,
        database_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search for nearest neighbors using cosine similarity.

        Args:
            embedding: Query vector.
            top_k: Maximum number of results.
            database_filter: Optional database name filter.

        Returns:
            List of dicts with id, score, table_name, metadata.
        """
        if self._pool is None:
            logger.warning("pgvector_search_skipped", reason="not connected")
            return []

        table = self._settings.pgvector_table
        vec_literal = "[" + ",".join(str(v) for v in embedding) + "]"

        if getattr(self, "_legacy_schema", False):
            return await self._search_legacy(table, vec_literal, top_k, database_filter)

        # Standard schema (table_name, database_name, metadata columns)
        if database_filter:
            query = f"""
                SELECT id, table_name, metadata,
                       1 - (embedding <=> $1::vector) AS score
                FROM {table}
                WHERE database_name = $2
                ORDER BY embedding <=> $1::vector
                LIMIT $3;
            """
            params = (vec_literal, database_filter, top_k)
        else:
            query = f"""
                SELECT id, table_name, metadata,
                       1 - (embedding <=> $1::vector) AS score
                FROM {table}
                ORDER BY embedding <=> $1::vector
                LIMIT $2;
            """
            params = (vec_literal, top_k)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        results = []
        for row in rows:
            meta = row["metadata"]
            if isinstance(meta, str):
                meta = json.loads(meta)
            results.append({
                "id": row["id"],
                "score": float(row["score"]),
                "table_name": row["table_name"],
                "metadata": meta,
            })

        logger.debug(
            "pgvector_search_complete",
            top_k=top_k,
            results_found=len(results),
            database_filter=database_filter,
        )

        return results

    async def _search_legacy(
        self,
        table: str,
        vec_literal: str,
        top_k: int,
        database_filter: str | None,
    ) -> list[dict[str, Any]]:
        """Search using the legacy schema (entity_fqn, source_text, entity_type).

        When _real_tables is populated, filters out candidates whose table
        doesn't actually exist in the database — prevents the LLM from
        generating SQL for phantom tables that only exist in embeddings.
        Fetches extra rows to compensate for filtering.
        """
        # Fetch many more rows when filtering to real tables — most embeddings
        # may reference phantom tables that don't exist in the live DB.
        # With 28 embedded tables but only 4 real ones (~85% phantom),
        # we need a large over-fetch to guarantee enough real results.
        fetch_limit = top_k * 20 if self._real_tables else top_k

        query = f"""
            SELECT id, entity_type, entity_fqn, source_text,
                   1 - (embedding <=> $1::vector) AS score
            FROM {table}
            WHERE is_active = true
            ORDER BY embedding <=> $1::vector
            LIMIT $2;
        """
        params = (vec_literal, fetch_limit)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        results = []
        skipped_tables: set[str] = set()
        for row in rows:
            fqn = row["entity_fqn"] or ""
            table_name = _extract_table_name(fqn)
            database_name = _extract_database_name(fqn)

            # Apply database filter if provided
            if database_filter and database_name.lower() != database_filter.lower():
                continue

            # Filter to real tables only (skip phantom tables from stale embeddings)
            if self._real_tables and table_name.lower() not in self._real_tables:
                skipped_tables.add(table_name)
                continue

            metadata = {
                "entity_type": row["entity_type"],
                "entity_fqn": fqn,
                "source_text": row["source_text"] or "",
            }
            results.append({
                "id": str(row["id"]),
                "score": float(row["score"]),
                "table_name": table_name,
                "metadata": metadata,
            })

            if len(results) >= top_k:
                break

        logger.debug(
            "pgvector_search_complete",
            top_k=top_k,
            results_found=len(results),
            database_filter=database_filter,
            schema="legacy",
            skipped_phantom_tables=sorted(skipped_tables) if skipped_tables else None,
        )

        return results

    async def get_all_columns_for_tables(
        self, table_names: list[str]
    ) -> dict[str, list[dict[str, str]]]:
        """Fetch all column metadata for the given tables from embeddings.

        Returns a dict mapping table_name -> list of {entity_fqn, source_text, entity_type}.
        Used to enrich the LLM context with complete schema info for matched tables.
        """
        if self._pool is None or not table_names:
            return {}

        table = self._settings.pgvector_table

        if getattr(self, "_legacy_schema", False):
            # Build LIKE patterns for each table
            patterns = [f"%.{t}" for t in table_names] + [f"%.{t}.%" for t in table_names]
            # Query all embeddings for these tables
            like_clauses = " OR ".join(f"entity_fqn LIKE ${i+1}" for i in range(len(patterns)))
            query = f"""
                SELECT entity_type, entity_fqn, source_text
                FROM {table}
                WHERE is_active = true AND ({like_clauses})
                ORDER BY entity_fqn;
            """
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(query, *patterns)

            result: dict[str, list[dict[str, str]]] = {}
            for row in rows:
                fqn = row["entity_fqn"] or ""
                tname = _extract_table_name(fqn)
                result.setdefault(tname, []).append({
                    "entity_type": row["entity_type"],
                    "entity_fqn": fqn,
                    "source_text": row["source_text"] or "",
                })
            return result

        return {}

    async def upsert(
        self,
        id: str,
        embedding: list[float],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Insert or update an embedding in the vector store.

        Args:
            id: Unique identifier for the embedding.
            embedding: The vector to store.
            metadata: Optional metadata dict (should include table_name, database_name).
        """
        if self._pool is None:
            raise RuntimeError("VectorStore not connected -- call connect() first")

        metadata = metadata or {}
        table = self._settings.pgvector_table
        vec_literal = "[" + ",".join(str(v) for v in embedding) + "]"
        table_name = metadata.pop("table_name", "")
        database_name = metadata.pop("database_name", "")
        meta_json = json.dumps(metadata)

        query = f"""
            INSERT INTO {table} (id, embedding, table_name, database_name, metadata, updated_at)
            VALUES ($1, $2::vector, $3, $4, $5::jsonb, NOW())
            ON CONFLICT (id) DO UPDATE SET
                embedding = EXCLUDED.embedding,
                table_name = EXCLUDED.table_name,
                database_name = EXCLUDED.database_name,
                metadata = EXCLUDED.metadata,
                updated_at = NOW();
        """

        async with self._pool.acquire() as conn:
            await conn.execute(query, id, vec_literal, table_name, database_name, meta_json)

    async def get_catalog(
        self, database_filter: str | None = None
    ) -> list[dict[str, Any]]:
        """Get a summary of indexed schema elements.

        Returns list of {database_name, table_name, element_count}.
        """
        if self._pool is None:
            return []

        table = self._settings.pgvector_table

        if getattr(self, "_legacy_schema", False):
            return await self._get_catalog_legacy(table, database_filter)

        if database_filter:
            query = f"""
                SELECT database_name, table_name, COUNT(*) AS element_count
                FROM {table}
                WHERE database_name = $1
                GROUP BY database_name, table_name
                ORDER BY database_name, table_name;
            """
            params = (database_filter,)
        else:
            query = f"""
                SELECT database_name, table_name, COUNT(*) AS element_count
                FROM {table}
                GROUP BY database_name, table_name
                ORDER BY database_name, table_name;
            """
            params = ()

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            {
                "database_name": row["database_name"],
                "table_name": row["table_name"],
                "element_count": row["element_count"],
            }
            for row in rows
        ]

    async def _get_catalog_legacy(
        self, table: str, database_filter: str | None
    ) -> list[dict[str, Any]]:
        """Get catalog using the legacy schema (entity_fqn)."""
        query = f"""
            SELECT entity_fqn, entity_type, COUNT(*) AS cnt
            FROM {table}
            WHERE is_active = true AND entity_type = 'table'
            GROUP BY entity_fqn, entity_type
            ORDER BY entity_fqn;
        """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query)

        results = []
        for row in rows:
            fqn = row["entity_fqn"] or ""
            db_name = _extract_database_name(fqn)
            tbl_name = _extract_table_name(fqn)

            if database_filter and db_name.lower() != database_filter.lower():
                continue

            results.append({
                "database_name": db_name,
                "table_name": tbl_name,
                "element_count": row["cnt"],
            })

        return results

    async def delete(self, id: str) -> bool:
        """Delete an embedding by ID. Returns True if a row was deleted."""
        if self._pool is None:
            raise RuntimeError("VectorStore not connected")

        table = self._settings.pgvector_table
        async with self._pool.acquire() as conn:
            result = await conn.execute(f"DELETE FROM {table} WHERE id = $1;", id)
            return result == "DELETE 1"

    async def health_check(self) -> bool:
        """Check pgvector connectivity."""
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                await conn.fetchval("SELECT 1;")
            return True
        except Exception:
            return False
