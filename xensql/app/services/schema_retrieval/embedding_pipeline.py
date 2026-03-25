"""Embedding Pipeline -- generates semantic vectors from schema metadata.

Embeds table descriptions, column descriptions, and composite text into
pgvector for semantic retrieval. Only re-embeds when source text changes
(hash-based idempotency). The vector DB is fully regenerable from schema.

XenSQL is a pure NL-to-SQL pipeline engine. No auth/RBAC concerns.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

import httpx
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from xensql.app.models.schema import ColumnInfo, TableInfo

logger = structlog.get_logger(__name__)

# Default embedding dimensions (OpenAI text-embedding-ada-002 / Azure equivalent)
_DEFAULT_DIMS = 1536


class EmbeddingPipeline:
    """Generates, stores, and manages semantic embeddings for schema metadata.

    Stores vectors in a pgvector-enabled PostgreSQL table. Supports both
    standard OpenAI and Azure OpenAI embedding endpoints.
    """

    def __init__(
        self,
        pgvector_dsn: str,
        embedding_api_key: str = "",
        embedding_api_base: str = "https://api.openai.com/v1",
        embedding_model: str = "text-embedding-ada-002",
        embedding_dims: int = _DEFAULT_DIMS,
        use_ssl: bool = False,
    ) -> None:
        self._dsn = pgvector_dsn
        self._api_key = embedding_api_key
        self._api_base = embedding_api_base.rstrip("/")
        self._model = embedding_model
        self._dims = embedding_dims
        self._use_ssl = use_ssl
        self._engine: AsyncEngine | None = None
        self._session_factory: sessionmaker | None = None
        self._http_client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Initialize async engine and HTTP client, ensure DB schema exists."""
        connect_args: dict[str, Any] = {}
        clean_dsn = self._dsn.split("?")[0] if "?" in self._dsn else self._dsn

        if self._use_ssl and "localhost" not in clean_dsn and "127.0.0.1" not in clean_dsn:
            import ssl as _ssl
            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE
            connect_args["ssl"] = ssl_ctx

        self._engine = create_async_engine(
            clean_dsn,
            pool_size=2,
            max_overflow=2,
            connect_args=connect_args,
        )
        self._session_factory = sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )
        self._http_client = httpx.AsyncClient(timeout=30.0)
        await self._ensure_schema()
        logger.info("embedding_pipeline_connected")

    async def close(self) -> None:
        """Dispose engine and close HTTP client."""
        if self._engine:
            await self._engine.dispose()
        if self._http_client:
            await self._http_client.aclose()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def embed_schema(
        self,
        tables: list[TableInfo],
        *,
        progress_callback: Any | None = None,
    ) -> dict[str, int]:
        """Embed all provided tables and their columns.

        Only re-embeds when source text has changed (hash comparison).

        Args:
            tables: Tables to embed (with columns populated).
            progress_callback: Optional async callable(processed, total)
                              for progress tracking.

        Returns:
            Stats dict with keys: processed, embedded, skipped.
        """
        stats = {"processed": 0, "embedded": 0, "skipped": 0}
        total = len(tables)

        for table in tables:
            stats["processed"] += 1

            # Build composite source text
            col_parts = []
            for c in table.columns:
                entry = f"{c.column_name} ({c.data_type})"
                if c.description:
                    entry += f": {c.description}"
                col_parts.append(entry)
            col_descriptions = ", ".join(col_parts)

            source_text = (
                f"Table: {table.table_name}\n"
                f"Description: {table.description}\n"
                f"Domain: {table.domain.value if table.domain else ''}\n"
                f"Columns: {col_descriptions}"
            )
            source_hash = hashlib.sha256(source_text.encode()).hexdigest()

            # Skip if already embedded with same hash
            if await self._has_current_embedding(table.table_id, source_hash):
                stats["skipped"] += 1
                if progress_callback:
                    await progress_callback(stats["processed"], total)
                continue

            # Generate and store table embedding
            embedding = await self._generate_embedding(source_text)
            if embedding is None:
                if progress_callback:
                    await progress_callback(stats["processed"], total)
                continue

            await self._store_embedding(
                entity_type="table",
                entity_fqn=table.table_id,
                source_text=source_text,
                source_hash=source_hash,
                embedding=embedding,
            )
            stats["embedded"] += 1

            # Embed individual columns for column-level semantic search
            for col in table.columns:
                col_text = (
                    f"Column {col.column_name} ({col.data_type}) "
                    f"in {table.table_name}"
                )
                if col.description:
                    col_text += f": {col.description}"

                col_hash = hashlib.sha256(col_text.encode()).hexdigest()
                col_fqn = (
                    col.column_id
                    if col.column_id
                    else f"{table.table_id}.{col.column_name}"
                )

                if not await self._has_current_embedding(col_fqn, col_hash):
                    col_embedding = await self._generate_embedding(col_text)
                    if col_embedding:
                        await self._store_embedding(
                            entity_type="column",
                            entity_fqn=col_fqn,
                            source_text=col_text,
                            source_hash=col_hash,
                            embedding=col_embedding,
                        )

            if progress_callback:
                await progress_callback(stats["processed"], total)

        logger.info("embed_schema_complete", **stats)
        return stats

    async def update_embeddings(
        self,
        changed_tables: list[TableInfo],
    ) -> dict[str, int]:
        """Re-embed only the tables that have changed.

        This is a convenience wrapper around embed_schema that processes
        only the delta. Unchanged tables (same source hash) are skipped
        automatically.

        Args:
            changed_tables: Tables whose schema has changed.

        Returns:
            Stats dict with keys: processed, embedded, skipped.
        """
        if not changed_tables:
            return {"processed": 0, "embedded": 0, "skipped": 0}

        logger.info("update_embeddings_start", count=len(changed_tables))
        return await self.embed_schema(changed_tables)

    async def deactivate_embeddings(self, table_ids: list[str]) -> int:
        """Mark embeddings for removed tables as inactive.

        Returns count of deactivated rows.
        """
        if not table_ids:
            return 0

        async with self._get_session() as session:
            result = await session.execute(
                text("""
                    UPDATE schema_embeddings
                    SET is_active = false
                    WHERE entity_fqn = ANY(:ids)
                      AND is_active = true
                """),
                {"ids": table_ids},
            )
            await session.commit()
            count = result.rowcount or 0
            logger.info("embeddings_deactivated", count=count)
            return count

    async def rebuild_all(self, tables: list[TableInfo]) -> dict[str, int]:
        """Full rebuild: clear all embeddings and re-embed everything.

        Args:
            tables: Complete set of tables to embed.

        Returns:
            Stats dict.
        """
        async with self._get_session() as session:
            await session.execute(
                text(
                    "DELETE FROM schema_embeddings "
                    "WHERE entity_type IN ('table', 'column')"
                )
            )
            await session.commit()

        logger.info("embeddings_cleared_for_rebuild")
        return await self.embed_schema(tables)

    # ------------------------------------------------------------------
    # DB schema
    # ------------------------------------------------------------------

    async def _ensure_schema(self) -> None:
        """Ensure the schema_embeddings table exists."""
        async with self._get_session() as session:
            try:
                await session.execute(text(f"""
                    CREATE TABLE IF NOT EXISTS schema_embeddings (
                        id              BIGSERIAL PRIMARY KEY,
                        entity_type     VARCHAR(20)  NOT NULL DEFAULT 'table',
                        entity_fqn      VARCHAR(500) NOT NULL,
                        source_text     TEXT         NOT NULL DEFAULT '',
                        source_hash     TEXT         NOT NULL DEFAULT '',
                        is_active       BOOLEAN      NOT NULL DEFAULT true,
                        embedding       vector({self._dims}),
                        created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                        UNIQUE (entity_fqn, entity_type)
                    )
                """))
                # Ensure source_hash column exists on older tables
                await session.execute(text(
                    "ALTER TABLE schema_embeddings "
                    "ADD COLUMN IF NOT EXISTS source_hash TEXT NOT NULL DEFAULT ''"
                ))
                await session.commit()
                logger.info("embedding_schema_ready")
            except Exception as exc:
                logger.error("embedding_schema_failed", error=str(exc))
                await session.rollback()
                raise

    # ------------------------------------------------------------------
    # Embedding generation
    # ------------------------------------------------------------------

    async def _generate_embedding(self, input_text: str) -> list[float] | None:
        """Call the embedding API. Supports OpenAI and Azure OpenAI.

        Returns None on failure.
        """
        if not self._http_client:
            return None

        azure_endpoint = os.getenv("AZURE_AI_ENDPOINT", "").rstrip("/")
        azure_api_key = os.getenv("AZURE_AI_API_KEY", "")

        if self._api_key:
            # Standard OpenAI
            url = f"{self._api_base}/embeddings"
            headers = {"Authorization": f"Bearer {self._api_key}"}
            body: dict[str, Any] = {
                "model": self._model,
                "input": input_text[:8000],
            }
        elif azure_api_key and azure_endpoint:
            # Azure OpenAI
            url = (
                f"{azure_endpoint}/openai/deployments/"
                f"{self._model}/embeddings?api-version=2024-02-01"
            )
            headers = {"api-key": azure_api_key}
            body = {"input": input_text[:8000]}
        else:
            logger.debug("embedding_api_not_configured")
            return None

        try:
            response = await self._http_client.post(
                url, headers=headers, json=body
            )
            response.raise_for_status()
            data = response.json()
            return data["data"][0]["embedding"]
        except Exception as exc:
            logger.warning("embedding_generation_failed", error=str(exc))
            return None

    # ------------------------------------------------------------------
    # Storage helpers
    # ------------------------------------------------------------------

    async def _has_current_embedding(
        self, entity_fqn: str, source_hash: str
    ) -> bool:
        """Check if an embedding with the same source hash already exists."""
        async with self._get_session() as session:
            result = await session.execute(
                text("""
                    SELECT 1 FROM schema_embeddings
                    WHERE entity_fqn = :fqn
                      AND source_hash = :hash
                    LIMIT 1
                """),
                {"fqn": entity_fqn, "hash": source_hash},
            )
            return result.fetchone() is not None

    async def _store_embedding(
        self,
        entity_type: str,
        entity_fqn: str,
        source_text: str,
        source_hash: str,
        embedding: list[float],
    ) -> None:
        """Insert or update embedding in pgvector."""
        embedding_str = "[" + ",".join(str(x) for x in embedding) + "]"

        async with self._get_session() as session:
            await session.execute(
                text("""
                    INSERT INTO schema_embeddings
                        (entity_type, entity_fqn, source_text, source_hash,
                         is_active, embedding)
                    VALUES
                        (:etype, :fqn, :source, :hash, true,
                         CAST(:embedding AS vector))
                    ON CONFLICT (entity_fqn, entity_type)
                    DO UPDATE SET
                        source_text = EXCLUDED.source_text,
                        source_hash = EXCLUDED.source_hash,
                        embedding   = EXCLUDED.embedding,
                        is_active   = true,
                        created_at  = NOW()
                """),
                {
                    "etype": entity_type,
                    "fqn": entity_fqn,
                    "source": source_text[:10000],
                    "hash": source_hash,
                    "embedding": embedding_str,
                },
            )
            await session.commit()

    def _get_session(self) -> AsyncSession:
        if not self._session_factory:
            raise RuntimeError("Embedding DB not connected -- call connect() first")
        return self._session_factory()
