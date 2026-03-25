"""XenSQL Pipeline API routes.

POST /api/v1/pipeline/query   - Main NL-to-SQL endpoint
POST /api/v1/pipeline/embed   - Embed text for semantic search
GET  /api/v1/pipeline/health  - Health check with component status
POST /api/v1/schema/crawl     - Trigger schema crawl
GET  /api/v1/schema/catalog   - Get schema catalog
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException

from xensql.app.config import Settings, get_settings
from xensql.app.models.api import (
    HealthResponse,
    PipelineRequest,
    PipelineResponse,
)
from xensql.app.models.enums import PipelineStatus
from xensql.app.services.pipeline_orchestrator import PipelineOrchestrator
from xensql.app.clients.embedding_client import EmbeddingClient
from xensql.app.clients.vector_store import VectorStore

logger = structlog.get_logger(__name__)
router = APIRouter()


# -- Dependency injection ------------------------------------------------------


def _get_orchestrator(
    settings: Settings = Depends(get_settings),
) -> PipelineOrchestrator:
    """Provide a PipelineOrchestrator instance."""
    return PipelineOrchestrator(settings)


def _get_embedding_client(
    settings: Settings = Depends(get_settings),
) -> EmbeddingClient:
    """Provide an EmbeddingClient instance."""
    return EmbeddingClient(settings)


def _get_vector_store(
    settings: Settings = Depends(get_settings),
) -> VectorStore:
    """Provide a VectorStore instance."""
    return VectorStore(settings)


# -- Pipeline routes -----------------------------------------------------------


@router.post("/pipeline/query", response_model=PipelineResponse)
async def pipeline_query(
    request: PipelineRequest,
    orchestrator: PipelineOrchestrator = Depends(_get_orchestrator),
) -> PipelineResponse:
    """Execute the NL-to-SQL pipeline.

    Accepts a natural language question with pre-filtered schema from
    QueryVault. Runs the full pipeline (ambiguity check, intent
    classification, embedding, context optimization, SQL generation,
    confidence scoring) and returns the generated SQL.

    The generated SQL is NOT validated or executed here.
    """
    logger.info(
        "pipeline_query_received",
        question_len=len(request.question),
        tables_in_schema=len(request.filtered_schema.get("tables", [])),
        session_id=request.session_id,
    )

    response = await orchestrator.execute(request)

    if response.status == PipelineStatus.ERROR and response.error_code:
        code_to_status = {
            "NO_TABLES_FOUND": 404,
            "LLM_PROVIDER_ERROR": 503,
            "GENERATION_FAILED": 502,
            "TOKEN_BUDGET_EXCEEDED": 422,
        }
        http_status = code_to_status.get(response.error_code.value, 500)
        if http_status >= 500:
            logger.error(
                "pipeline_server_error",
                request_id=response.request_id,
                error_code=response.error_code.value,
                error=response.error,
            )

    return response


@router.post("/pipeline/embed")
async def embed_text(
    payload: dict[str, Any],
    embedding_client: EmbeddingClient = Depends(_get_embedding_client),
) -> dict[str, Any]:
    """Embed text for semantic search.

    Accepts {"text": "...", "batch": false} or {"texts": [...], "batch": true}.
    Returns the embedding vector(s).
    """
    is_batch = payload.get("batch", False)

    try:
        await embedding_client.connect()

        if is_batch:
            texts = payload.get("texts", [])
            if not texts:
                raise HTTPException(status_code=400, detail="'texts' list is required for batch mode")
            embeddings = await embedding_client.embed_batch(texts)
            return {"embeddings": embeddings, "count": len(embeddings)}
        else:
            text = payload.get("text", "")
            if not text:
                raise HTTPException(status_code=400, detail="'text' is required")
            embedding = await embedding_client.embed(text)
            return {"embedding": embedding, "dimensions": len(embedding)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("embed_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Embedding failed: {exc}")
    finally:
        await embedding_client.close()


@router.get("/pipeline/health", response_model=HealthResponse)
async def pipeline_health(
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Health check with component status.

    Reports connectivity to Redis, Neo4j, pgvector, and LLM providers.
    """
    from xensql.app.main import get_redis, get_neo4j

    dependencies: dict[str, bool] = {}

    # Redis
    redis = get_redis()
    if redis is not None:
        try:
            await redis.ping()
            dependencies["redis"] = True
        except Exception:
            dependencies["redis"] = False
    else:
        dependencies["redis"] = False

    # Neo4j
    neo4j = get_neo4j()
    if neo4j is not None:
        try:
            async with neo4j.session() as session:
                await session.run("RETURN 1")
            dependencies["neo4j"] = True
        except Exception:
            dependencies["neo4j"] = False
    else:
        dependencies["neo4j"] = False

    # pgvector
    try:
        store = VectorStore(settings)
        await store.connect()
        dependencies["pgvector"] = await store.health_check()
        await store.close()
    except Exception:
        dependencies["pgvector"] = False

    overall = "ok" if all(dependencies.values()) else "degraded"

    return HealthResponse(
        status=overall,
        service="xensql",
        version="1.0.0",
        dependencies=dependencies,
    )


# -- Schema routes -------------------------------------------------------------


@router.post("/schema/crawl")
async def schema_crawl(
    payload: dict[str, Any],
    vector_store: VectorStore = Depends(_get_vector_store),
    embedding_client: EmbeddingClient = Depends(_get_embedding_client),
) -> dict[str, Any]:
    """Trigger a schema crawl -- embed and upsert schema elements.

    Accepts {"elements": [{"id": "...", "text": "...", "metadata": {...}}]}.
    Embeds each element and upserts into the vector store.
    """
    elements = payload.get("elements", [])
    if not elements:
        raise HTTPException(status_code=400, detail="'elements' list is required")

    start = time.monotonic()

    try:
        await embedding_client.connect()
        await vector_store.connect()

        texts = [el["text"] for el in elements]
        embeddings = await embedding_client.embed_batch(texts)

        upserted = 0
        for el, emb in zip(elements, embeddings):
            await vector_store.upsert(
                id=el["id"],
                embedding=emb,
                metadata=el.get("metadata", {}),
            )
            upserted += 1

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "status": "ok",
            "elements_processed": upserted,
            "elapsed_ms": round(elapsed_ms, 1),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("schema_crawl_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Schema crawl failed: {exc}")
    finally:
        await embedding_client.close()
        await vector_store.close()


@router.get("/schema/catalog")
async def schema_catalog(
    database: str | None = None,
    vector_store: VectorStore = Depends(_get_vector_store),
) -> dict[str, Any]:
    """Get the schema catalog from the vector store.

    Returns a summary of indexed schema elements, optionally filtered by database.
    """
    try:
        await vector_store.connect()
        catalog = await vector_store.get_catalog(database_filter=database)
        return {"catalog": catalog}
    except Exception as exc:
        logger.error("schema_catalog_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Catalog retrieval failed: {exc}")
    finally:
        await vector_store.close()
