"""FastAPI application for XenSQL - NL-to-SQL Pipeline Engine.

XenSQL is an LLM-agnostic pipeline that converts natural language questions
into raw SQL. It receives pre-filtered schema from QueryVault and returns
generated SQL. It does NOT handle auth, RBAC, validation, execution, or audit.

Port: 8900
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from xensql.app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()

# -- Connections ---------------------------------------------------------------

_redis_pool = None
_neo4j_driver = None


async def _connect_redis():
    """Initialize Redis connection pool."""
    global _redis_pool
    try:
        import redis.asyncio as aioredis

        _redis_pool = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=settings.redis_max_connections,
        )
        await _redis_pool.ping()
        logger.info("redis_connected", url=settings.redis_url)
    except Exception as exc:
        logger.warning("redis_connection_failed", error=str(exc))
        _redis_pool = None


async def _disconnect_redis():
    """Close Redis connection pool."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.close()
        _redis_pool = None
        logger.info("redis_disconnected")


async def _connect_neo4j():
    """Initialize Neo4j async driver."""
    global _neo4j_driver
    try:
        from neo4j import AsyncGraphDatabase

        _neo4j_driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        async with _neo4j_driver.session() as session:
            await session.run("RETURN 1")
        logger.info("neo4j_connected", uri=settings.neo4j_uri)
    except Exception as exc:
        logger.warning("neo4j_connection_failed", error=str(exc))
        _neo4j_driver = None


async def _disconnect_neo4j():
    """Close Neo4j driver."""
    global _neo4j_driver
    if _neo4j_driver is not None:
        await _neo4j_driver.close()
        _neo4j_driver = None
        logger.info("neo4j_disconnected")


def get_redis():
    """Return the active Redis pool (or None)."""
    return _redis_pool


def get_neo4j():
    """Return the active Neo4j driver (or None)."""
    return _neo4j_driver


# -- Lifespan -----------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle -- startup and shutdown."""
    logger.info(
        "xensql_starting",
        port=settings.service_port,
        env=settings.app_env,
        primary_llm=settings.llm_primary_provider,
    )
    await _connect_redis()
    await _connect_neo4j()
    yield
    await _disconnect_redis()
    await _disconnect_neo4j()
    logger.info("xensql_stopped")


# -- Application ---------------------------------------------------------------

app = FastAPI(
    title="XenSQL - NL-to-SQL Pipeline Engine",
    description=(
        "LLM-agnostic pipeline engine that converts natural language questions "
        "into raw SQL queries. Receives pre-filtered schema from QueryVault and "
        "orchestrates embedding, retrieval, context optimization, and SQL "
        "generation across multiple LLM providers."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- Routes --------------------------------------------------------------------

from xensql.app.api.routes import router as pipeline_router  # noqa: E402

app.include_router(pipeline_router, prefix="/api/v1")


@app.get("/health")
async def health():
    """Quick liveness probe."""
    return {"status": "ok", "service": "xensql", "version": "1.0.0"}
