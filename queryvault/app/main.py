"""FastAPI application for QueryVault AI Security Framework.

QueryVault wraps NL-to-SQL pipelines (XenSQL) at 5 independent security zones.
Port 8950.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from queryvault.app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# ── Resource handles initialised at startup ──────────────────

_redis: Any = None
_neo4j_driver: Any = None
_audit_pool: Any = None
_circuit_breakers: dict[str, Any] = {}


async def _init_redis() -> Any:
    """Connect to Redis for behavioral fingerprints and probing detection."""
    import redis.asyncio as aioredis

    pool = aioredis.ConnectionPool.from_url(
        settings.redis_url,
        max_connections=settings.redis_max_connections,
        decode_responses=True,
    )
    client = aioredis.Redis(connection_pool=pool)
    await client.ping()
    logger.info("redis_connected", url=settings.redis_url)
    return client


async def _init_neo4j() -> Any:
    """Connect to Neo4j for policy graph queries."""
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
        database=settings.neo4j_database,
    )
    await driver.verify_connectivity()
    logger.info("neo4j_connected", uri=settings.neo4j_uri)
    return driver


async def _init_audit_pool() -> Any:
    """Create a PostgreSQL connection pool for the audit store."""
    import asyncpg

    pool = await asyncpg.create_pool(
        dsn=settings.postgres_dsn,
        min_size=settings.postgres_pool_min,
        max_size=settings.postgres_pool_max,
    )
    logger.info("audit_pool_created", dsn=settings.postgres_dsn.split("@")[-1])
    return pool


def _init_circuit_breakers() -> dict[str, Any]:
    """Initialise circuit breakers for downstream services."""
    breakers: dict[str, Any] = {}
    services = ["xensql", "neo4j", "redis", "audit_store"]
    for svc in services:
        breakers[svc] = {
            "state": "CLOSED",
            "failure_count": 0,
            "failure_threshold": settings.circuit_breaker_failure_threshold,
            "recovery_timeout": settings.circuit_breaker_recovery_timeout,
            "half_open_max_calls": settings.circuit_breaker_half_open_max_calls,
            "last_failure_time": None,
        }
    logger.info("circuit_breakers_initialised", services=services)
    return breakers


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Manage application lifecycle -- startup and shutdown."""
    global _redis, _neo4j_driver, _audit_pool, _circuit_breakers

    logger.info("queryvault_starting", port=settings.app_port, env=settings.app_env)

    # Initialise circuit breakers (always)
    _circuit_breakers = _init_circuit_breakers()

    try:
        _redis = await _init_redis()
    except Exception as exc:
        logger.warning("redis_init_failed", error=str(exc))

    try:
        _neo4j_driver = await _init_neo4j()
    except Exception as exc:
        logger.warning("neo4j_init_failed", error=str(exc))

    try:
        _audit_pool = await _init_audit_pool()
    except Exception as exc:
        logger.warning("audit_pool_init_failed", error=str(exc))

    logger.info("queryvault_started")

    yield

    # ── Shutdown ─────────────────────────────────────────────
    logger.info("queryvault_shutting_down")

    if _redis:
        await _redis.aclose()
        logger.info("redis_closed")

    if _neo4j_driver:
        await _neo4j_driver.close()
        logger.info("neo4j_closed")

    if _audit_pool:
        await _audit_pool.close()
        logger.info("audit_pool_closed")

    logger.info("queryvault_stopped")


# ── Accessor functions for shared resources ──────────────────


def get_redis() -> Any:
    return _redis


def get_neo4j() -> Any:
    return _neo4j_driver


def get_audit_pool() -> Any:
    return _audit_pool


def get_circuit_breakers() -> dict[str, Any]:
    return _circuit_breakers


# ── FastAPI application ──────────────────────────────────────

app = FastAPI(
    title="QueryVault - AI Security Framework",
    description=(
        "Security framework that wraps NL-to-SQL pipelines at 5 independent "
        "security zones. Provides adaptive query defense, SQL accuracy guard, "
        "compliance reporting, and real-time threat monitoring."
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

# ── Route registration ───────────────────────────────────────

from queryvault.app.api import (  # noqa: E402
    alert_routes,
    compliance_routes,
    gateway_routes,
    mock_users_routes,
    policy_routes,
    threat_routes,
)

app.include_router(gateway_routes.router, prefix="/api/v1")
app.include_router(compliance_routes.router, prefix="/api/v1")
app.include_router(threat_routes.router, prefix="/api/v1")
app.include_router(alert_routes.router, prefix="/api/v1")
app.include_router(mock_users_routes.router, prefix="/api/v1")
app.include_router(policy_routes.router, prefix="/api/v1")


# ── Root health endpoint ─────────────────────────────────────


@app.get("/health")
async def health():
    """Basic liveness probe."""
    return {
        "status": "ok",
        "service": "queryvault",
        "version": "1.0.0",
        "port": settings.app_port,
    }
