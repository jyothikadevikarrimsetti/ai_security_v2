"""QueryVault Gateway API routes.

POST /api/v1/gateway/query  -- Main security gateway endpoint
GET  /api/v1/gateway/health -- Health check with component status
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException

from queryvault.app.config import get_settings
from queryvault.app.models.api import GatewayQueryRequest, GatewayQueryResponse
from queryvault.app.services.gateway_orchestrator import GatewayOrchestrator
from queryvault.app.clients.xensql_client import XenSQLClient
from queryvault.app.clients.graph_client import GraphClient
from queryvault.app.main import get_redis, get_neo4j, get_audit_pool, get_circuit_breakers

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["gateway"])
settings = get_settings()


@router.post("/gateway/query", response_model=GatewayQueryResponse)
async def gateway_query(request: GatewayQueryRequest) -> GatewayQueryResponse:
    """Execute the full security-wrapped NL-to-SQL pipeline.

    Wraps XenSQL at 5 security zones:
      Zone 1 PRE-MODEL:      Identity, injection scan, probing defense, behavioral check, RBAC
      Zone 2 MODEL BOUNDARY:  Context minimization + XenSQL pipeline call
      Zone 3 POST-MODEL:      3-gate validation + hallucination detection + query rewriting
      Zone 4 EXECUTION:       Circuit breaker + resource-bounded execution + result sanitization
      Zone 5 CONTINUOUS:       Audit event ingestion + anomaly detection + alert processing
    """
    xensql_client = XenSQLClient(settings)
    graph_client = GraphClient(settings, get_neo4j())

    orchestrator = GatewayOrchestrator(
        settings=settings,
        xensql_client=xensql_client,
        graph_client=graph_client,
        redis=get_redis(),
        audit_pool=get_audit_pool(),
        circuit_breakers=get_circuit_breakers(),
    )

    try:
        return await orchestrator.process(request)
    except Exception as exc:
        logger.error("gateway_query_failed", error=str(exc))
        raise HTTPException(status_code=500, detail="Internal security gateway error")


@router.get("/gateway/health")
async def gateway_health() -> dict:
    """Health check with component status for all downstream dependencies."""
    components: dict[str, str] = {}

    # Redis
    redis = get_redis()
    if redis:
        try:
            await redis.ping()
            components["redis"] = "healthy"
        except Exception:
            components["redis"] = "unhealthy"
    else:
        components["redis"] = "not_connected"

    # Neo4j
    neo4j = get_neo4j()
    if neo4j:
        try:
            await neo4j.verify_connectivity()
            components["neo4j"] = "healthy"
        except Exception:
            components["neo4j"] = "unhealthy"
    else:
        components["neo4j"] = "not_connected"

    # Audit store (PostgreSQL)
    audit_pool = get_audit_pool()
    if audit_pool:
        try:
            async with audit_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            components["audit_store"] = "healthy"
        except Exception:
            components["audit_store"] = "unhealthy"
    else:
        components["audit_store"] = "not_connected"

    # XenSQL (HTTP health check)
    xensql_client = XenSQLClient(settings)
    try:
        healthy = await xensql_client.health_check()
        components["xensql"] = "healthy" if healthy else "unhealthy"
    except Exception:
        components["xensql"] = "unhealthy"

    # Circuit breakers
    breakers = get_circuit_breakers()
    for name, breaker in breakers.items():
        components[f"circuit_breaker_{name}"] = breaker.get("state", "UNKNOWN")

    all_healthy = all(
        v in ("healthy", "CLOSED") for v in components.values()
    )
    overall = "ok" if all_healthy else "degraded"

    return {
        "status": overall,
        "service": "queryvault",
        "version": "1.0.0",
        "components": components,
    }
