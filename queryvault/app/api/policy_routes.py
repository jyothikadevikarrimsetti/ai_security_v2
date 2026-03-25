"""Policy Management API routes.

CRUD operations for role policies, table classification, and column metadata.
All changes are persisted to Neo4j and reflected in the NL-to-SQL pipeline.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from queryvault.app.clients.graph_client import GraphClient
from queryvault.app.config import get_settings

router = APIRouter(tags=["policies"])


# ── Request/Response models ─────────────────────────────


class RolePolicyUpdate(BaseModel):
    allowed_tables: list[str] = []
    denied_tables: list[str] = []
    denied_operations: list[str] = []
    row_filters: list[dict[str, str]] = []  # [{table, condition}]
    domains: list[str] = []
    result_limit: int | None = None  # Per-role max rows returned (e.g. 50)


class TableMetadataUpdate(BaseModel):
    sensitivity_level: int = Field(ge=1, le=5)
    domain: str


class ColumnMetadataUpdate(BaseModel):
    classification_level: int = Field(ge=1, le=5)
    default_visibility: str = "VISIBLE"  # VISIBLE | MASKED | HIDDEN


# ── Helpers ──────────────────────────────────────────────


def _get_graph() -> GraphClient:
    from queryvault.app.main import get_neo4j
    driver = get_neo4j()
    if not driver:
        raise HTTPException(503, "Neo4j not connected")
    return GraphClient(get_settings(), driver=driver)


# ── Role endpoints ──────────────────────────────────────


@router.get("/policies/roles")
async def list_roles() -> dict[str, Any]:
    """List all roles with their policy summaries."""
    graph = _get_graph()
    roles = await graph.list_roles_with_policies()
    return {"roles": roles}


@router.get("/policies/roles/{role_name}")
async def get_role(role_name: str) -> dict[str, Any]:
    """Get full policy detail for a role."""
    graph = _get_graph()
    detail = await graph.get_role_detail(role_name)
    if not detail:
        raise HTTPException(404, f"Role not found: {role_name}")
    return detail


@router.put("/policies/roles/{role_name}")
async def update_role(role_name: str, body: RolePolicyUpdate) -> dict[str, Any]:
    """Update policies for a role (replaces all policy edges)."""
    graph = _get_graph()
    # Verify role exists
    detail = await graph.get_role_detail(role_name)
    if not detail:
        raise HTTPException(404, f"Role not found: {role_name}")
    ok = await graph.update_role_policies(role_name, body.model_dump())
    if not ok:
        raise HTTPException(500, "Failed to update role policies")
    return {"updated": True, "role": role_name}


# ── Table endpoints ─────────────────────────────────────


@router.get("/policies/tables")
async def list_tables() -> dict[str, Any]:
    """List tables with sensitivity and domain metadata."""
    graph = _get_graph()
    tables = await graph.list_tables_with_metadata()
    return {"tables": tables}


@router.put("/policies/tables/{table_name}")
async def update_table(table_name: str, body: TableMetadataUpdate) -> dict[str, Any]:
    """Update table sensitivity level and domain."""
    graph = _get_graph()
    ok = await graph.update_table_metadata(table_name, body.sensitivity_level, body.domain)
    if not ok:
        raise HTTPException(500, "Failed to update table metadata")
    return {"updated": True, "table": table_name}


# ── Column endpoints ────────────────────────────────────


@router.get("/policies/columns/{table_name}")
async def list_columns(table_name: str) -> dict[str, Any]:
    """List columns for a table with classification metadata."""
    graph = _get_graph()
    columns = await graph.list_columns_for_table(table_name)
    return {"table": table_name, "columns": columns}


@router.put("/policies/columns/{table_name}/{column_name}")
async def update_column(
    table_name: str, column_name: str, body: ColumnMetadataUpdate,
) -> dict[str, Any]:
    """Update a column's classification level and visibility."""
    graph = _get_graph()
    ok = await graph.update_column_metadata(
        table_name, column_name,
        body.classification_level, body.default_visibility,
    )
    if not ok:
        raise HTTPException(500, "Failed to update column metadata")
    return {"updated": True, "table": table_name, "column": column_name}


# ── Sync endpoint ───────────────────────────────────────


@router.post("/policies/sync")
async def sync_policies() -> dict[str, Any]:
    """Re-seed Neo4j from hardcoded policy definitions."""
    from queryvault.app.main import get_neo4j
    from queryvault.scripts.seed_neo4j import seed_all

    settings = get_settings()
    driver = get_neo4j()
    if not driver:
        raise HTTPException(503, "Neo4j not connected")

    stats = await seed_all(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password,
        neo4j_database=settings.neo4j_database,
    )
    return {"synced": True, "stats": stats}
