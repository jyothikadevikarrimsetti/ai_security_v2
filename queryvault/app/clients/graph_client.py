"""Neo4j Graph client for policy queries.

Provides access to the policy graph for RBAC resolution, domain access
mapping, and data classification lookups.
"""

from __future__ import annotations

from typing import Any

import structlog

from queryvault.app.config import Settings

logger = structlog.get_logger(__name__)


class GraphClient:
    """Async Neo4j client for policy graph queries."""

    def __init__(self, settings: Settings, driver: Any = None) -> None:
        self._settings = settings
        self._driver = driver

    async def connect(self) -> None:
        """Initialise the Neo4j driver."""
        from neo4j import AsyncGraphDatabase

        self._driver = AsyncGraphDatabase.driver(
            self._settings.neo4j_uri,
            auth=(self._settings.neo4j_user, self._settings.neo4j_password),
            database=self._settings.neo4j_database,
        )
        await self._driver.verify_connectivity()
        logger.info("graph_client_connected", uri=self._settings.neo4j_uri)

    async def close(self) -> None:
        """Close the Neo4j driver."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("graph_client_closed")

    async def resolve_rbac_policy(self, user_id: str, roles: list[str]) -> dict[str, Any]:
        """Resolve the RBAC policy for a user based on their roles.

        Returns:
            Dict with allowed_tables, denied_tables, denied_operations, row_filters.
        """
        if not self._driver:
            logger.debug("graph_not_connected", method="resolve_rbac_policy")
            return self._default_rbac_policy()

        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """
                    MATCH (u:User {user_id: $user_id})-[:HAS_ROLE]->(r:Role)
                    OPTIONAL MATCH (r)-[:ALLOWS_TABLE]->(t:Table)
                    OPTIONAL MATCH (r)-[:DENIES_TABLE]->(dt:Table)
                    OPTIONAL MATCH (r)-[:DENIES_OP]->(op:Operation)
                    OPTIONAL MATCH (r)-[:ROW_FILTER]->(rf:RowFilter)
                    RETURN
                        collect(DISTINCT t.name) AS allowed_tables,
                        collect(DISTINCT dt.name) AS denied_tables,
                        collect(DISTINCT op.name) AS denied_operations,
                        collect(DISTINCT {table: rf.table, condition: rf.condition}) AS row_filters,
                        min(r.result_limit) AS result_limit
                    """,
                    user_id=user_id,
                )
                record = await result.single()

                if record:
                    return {
                        "allowed_tables": record["allowed_tables"],
                        "denied_tables": record["denied_tables"],
                        "denied_operations": record["denied_operations"],
                        "row_filters": [
                            rf for rf in record["row_filters"]
                            if rf.get("condition")
                        ],
                        "result_limit": record["result_limit"],
                    }
        except Exception as exc:
            logger.warning("rbac_policy_query_failed", error=str(exc))

        return self._default_rbac_policy()

    async def get_user_domains(self, user_id: str) -> list[str]:
        """Get the data domains a user has access to.

        Returns:
            List of domain names (e.g. ["CLINICAL", "ADMINISTRATIVE"]).
        """
        if not self._driver:
            logger.debug("graph_not_connected", method="get_user_domains")
            return []

        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """
                    MATCH (u:User {user_id: $user_id})-[:HAS_ROLE]->(r:Role)
                          -[:ACCESS_DOMAIN]->(d:Domain)
                    RETURN collect(DISTINCT d.name) AS domains
                    """,
                    user_id=user_id,
                )
                record = await result.single()
                if record:
                    return record["domains"]
        except Exception as exc:
            logger.warning("domain_query_failed", error=str(exc))

        return []

    async def get_column_scope(
        self, user_id: str, clearance_level: int, domains: list[str],
    ) -> dict[str, str]:
        """Get column-level visibility for a user based on clearance and domains.

        Returns:
            Dict mapping column_name -> visibility (VISIBLE, MASKED, HIDDEN).
        """
        if not self._driver:
            logger.debug("graph_not_connected", method="get_column_scope")
            return {}

        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """
                    MATCH (c:Column)-[:BELONGS_TO]->(t:Table)-[:IN_DOMAIN]->(d:Domain)
                    WHERE d.name IN $domains
                    RETURN c.name AS column_name,
                           c.classification_level AS level,
                           c.default_visibility AS visibility
                    """,
                    domains=domains,
                )
                scope: dict[str, str] = {}
                async for record in result:
                    col = record["column_name"]
                    level = record.get("level", 1)
                    default_vis = record.get("visibility", "VISIBLE")

                    if level > clearance_level:
                        scope[col] = "HIDDEN"
                    elif level == clearance_level:
                        scope[col] = "MASKED"
                    else:
                        scope[col] = default_vis

                return scope
        except Exception as exc:
            logger.warning("column_scope_query_failed", error=str(exc))

        return {}

    async def get_classification_data(self, table_name: str) -> dict[str, Any]:
        """Get data classification metadata for a specific table.

        Returns:
            Dict with table classification info (domain, sensitivity, columns).
        """
        if not self._driver:
            return {}

        try:
            async with self._driver.session() as session:
                result = await session.run(
                    """
                    MATCH (t:Table {name: $table_name})
                    OPTIONAL MATCH (t)-[:IN_DOMAIN]->(d:Domain)
                    OPTIONAL MATCH (c:Column)-[:BELONGS_TO]->(t)
                    RETURN t.name AS table_name,
                           t.sensitivity_level AS sensitivity,
                           d.name AS domain,
                           collect({
                               name: c.name,
                               classification_level: c.classification_level,
                               data_type: c.data_type
                           }) AS columns
                    """,
                    table_name=table_name,
                )
                record = await result.single()
                if record:
                    return {
                        "table_name": record["table_name"],
                        "sensitivity": record.get("sensitivity"),
                        "domain": record.get("domain"),
                        "columns": record["columns"],
                    }
        except Exception as exc:
            logger.warning("classification_query_failed", table=table_name, error=str(exc))

        return {}

    async def health_check(self) -> bool:
        """Check Neo4j connectivity."""
        if not self._driver:
            return False
        try:
            await self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    # ── Policy CRUD methods ─────────────────────────────────

    async def list_roles_with_policies(self) -> list[dict[str, Any]]:
        """Return all roles with their policy summaries."""
        if not self._driver:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run("""
                    MATCH (r:Role)
                    OPTIONAL MATCH (r)-[:ALLOWS_TABLE]->(at:Table)
                    OPTIONAL MATCH (r)-[:DENIES_TABLE]->(dt:Table)
                    OPTIONAL MATCH (r)-[:DENIES_OP]->(op:Operation)
                    OPTIONAL MATCH (r)-[:ROW_FILTER]->(rf:RowFilter)
                    OPTIONAL MATCH (r)-[:ACCESS_DOMAIN]->(d:Domain)
                    RETURN r.name AS name,
                           r.clearance_level AS clearance_level,
                           r.domain AS domain,
                           r.bound_policies AS bound_policies,
                           r.result_limit AS result_limit,
                           collect(DISTINCT at.name) AS allowed_tables,
                           collect(DISTINCT dt.name) AS denied_tables,
                           collect(DISTINCT op.name) AS denied_operations,
                           collect(DISTINCT {table: rf.table, condition: rf.condition}) AS row_filters,
                           collect(DISTINCT d.name) AS domains
                    ORDER BY r.name
                """)
                roles = []
                async for record in result:
                    roles.append({
                        "name": record["name"],
                        "clearance_level": record["clearance_level"] or 1,
                        "domain": record["domain"] or "",
                        "bound_policies": record["bound_policies"] or [],
                        "result_limit": record["result_limit"],
                        "allowed_tables": [t for t in record["allowed_tables"] if t],
                        "denied_tables": [t for t in record["denied_tables"] if t],
                        "denied_operations": [o for o in record["denied_operations"] if o],
                        "row_filters": [rf for rf in record["row_filters"] if rf.get("condition")],
                        "domains": [d for d in record["domains"] if d],
                    })
                return roles
        except Exception as exc:
            logger.warning("list_roles_failed", error=str(exc))
            return []

    async def get_role_detail(self, role_name: str) -> dict[str, Any] | None:
        """Return full policy detail for a single role."""
        if not self._driver:
            return None
        try:
            async with self._driver.session() as session:
                result = await session.run("""
                    MATCH (r:Role {name: $name})
                    OPTIONAL MATCH (r)-[:ALLOWS_TABLE]->(at:Table)
                    OPTIONAL MATCH (r)-[:DENIES_TABLE]->(dt:Table)
                    OPTIONAL MATCH (r)-[:DENIES_OP]->(op:Operation)
                    OPTIONAL MATCH (r)-[:ROW_FILTER]->(rf:RowFilter)
                    OPTIONAL MATCH (r)-[:ACCESS_DOMAIN]->(d:Domain)
                    RETURN r.name AS name,
                           r.clearance_level AS clearance_level,
                           r.domain AS domain,
                           r.bound_policies AS bound_policies,
                           r.result_limit AS result_limit,
                           collect(DISTINCT at.name) AS allowed_tables,
                           collect(DISTINCT dt.name) AS denied_tables,
                           collect(DISTINCT op.name) AS denied_operations,
                           collect(DISTINCT {table: rf.table, condition: rf.condition}) AS row_filters,
                           collect(DISTINCT d.name) AS domains
                """, name=role_name)
                record = await result.single()
                if not record or not record["name"]:
                    return None
                return {
                    "name": record["name"],
                    "clearance_level": record["clearance_level"] or 1,
                    "domain": record["domain"] or "",
                    "bound_policies": record["bound_policies"] or [],
                    "result_limit": record["result_limit"],
                    "allowed_tables": [t for t in record["allowed_tables"] if t],
                    "denied_tables": [t for t in record["denied_tables"] if t],
                    "denied_operations": [o for o in record["denied_operations"] if o],
                    "row_filters": [rf for rf in record["row_filters"] if rf.get("condition")],
                    "domains": [d for d in record["domains"] if d],
                }
        except Exception as exc:
            logger.warning("get_role_detail_failed", role=role_name, error=str(exc))
            return None

    async def update_role_policies(self, role_name: str, payload: dict[str, Any]) -> bool:
        """Replace all policy edges for a role."""
        if not self._driver:
            return False
        try:
            async with self._driver.session() as session:
                # Update result_limit on Role node
                result_limit = payload.get("result_limit")
                if result_limit is not None:
                    await session.run("""
                        MATCH (r:Role {name: $name})
                        SET r.result_limit = $limit
                    """, name=role_name, limit=result_limit)
                else:
                    await session.run("""
                        MATCH (r:Role {name: $name})
                        REMOVE r.result_limit
                    """, name=role_name)

                # Delete existing policy edges
                await session.run("""
                    MATCH (r:Role {name: $name})-[rel:ALLOWS_TABLE|DENIES_TABLE|DENIES_OP|ROW_FILTER|ACCESS_DOMAIN]->()
                    DELETE rel
                """, name=role_name)

                # Create ALLOWS_TABLE
                for table in payload.get("allowed_tables", []):
                    await session.run("""
                        MATCH (r:Role {name: $role}), (t:Table {name: $table})
                        MERGE (r)-[:ALLOWS_TABLE]->(t)
                    """, role=role_name, table=table)

                # Create DENIES_TABLE
                for table in payload.get("denied_tables", []):
                    await session.run("""
                        MATCH (r:Role {name: $role}), (t:Table {name: $table})
                        MERGE (r)-[:DENIES_TABLE]->(t)
                    """, role=role_name, table=table)

                # Create DENIES_OP
                for op in payload.get("denied_operations", []):
                    await session.run("""
                        MATCH (r:Role {name: $role}), (o:Operation {name: $op})
                        MERGE (r)-[:DENIES_OP]->(o)
                    """, role=role_name, op=op)

                # Create ROW_FILTER
                for rf in payload.get("row_filters", []):
                    if rf.get("condition"):
                        await session.run("""
                            MATCH (r:Role {name: $role})
                            MERGE (rf:RowFilter {table: $table, condition: $condition})
                            MERGE (r)-[:ROW_FILTER]->(rf)
                        """, role=role_name, table=rf["table"], condition=rf["condition"])

                # Create ACCESS_DOMAIN
                for domain in payload.get("domains", []):
                    await session.run("""
                        MATCH (r:Role {name: $role}), (d:Domain {name: $domain})
                        MERGE (r)-[:ACCESS_DOMAIN]->(d)
                    """, role=role_name, domain=domain)

                logger.info("role_policies_updated", role=role_name)
                return True
        except Exception as exc:
            logger.warning("update_role_policies_failed", role=role_name, error=str(exc))
            return False

    async def list_tables_with_metadata(self) -> list[dict[str, Any]]:
        """Return all tables with sensitivity, domain, and column count."""
        if not self._driver:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run("""
                    MATCH (t:Table)
                    OPTIONAL MATCH (t)-[:IN_DOMAIN]->(d:Domain)
                    OPTIONAL MATCH (c:Column)-[:BELONGS_TO]->(t)
                    RETURN t.name AS name,
                           t.sensitivity_level AS sensitivity_level,
                           d.name AS domain,
                           count(c) AS column_count
                    ORDER BY t.name
                """)
                tables = []
                async for record in result:
                    tables.append({
                        "name": record["name"],
                        "sensitivity_level": record["sensitivity_level"] or 1,
                        "domain": record["domain"] or "",
                        "column_count": record["column_count"],
                    })
                return tables
        except Exception as exc:
            logger.warning("list_tables_failed", error=str(exc))
            return []

    async def update_table_metadata(
        self, table_name: str, sensitivity_level: int, domain: str,
    ) -> bool:
        """Update a table's sensitivity level and domain."""
        if not self._driver:
            return False
        try:
            async with self._driver.session() as session:
                await session.run("""
                    MATCH (t:Table {name: $name})
                    SET t.sensitivity_level = $sensitivity, t.domain = $domain
                """, name=table_name, sensitivity=sensitivity_level, domain=domain)
                # Update IN_DOMAIN edge
                await session.run("""
                    MATCH (t:Table {name: $name})-[old:IN_DOMAIN]->()
                    DELETE old
                """, name=table_name)
                await session.run("""
                    MATCH (t:Table {name: $name}), (d:Domain {name: $domain})
                    MERGE (t)-[:IN_DOMAIN]->(d)
                """, name=table_name, domain=domain)
                return True
        except Exception as exc:
            logger.warning("update_table_failed", table=table_name, error=str(exc))
            return False

    async def list_columns_for_table(self, table_name: str) -> list[dict[str, Any]]:
        """Return columns for a table with classification metadata."""
        if not self._driver:
            return []
        try:
            async with self._driver.session() as session:
                result = await session.run("""
                    MATCH (c:Column {table: $table})-[:BELONGS_TO]->(t:Table {name: $table})
                    RETURN c.name AS name,
                           c.data_type AS data_type,
                           c.classification_level AS classification_level,
                           c.default_visibility AS default_visibility,
                           c.is_pii AS is_pii
                    ORDER BY c.name
                """, table=table_name)
                columns = []
                async for record in result:
                    columns.append({
                        "name": record["name"],
                        "data_type": record["data_type"] or "unknown",
                        "classification_level": record["classification_level"] or 1,
                        "default_visibility": record["default_visibility"] or "VISIBLE",
                        "is_pii": bool(record["is_pii"]),
                    })
                return columns
        except Exception as exc:
            logger.warning("list_columns_failed", table=table_name, error=str(exc))
            return []

    async def update_column_metadata(
        self, table_name: str, column_name: str,
        classification_level: int, default_visibility: str,
    ) -> bool:
        """Update a column's classification level and visibility."""
        if not self._driver:
            return False
        try:
            async with self._driver.session() as session:
                await session.run("""
                    MATCH (c:Column {name: $col, table: $table})
                    SET c.classification_level = $level,
                        c.default_visibility = $visibility
                """, col=column_name, table=table_name,
                    level=classification_level, visibility=default_visibility)
                return True
        except Exception as exc:
            logger.warning("update_column_failed", table=table_name, col=column_name, error=str(exc))
            return False

    @staticmethod
    def _default_rbac_policy() -> dict[str, Any]:
        """Return a restrictive default RBAC policy when graph is unavailable."""
        return {
            "allowed_tables": [],
            "denied_tables": [],
            "denied_operations": ["DELETE", "UPDATE", "DROP", "ALTER", "TRUNCATE"],
            "row_filters": [],
            "result_limit": None,
        }
