"""Seed Neo4j with roles, users, tables, columns, and default policies.

All operations use MERGE for idempotency -- safe to re-run.
Reads role hierarchy, clearance, domain, and policy data from role_resolver.py.
Discovers real columns from PostgreSQL information_schema.

Usage:
    python -m queryvault.scripts.seed_neo4j
"""

from __future__ import annotations

import asyncio
import os
import sys

# ---------------------------------------------------------------------------
# Data sources (imported from existing hardcoded dicts)
# ---------------------------------------------------------------------------

from queryvault.app.services.identity.role_resolver import (
    ROLE_CLEARANCE,
    ROLE_DOMAIN,
    ROLE_INHERITANCE,
    ROLE_POLICIES,
)
from queryvault.app.api.mock_users_routes import MOCK_USER_PROFILES
from queryvault.app.models.enums import ClearanceLevel, Domain

# ---------------------------------------------------------------------------
# Table definitions (the 4 real tables in the analytics DB)
# ---------------------------------------------------------------------------

TABLE_DEFINITIONS = {
    "encounter_summaries": {"sensitivity_level": 3, "domain": "CLINICAL"},
    "population_health":   {"sensitivity_level": 2, "domain": "CLINICAL"},
    "quality_metrics":     {"sensitivity_level": 2, "domain": "ADMINISTRATIVE"},
    "research_cohorts":    {"sensitivity_level": 3, "domain": "RESEARCH"},
}

# ---------------------------------------------------------------------------
# Default role -> table access policies
# ---------------------------------------------------------------------------

ROLE_TABLE_ACCESS: dict[str, dict] = {
    # Clinical roles
    "ATTENDING_PHYSICIAN":   {"allow": ["encounter_summaries", "population_health", "quality_metrics"], "deny": []},
    "CONSULTING_PHYSICIAN":  {"allow": ["encounter_summaries", "population_health"], "deny": []},
    "EMERGENCY_PHYSICIAN":   {"allow": ["encounter_summaries", "population_health", "quality_metrics"], "deny": []},
    "PSYCHIATRIST":          {"allow": ["encounter_summaries", "population_health"], "deny": []},
    "RESIDENT":              {"allow": ["encounter_summaries", "population_health"], "deny": ["research_cohorts"]},
    "HEAD_NURSE":            {"allow": ["encounter_summaries", "population_health"], "deny": ["research_cohorts"]},
    "ICU_NURSE":             {"allow": ["encounter_summaries", "population_health"], "deny": ["research_cohorts"]},
    "REGISTERED_NURSE":      {"allow": ["encounter_summaries", "population_health"], "deny": ["research_cohorts"]},
    # Financial roles
    "BILLING_CLERK":         {"allow": ["quality_metrics", "population_health"], "deny": ["encounter_summaries"]},
    "REVENUE_CYCLE_ANALYST": {"allow": ["quality_metrics", "population_health"], "deny": ["encounter_summaries"]},
    "REVENUE_CYCLE_MANAGER": {"allow": ["quality_metrics", "population_health"], "deny": ["encounter_summaries"]},
    # Admin
    "HR_MANAGER":            {"allow": ["quality_metrics"], "deny": ["encounter_summaries", "research_cohorts"]},
    "HR_DIRECTOR":           {"allow": ["quality_metrics", "population_health"], "deny": []},
    "IT_ADMINISTRATOR":      {"allow": ["quality_metrics"], "deny": []},
    # Compliance - full access for auditing
    "HIPAA_PRIVACY_OFFICER": {"allow": ["encounter_summaries", "population_health", "quality_metrics", "research_cohorts"], "deny": []},
    # Research
    "CLINICAL_RESEARCHER":   {"allow": ["research_cohorts", "population_health"], "deny": ["encounter_summaries"]},
}

# All non-admin roles denied these operations
DENIED_OPS_FOR_ALL = ["DELETE", "DROP", "ALTER", "TRUNCATE"]

# Row filters by role
ROLE_ROW_FILTERS: dict[str, list[dict]] = {
    "REGISTERED_NURSE": [
        {"table": "encounter_summaries", "condition": "facility_id = '{{user.facility}}'"},
    ],
    "BILLING_CLERK": [
        {"table": "quality_metrics", "condition": "facility_id = '{{user.facility}}'"},
    ],
    "RESIDENT": [
        {"table": "encounter_summaries", "condition": "department_name = '{{user.department}}'"},
    ],
}

# PII-like column name patterns -> higher classification
PII_PATTERNS = {"patient", "name", "ssn", "dob", "mrn", "aadhaar", "phone", "email", "address", "npi"}

OPERATIONS = ["DELETE", "UPDATE", "DROP", "ALTER", "TRUNCATE"]
DOMAINS = ["CLINICAL", "FINANCIAL", "ADMINISTRATIVE", "RESEARCH", "COMPLIANCE", "IT_OPERATIONS"]


async def seed_all(neo4j_uri: str, neo4j_user: str, neo4j_password: str,
                   neo4j_database: str = "neo4j", pg_dsn: str | None = None) -> dict:
    """Run the full seed pipeline. Returns summary stats."""
    from neo4j import AsyncGraphDatabase

    driver = AsyncGraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    await driver.verify_connectivity()
    print(f"Connected to Neo4j at {neo4j_uri}")

    stats: dict[str, int] = {}

    async with driver.session(database=neo4j_database) as session:
        # 1. Constraints
        await _create_constraints(session)
        print("  [1/8] Constraints created")

        # 2. Domains
        stats["domains"] = await _seed_domains(session)
        print(f"  [2/8] Domains: {stats['domains']}")

        # 3. Operations
        stats["operations"] = await _seed_operations(session)
        print(f"  [3/8] Operations: {stats['operations']}")

        # 4. Roles + ACCESS_DOMAIN edges
        stats["roles"] = await _seed_roles(session)
        print(f"  [4/8] Roles: {stats['roles']}")

        # 5. Tables + IN_DOMAIN edges
        stats["tables"] = await _seed_tables(session)
        print(f"  [5/8] Tables: {stats['tables']}")

        # 6. Columns (from PostgreSQL)
        stats["columns"] = await _seed_columns(session, pg_dsn)
        print(f"  [6/8] Columns: {stats['columns']}")

        # 7. Users + HAS_ROLE edges
        stats["users"] = await _seed_users(session)
        print(f"  [7/8] Users: {stats['users']}")

        # 8. Policy edges (ALLOWS_TABLE, DENIES_TABLE, DENIES_OP, ROW_FILTER)
        stats["policy_edges"] = await _seed_policy_edges(session)
        print(f"  [8/8] Policy edges: {stats['policy_edges']}")

    await driver.close()
    print(f"\nSeed complete: {stats}")
    return stats


async def _create_constraints(session) -> None:
    constraints = [
        "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Role) REQUIRE r.name IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.user_id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Table) REQUIRE t.name IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (o:Operation) REQUIRE o.name IS UNIQUE",
    ]
    for c in constraints:
        try:
            await session.run(c)
        except Exception as exc:
            # If a plain index already exists on this property, drop it first and retry
            err_msg = str(exc)
            if "already exists an index" in err_msg:
                # Extract label from constraint (e.g. "Table" from "FOR (t:Table)")
                label = c.split(":")[1].split(")")[0]
                prop = c.split(".")[-1].split(" ")[0]
                drop_idx = f"DROP INDEX ON :{label}({prop})"
                try:
                    await session.run(drop_idx)
                    await session.run(c)
                    print(f"    Dropped conflicting index on :{label}({prop}), constraint created")
                except Exception:
                    print(f"    Warning: could not resolve index conflict for {label}.{prop}, skipping constraint")
            else:
                print(f"    Warning: constraint skipped -- {err_msg}")


async def _seed_domains(session) -> int:
    for d in DOMAINS:
        await session.run("MERGE (d:Domain {name: $name})", name=d)
    return len(DOMAINS)


async def _seed_operations(session) -> int:
    for op in OPERATIONS:
        await session.run("MERGE (o:Operation {name: $name})", name=op)
    return len(OPERATIONS)


async def _seed_roles(session) -> int:
    count = 0
    all_roles = set(ROLE_INHERITANCE.keys())
    # Also add parent roles that aren't keys
    for parents in ROLE_INHERITANCE.values():
        all_roles.update(parents)

    for role_name in sorted(all_roles):
        clearance = ROLE_CLEARANCE.get(role_name, ClearanceLevel.PUBLIC).value
        domain_enum = ROLE_DOMAIN.get(role_name)
        domain = domain_enum.value if domain_enum else ""
        policies = ROLE_POLICIES.get(role_name, [])

        await session.run(
            """
            MERGE (r:Role {name: $name})
            SET r.clearance_level = $clearance,
                r.domain = $domain,
                r.bound_policies = $policies
            """,
            name=role_name, clearance=clearance, domain=domain, policies=policies,
        )

        # ACCESS_DOMAIN edge
        if domain:
            await session.run(
                """
                MATCH (r:Role {name: $role}), (d:Domain {name: $domain})
                MERGE (r)-[:ACCESS_DOMAIN]->(d)
                """,
                role=role_name, domain=domain,
            )
        count += 1

    return count


async def _seed_tables(session) -> int:
    for table_name, meta in TABLE_DEFINITIONS.items():
        await session.run(
            """
            MERGE (t:Table {name: $name})
            SET t.sensitivity_level = $sensitivity, t.domain = $domain
            """,
            name=table_name,
            sensitivity=meta["sensitivity_level"],
            domain=meta["domain"],
        )
        # IN_DOMAIN edge
        await session.run(
            """
            MATCH (t:Table {name: $table}), (d:Domain {name: $domain})
            MERGE (t)-[:IN_DOMAIN]->(d)
            """,
            table=table_name, domain=meta["domain"],
        )
    return len(TABLE_DEFINITIONS)


async def _seed_columns(session, pg_dsn: str | None) -> int:
    """Discover columns from PostgreSQL and seed into Neo4j."""
    if not pg_dsn:
        print("    (No PG DSN -- using fallback column list)")
        return await _seed_columns_fallback(session)

    try:
        import asyncpg
        conn = await asyncpg.connect(pg_dsn)
        rows = await conn.fetch(
            """
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name IN ('encounter_summaries', 'population_health', 'quality_metrics', 'research_cohorts')
            ORDER BY table_name, ordinal_position
            """
        )
        await conn.close()
    except Exception as exc:
        print(f"    (PG connection failed: {exc} -- using fallback)")
        return await _seed_columns_fallback(session)

    count = 0
    for row in rows:
        table_name = row["table_name"]
        col_name = row["column_name"]
        data_type = row["data_type"]

        # Heuristic: PII-like columns get higher classification
        is_pii = any(p in col_name.lower() for p in PII_PATTERNS)
        classification = 3 if is_pii else 1
        visibility = "MASKED" if is_pii else "VISIBLE"

        await session.run(
            """
            MERGE (c:Column {name: $col_name, table: $table_name})
            SET c.data_type = $data_type,
                c.classification_level = $classification,
                c.default_visibility = $visibility,
                c.is_pii = $is_pii
            """,
            col_name=col_name, table_name=table_name,
            data_type=data_type, classification=classification,
            visibility=visibility, is_pii=is_pii,
        )
        # BELONGS_TO edge
        await session.run(
            """
            MATCH (c:Column {name: $col, table: $table}), (t:Table {name: $table})
            MERGE (c)-[:BELONGS_TO]->(t)
            """,
            col=col_name, table=table_name,
        )
        count += 1

    return count


async def _seed_columns_fallback(session) -> int:
    """Fallback column list when PostgreSQL isn't reachable."""
    FALLBACK_COLUMNS = {
        "encounter_summaries": [
            "summary_id", "facility_id", "facility_name", "department_id", "department_name",
            "encounter_type", "report_month", "total_encounters", "total_admissions",
            "total_discharges", "avg_length_of_stay", "bed_occupancy_rate",
            "mortality_count", "mortality_rate", "readmission_count", "readmission_rate",
            "total_revenue", "avg_revenue_per_encounter", "created_at",
        ],
        "population_health": [
            "record_id", "report_quarter", "region", "age_group", "gender",
            "disease_category", "patient_count", "encounter_count",
            "avg_cost", "avg_los", "mortality_rate", "complication_rate", "created_at",
        ],
        "quality_metrics": [
            "metric_id", "facility_id", "department_id", "metric_name", "metric_category",
            "report_month", "numerator", "denominator", "metric_value",
            "target_value", "benchmark_value", "performance_status", "created_at",
        ],
        "research_cohorts": [
            "cohort_id", "study_name", "pi_name", "irb_number", "start_date",
            "end_date", "status", "created_at",
        ],
    }
    count = 0
    for table_name, columns in FALLBACK_COLUMNS.items():
        for col_name in columns:
            is_pii = any(p in col_name.lower() for p in PII_PATTERNS)
            classification = 3 if is_pii else 1
            visibility = "MASKED" if is_pii else "VISIBLE"

            await session.run(
                """
                MERGE (c:Column {name: $col_name, table: $table_name})
                SET c.data_type = 'unknown',
                    c.classification_level = $classification,
                    c.default_visibility = $visibility,
                    c.is_pii = $is_pii
                """,
                col_name=col_name, table_name=table_name,
                classification=classification, visibility=visibility, is_pii=is_pii,
            )
            await session.run(
                """
                MATCH (c:Column {name: $col, table: $table}), (t:Table {name: $table})
                MERGE (c)-[:BELONGS_TO]->(t)
                """,
                col=col_name, table=table_name,
            )
            count += 1
    return count


async def _seed_users(session) -> int:
    count = 0
    for oid, profile in MOCK_USER_PROFILES.items():
        await session.run(
            """
            MERGE (u:User {user_id: $oid})
            SET u.display_name = $name, u.email = $email, u.category = $category
            """,
            oid=oid, name=profile["display_name"],
            email=profile.get("email", ""), category=profile.get("category", ""),
        )
        # HAS_ROLE edges
        for role in profile.get("ad_roles", []):
            await session.run(
                """
                MATCH (u:User {user_id: $oid}), (r:Role {name: $role})
                MERGE (u)-[:HAS_ROLE]->(r)
                """,
                oid=oid, role=role,
            )
        count += 1
    return count


async def _seed_policy_edges(session) -> int:
    count = 0
    for role_name, access in ROLE_TABLE_ACCESS.items():
        # ALLOWS_TABLE
        for table in access.get("allow", []):
            await session.run(
                """
                MATCH (r:Role {name: $role}), (t:Table {name: $table})
                MERGE (r)-[:ALLOWS_TABLE]->(t)
                """,
                role=role_name, table=table,
            )
            count += 1

        # DENIES_TABLE
        for table in access.get("deny", []):
            await session.run(
                """
                MATCH (r:Role {name: $role}), (t:Table {name: $table})
                MERGE (r)-[:DENIES_TABLE]->(t)
                """,
                role=role_name, table=table,
            )
            count += 1

    # DENIES_OP for all roles (except admin/compliance)
    admin_roles = {"HIPAA_PRIVACY_OFFICER", "IT_ADMINISTRATOR", "HR_DIRECTOR"}
    for role_name in ROLE_TABLE_ACCESS:
        if role_name in admin_roles:
            ops_to_deny = ["DELETE", "DROP", "ALTER", "TRUNCATE"]
        else:
            ops_to_deny = DENIED_OPS_FOR_ALL
        for op in ops_to_deny:
            await session.run(
                """
                MATCH (r:Role {name: $role}), (o:Operation {name: $op})
                MERGE (r)-[:DENIES_OP]->(o)
                """,
                role=role_name, op=op,
            )
            count += 1

    # ROW_FILTER edges
    for role_name, filters in ROLE_ROW_FILTERS.items():
        for rf in filters:
            await session.run(
                """
                MATCH (r:Role {name: $role})
                MERGE (rf:RowFilter {table: $table, condition: $condition})
                MERGE (r)-[:ROW_FILTER]->(rf)
                """,
                role=role_name, table=rf["table"], condition=rf["condition"],
            )
            count += 1

    return count


async def main():
    """Entry point -- reads config from environment."""
    from queryvault.app.config import get_settings
    settings = get_settings()

    # Also try to get the Aiven PG DSN for column discovery
    pg_dsn = os.environ.get("XENSQL_PGVECTOR_DSN", None)

    await seed_all(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password,
        neo4j_database=settings.neo4j_database,
        pg_dsn=pg_dsn,
    )


if __name__ == "__main__":
    asyncio.run(main())
