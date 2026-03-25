"""Policy Resolver -- Full L4 policy resolution pipeline.

Zero Trust Control: ZT-002 (Policy Resolution)

Implements the complete deterministic resolution lifecycle:
  1. Collect policies from Neo4j via the graph client
  2. Resolve table-level conflicts (priority-based, BTG override)
  3. Aggregate conditions (row filters, join restrictions, max rows)
  4. Generate NL rules for the LLM prompt
  5. Sign the Permission Envelope (HMAC-SHA256)

Security invariants:
  - Deny by default: no policy = no access.
  - Clearance gating: user clearance >= table sensitivity.
  - BTG overrides for policies with priority < 200 only.
  - Hard DENYs (priority >= 200) are never overridden, even under BTG.
  - Fail closed on any exception.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import structlog
from pydantic import BaseModel, Field

from queryvault.app.models.enums import ColumnVisibility, PolicyDecision
from queryvault.app.models.security_context import (
    PermissionEnvelope,
    SecurityContext,
    TablePermission,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Supporting data classes
# ---------------------------------------------------------------------------


class PolicyNode(BaseModel):
    """A single policy fetched from the knowledge graph."""

    policy_id: str
    effect: str  # ALLOW | DENY | MASK | FILTER
    priority: int = 0
    conditions: list[ConditionNode] = Field(default_factory=list)

    @property
    def is_deny(self) -> bool:
        return self.effect.upper() == "DENY"

    @property
    def is_allow(self) -> bool:
        return self.effect.upper() in {"ALLOW", "FILTER", "MASK"}


class ConditionNode(BaseModel):
    """A condition attached to a policy node."""

    condition_id: str = ""
    condition_type: str = ""  # ROW_FILTER | MASKING_RULE | AGGREGATE_ONLY | etc.
    expression: str = ""
    parameters: Optional[str] = None


class ColumnMeta(BaseModel):
    """Column metadata from the knowledge graph."""

    column_id: str
    column_name: str
    data_type: str = "TEXT"
    is_pii: bool = False
    policies: list[PolicyNode] = Field(default_factory=list)


class TableMeta(BaseModel):
    """Table metadata assembled from graph queries."""

    table_id: str
    table_name: str = ""
    domain: str = ""
    sensitivity_level: int = 1
    table_policies: list[PolicyNode] = Field(default_factory=list)
    columns: dict[str, ColumnMeta] = Field(default_factory=dict)


class ColumnDecision(BaseModel):
    """Resolved column-level access decision."""

    column_name: str
    visibility: ColumnVisibility = ColumnVisibility.HIDDEN
    masking_expression: Optional[str] = None
    computed_expression: Optional[str] = None
    reason: str = ""


class JoinRestriction(BaseModel):
    """Cross-domain join prohibition."""

    source_domain: str
    target_domain: str
    policy_id: str
    restriction_type: str = "DENY"


# ---------------------------------------------------------------------------
# Resolution statistics (in-memory, per-process)
# ---------------------------------------------------------------------------

_stats: dict[str, int | float] = {
    "total_requests": 0,
    "total_latency_ms": 0.0,
    "total_policies_evaluated": 0,
    "total_denials": 0,
    "total_allows": 0,
    "btg_activations": 0,
    "errors": 0,
}


def get_resolution_stats() -> dict:
    """Return a copy of accumulated resolution statistics."""
    s = dict(_stats)
    s["avg_latency_ms"] = (
        round(s["total_latency_ms"] / s["total_requests"], 2)
        if s["total_requests"] > 0
        else 0.0
    )
    return s


def clear_resolution_stats() -> None:
    """Reset all counters."""
    for k in _stats:
        _stats[k] = 0 if isinstance(_stats[k], int) else 0.0


# ---------------------------------------------------------------------------
# PolicyResolver
# ---------------------------------------------------------------------------


class PolicyResolver:
    """Executes the full L4 policy resolution pipeline.

    Usage::

        resolver = PolicyResolver(graph_client, signing_key="...")
        envelope = await resolver.resolve(security_context, requested_tables)
    """

    # Effects that grant table-level access (with conditions).
    _GRANT_EFFECTS = frozenset({"ALLOW", "FILTER", "MASK"})

    def __init__(
        self,
        graph_client: Any,
        *,
        signing_key: str = "queryvault-default-key",
        envelope_ttl_seconds: int = 60,
    ) -> None:
        self._graph = graph_client
        self._signing_key = signing_key
        self._envelope_ttl = envelope_ttl_seconds

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def resolve(
        self,
        security_context: SecurityContext,
        requested_tables: list[str],
    ) -> PermissionEnvelope:
        """Run the full resolution pipeline and return a signed PermissionEnvelope.

        Steps:
          1. Collect policies from Neo4j
          2. Resolve table-level conflicts (priority-based, BTG override)
          3. Aggregate conditions (row filters, join restrictions)
          4. Generate NL rules for LLM prompt
          5. Sign envelope with HMAC-SHA256
        """
        start = time.perf_counter()
        now = datetime.now(UTC)

        envelope = PermissionEnvelope(
            signature="",
            expires_at=(now + timedelta(seconds=self._envelope_ttl)).isoformat() + "Z",
        )

        # Extract convenience references
        user_clearance = security_context.authorization.clearance_level
        effective_roles = security_context.authorization.effective_roles
        btg_active = security_context.emergency.btg_active
        user_ctx = self._build_user_context(security_context)

        if btg_active:
            _stats["btg_activations"] += 1

        total_policies_seen = 0

        try:
            # Step 1 -- Collect metadata from the knowledge graph
            table_meta_map = await self._collect_policies(
                requested_tables, effective_roles
            )

            all_active_policies: list[PolicyNode] = []

            # Steps 2 & 3 -- Per-table resolution and condition aggregation
            for table_id in requested_tables:
                meta = table_meta_map.get(table_id)

                if meta is None:
                    envelope.table_permissions.append(
                        TablePermission(
                            table_id=table_id,
                            decision=PolicyDecision.DENY,
                        )
                    )
                    continue

                total_policies_seen += len(meta.table_policies)

                # Clearance gating: user clearance must meet or exceed table sensitivity
                if user_clearance < meta.sensitivity_level:
                    envelope.table_permissions.append(
                        TablePermission(
                            table_id=table_id,
                            decision=PolicyDecision.DENY,
                        )
                    )
                    continue

                # Table-level conflict resolution
                decision, active_pols, reason = self._resolve_table_conflict(meta)

                # BTG override: flip DENY to ALLOW when BTG is active and
                # no hard-deny (priority >= 200) exists.
                if btg_active and decision == PolicyDecision.DENY:
                    if self._btg_can_override(table_id, meta, security_context):
                        decision = PolicyDecision.ALLOW
                        reason = f"BTG override. Original: {reason}"
                        active_pols = [
                            p for p in meta.table_policies if p.is_allow
                        ] or meta.table_policies

                tp = TablePermission(
                    table_id=table_id,
                    table_name=meta.table_name,
                    decision=decision,
                )

                if decision == PolicyDecision.ALLOW:
                    # Column-level resolution
                    col_decisions = self._resolve_columns(meta, active_pols)
                    tp.columns = [
                        {
                            "column_name": cd.column_name,
                            "visibility": cd.visibility.value,
                            "masking_expression": cd.masking_expression,
                        }
                        for cd in col_decisions
                    ]

                    # Row filter aggregation
                    row_filters = self._aggregate_row_filters(active_pols, user_ctx)
                    if row_filters:
                        tp.masking_rules = row_filters  # reuse masking_rules for row filters

                    # Aggregation-only / max-rows constraints
                    agg_only, max_rows = self._aggregate_constraints(active_pols)
                    tp.aggregation_only = agg_only
                    tp.max_rows = max_rows

                    all_active_policies.extend(active_pols)

                envelope.table_permissions.append(tp)

            # Global join restrictions
            join_restrictions = self._extract_join_restrictions(all_active_policies)
            envelope.join_restrictions = [
                {
                    "source_domain": jr.source_domain,
                    "target_domain": jr.target_domain,
                    "policy_id": jr.policy_id,
                }
                for jr in join_restrictions
            ]

            # Step 4 -- Generate NL rules for the LLM
            envelope.nl_rules = self._generate_nl_rules(envelope, join_restrictions)

            # Step 5 -- Sign the envelope
            envelope.signature = self._sign_envelope(envelope)

            # Stats
            elapsed_ms = (time.perf_counter() - start) * 1000
            _stats["total_requests"] += 1
            _stats["total_latency_ms"] += elapsed_ms
            _stats["total_policies_evaluated"] += total_policies_seen
            _stats["total_allows"] += sum(
                1
                for tp in envelope.table_permissions
                if tp.decision == PolicyDecision.ALLOW
            )
            _stats["total_denials"] += sum(
                1
                for tp in envelope.table_permissions
                if tp.decision == PolicyDecision.DENY
            )

            logger.info(
                "policy_resolution_complete",
                context_id=security_context.context_id,
                tables_requested=len(requested_tables),
                tables_allowed=_stats["total_allows"],
                btg_active=btg_active,
                duration_ms=round(elapsed_ms, 2),
            )

        except Exception as exc:
            logger.exception(
                "policy_resolution_failed",
                context_id=security_context.context_id,
                error=str(exc),
            )
            _stats["errors"] += 1

            # Fail closed -- deny everything
            envelope.table_permissions = [
                TablePermission(
                    table_id=tid,
                    decision=PolicyDecision.DENY,
                )
                for tid in requested_tables
            ]
            envelope.signature = self._sign_envelope(envelope)

        return envelope

    # ------------------------------------------------------------------
    # Step 1: Collect policies
    # ------------------------------------------------------------------

    async def _collect_policies(
        self,
        table_ids: list[str],
        effective_roles: list[str],
    ) -> dict[str, TableMeta]:
        """Fetch table metadata and policies from the Neo4j graph."""
        if not table_ids or not effective_roles:
            return {}

        # Delegate to graph client (expected interface matches L4 pattern)
        table_policies = await self._graph.get_table_policies(table_ids, effective_roles)
        column_policies = await self._graph.get_column_policies(table_ids, effective_roles)
        all_columns = await self._graph.get_all_table_columns(table_ids)
        table_props = await self._graph.get_table_properties(table_ids)

        tables: dict[str, TableMeta] = {}

        # Parse table-level policies
        for record in table_policies:
            tid = record["table_id"]
            if tid not in tables:
                tables[tid] = TableMeta(
                    table_id=tid,
                    table_name=tid.split(".")[-1] if "." in tid else tid,
                )
            tables[tid].table_policies.append(PolicyNode(**record["policy"]))

        # Parse column-level policies
        for record in column_policies:
            tid = record["table_id"]
            col_name = record["column_name"]
            col_id = record.get("column_id") or f"{tid}.{col_name}"
            if tid not in tables:
                tables[tid] = TableMeta(
                    table_id=tid,
                    table_name=tid.split(".")[-1] if "." in tid else tid,
                )
            if col_id not in tables[tid].columns:
                tables[tid].columns[col_id] = ColumnMeta(
                    column_id=col_id, column_name=col_name
                )
            if record.get("policy"):
                tables[tid].columns[col_id].policies.append(
                    PolicyNode(**record["policy"])
                )

        # Register all columns (even those without explicit policies)
        for record in all_columns:
            tid = record["table_id"]
            col_id = record.get("column_id") or f"{tid}.{record['column_name']}"
            col_name = record["column_name"]
            if tid not in tables:
                tables[tid] = TableMeta(
                    table_id=tid,
                    table_name=tid.split(".")[-1] if "." in tid else tid,
                )
            if col_id not in tables[tid].columns:
                tables[tid].columns[col_id] = ColumnMeta(
                    column_id=col_id,
                    column_name=col_name,
                    is_pii=record.get("is_pii", False),
                )

        # Ensure every requested table exists (deny-by-default if missing)
        for tid in table_ids:
            if tid not in tables:
                tables[tid] = TableMeta(
                    table_id=tid,
                    table_name=tid.split(".")[-1] if "." in tid else tid,
                )

        # Populate sensitivity and domain from graph properties
        for tid, props in table_props.items():
            if tid in tables:
                tables[tid].sensitivity_level = props.get("sensitivity_level", 1)
                tables[tid].domain = props.get("domain", "")

        return tables

    # ------------------------------------------------------------------
    # Step 2: Conflict resolution
    # ------------------------------------------------------------------

    def _resolve_table_conflict(
        self, meta: TableMeta
    ) -> tuple[PolicyDecision, list[PolicyNode], str]:
        """Deterministic table-level conflict resolution.

        Rules (in order):
          1. No policies -> DENY (deny by default)
          2. DENY beats ALLOW at equal or higher priority
          3. Highest-priority grant wins otherwise
        """
        if not meta.table_policies:
            return PolicyDecision.DENY, [], "No policies apply -- deny by default"

        sorted_pols = sorted(
            meta.table_policies, key=lambda p: p.priority, reverse=True
        )

        best_deny_prio: int | None = None
        best_grant_prio: int | None = None

        for p in sorted_pols:
            eff = p.effect.upper()
            if eff == "DENY" and best_deny_prio is None:
                best_deny_prio = p.priority
            if eff in self._GRANT_EFFECTS and best_grant_prio is None:
                best_grant_prio = p.priority

        # DENY at equal or higher priority beats any grant
        if best_deny_prio is not None:
            if best_grant_prio is None or best_deny_prio >= best_grant_prio:
                active = [
                    p
                    for p in sorted_pols
                    if p.is_deny and p.priority == best_deny_prio
                ]
                return (
                    PolicyDecision.DENY,
                    active,
                    f"DENY via policy {active[0].policy_id}",
                )

        # Grant wins
        if best_grant_prio is not None:
            grants = [
                p for p in sorted_pols if p.effect.upper() in self._GRANT_EFFECTS
            ]
            return (
                PolicyDecision.ALLOW,
                grants,
                f"ALLOW via policy {grants[0].policy_id}",
            )

        return PolicyDecision.DENY, [], "No valid effect found -- deny by default"

    def _resolve_columns(
        self, meta: TableMeta, active_policies: list[PolicyNode]
    ) -> list[ColumnDecision]:
        """Resolve per-column visibility inside an ALLOWED table.

        PII columns default to HIDDEN unless explicitly allowed.
        """
        decisions: list[ColumnDecision] = []

        for _col_id, col in meta.columns.items():
            if not col.policies:
                # No explicit column policy -- inherit from table.
                # PII defaults to HIDDEN unless explicitly allowed.
                vis = ColumnVisibility.HIDDEN if col.is_pii else ColumnVisibility.VISIBLE
                decisions.append(
                    ColumnDecision(
                        column_name=col.column_name,
                        visibility=vis,
                        reason="PII default HIDDEN" if col.is_pii else "Inherited ALLOW from table",
                    )
                )
                continue

            sorted_pols = sorted(col.policies, key=lambda p: p.priority, reverse=True)
            top_priority = sorted_pols[0].priority
            top_tier = [p for p in sorted_pols if p.priority == top_priority]

            has_deny = any(p.is_deny for p in top_tier)
            has_mask = any(p.effect.upper() == "MASK" for p in top_tier)

            if has_deny:
                decisions.append(
                    ColumnDecision(
                        column_name=col.column_name,
                        visibility=ColumnVisibility.HIDDEN,
                        reason=f"DENIED via {top_tier[0].policy_id}",
                    )
                )
            elif has_mask:
                mask_pol = next(p for p in top_tier if p.effect.upper() == "MASK")
                expr = None
                for c in mask_pol.conditions:
                    if c.condition_type == "MASKING_RULE":
                        expr = c.expression
                decisions.append(
                    ColumnDecision(
                        column_name=col.column_name,
                        visibility=ColumnVisibility.MASKED,
                        masking_expression=expr,
                        reason=f"MASKED via {mask_pol.policy_id}",
                    )
                )
            else:
                decisions.append(
                    ColumnDecision(
                        column_name=col.column_name,
                        visibility=ColumnVisibility.VISIBLE,
                        reason=f"ALLOW via {top_tier[0].policy_id}",
                    )
                )

        return decisions

    # ------------------------------------------------------------------
    # Step 3: Condition aggregation
    # ------------------------------------------------------------------

    def _aggregate_row_filters(
        self, policies: list[PolicyNode], user_ctx: dict[str, Any]
    ) -> list[str]:
        """Extract and parameter-inject row-level filters from active policies."""
        filters: set[str] = set()
        for p in policies:
            for c in p.conditions:
                if c.condition_type == "ROW_FILTER":
                    injected = self._inject_parameters(c.expression, user_ctx)
                    filters.add(f"({injected})")
        return sorted(filters)

    def _aggregate_constraints(
        self, policies: list[PolicyNode]
    ) -> tuple[bool, int | None]:
        """Extract aggregation-only flag and max-rows limit."""
        agg_only = False
        max_rows: int | None = None

        for p in policies:
            for c in p.conditions:
                if c.condition_type in ("AGGREGATE_ONLY", "AGGREGATION_ONLY"):
                    agg_only = True
                elif c.condition_type in ("ROW_LIMIT", "MAX_ROWS"):
                    try:
                        limit = int(c.expression)
                        if max_rows is None or limit < max_rows:
                            max_rows = limit
                    except (ValueError, TypeError):
                        pass

        return agg_only, max_rows

    def _extract_join_restrictions(
        self, policies: list[PolicyNode]
    ) -> list[JoinRestriction]:
        """Extract cross-domain join restrictions."""
        restrictions: list[JoinRestriction] = []
        for p in policies:
            for c in p.conditions:
                if c.condition_type == "JOIN_RESTRICTION":
                    parts = c.expression.split("|")
                    if len(parts) == 2:
                        restrictions.append(
                            JoinRestriction(
                                source_domain=parts[0].strip(),
                                target_domain=parts[1].strip(),
                                policy_id=p.policy_id,
                            )
                        )
        return restrictions

    @staticmethod
    def _inject_parameters(expression: str, user_ctx: dict[str, Any]) -> str:
        """Replace $param and {{user.param}} placeholders with context values."""
        import re

        result = expression

        # Handle {{dotted.path}} syntax
        for match in re.finditer(r"\{\{([a-zA-Z0-9_.]+)\}\}", expression):
            var = match.group(1)
            val = _resolve_context_value(var, user_ctx)
            result = result.replace(match.group(0), val)

        # Handle $simple_var syntax
        for match in re.finditer(r"\$([a-zA-Z0-9_]+)", result):
            var = match.group(1)
            val = _resolve_context_value(var, user_ctx)
            result = result.replace(match.group(0), val)

        return result

    # ------------------------------------------------------------------
    # Step 4: NL rule generation
    # ------------------------------------------------------------------

    def _generate_nl_rules(
        self,
        envelope: PermissionEnvelope,
        join_restrictions: list[JoinRestriction],
    ) -> list[str]:
        """Generate natural-language rules for the LLM prompt."""
        rules: list[str] = []

        # Global join restrictions
        if join_restrictions:
            rules.append(
                "CRITICAL: You are strictly forbidden from joining "
                "the following domains together:"
            )
            for jr in join_restrictions:
                rules.append(
                    f"  - Do not join tables in domain '{jr.source_domain}' "
                    f"with tables in domain '{jr.target_domain}'"
                )

        # Per-table rules
        for tp in envelope.table_permissions:
            if tp.decision != PolicyDecision.ALLOW:
                continue

            # Row filters
            if tp.masking_rules:
                filter_str = " AND ".join(tp.masking_rules)
                rules.append(
                    f"MANDATORY: When querying '{tp.table_id}', you MUST include "
                    f"in the WHERE clause: {filter_str}"
                )

            # Aggregation-only
            if tp.aggregation_only:
                rules.append(
                    f"MANDATORY: Queries against '{tp.table_id}' must be aggregations "
                    f"(COUNT, SUM, AVG). You cannot SELECT individual rows."
                )

            # Max rows
            if tp.max_rows:
                rules.append(
                    f"MANDATORY: Queries against '{tp.table_id}' must be limited "
                    f"to {tp.max_rows} rows maximum."
                )

            # Masked columns
            masked = [
                c
                for c in tp.columns
                if c.get("visibility") == ColumnVisibility.MASKED.value
            ]
            if masked:
                parts = [
                    f"MANDATORY: The following columns in '{tp.table_id}' "
                    f"must be masked in the SELECT list:"
                ]
                for c in masked:
                    expr = c.get("masking_expression") or f"MASKED({c['column_name']})"
                    parts.append(f"  - {c['column_name']}: use `{expr}`")
                rules.append("\n".join(parts))

        return rules

    # ------------------------------------------------------------------
    # Step 5: Envelope signing
    # ------------------------------------------------------------------

    def _sign_envelope(self, envelope: PermissionEnvelope) -> str:
        """Create HMAC-SHA256 signature over deterministic envelope payload."""
        payload = {
            "expires_at": envelope.expires_at,
            "tables": [],
        }

        for tp in sorted(envelope.table_permissions, key=lambda t: t.table_id):
            entry: dict[str, Any] = {
                "id": tp.table_id,
                "dec": tp.decision.value,
                "agg": tp.aggregation_only,
                "rows": tp.max_rows,
            }
            if tp.columns:
                entry["cols"] = sorted(
                    [
                        {"n": c.get("column_name", ""), "v": c.get("visibility", "")}
                        for c in tp.columns
                    ],
                    key=lambda x: x["n"],
                )
            payload["tables"].append(entry)

        payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)

        return hmac.new(
            self._signing_key.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # BTG helpers
    # ------------------------------------------------------------------

    def _btg_can_override(
        self,
        table_id: str,
        meta: TableMeta,
        ctx: SecurityContext,
    ) -> bool:
        """Determine if BTG may override a DENY for this table.

        BTG overrides only when ALL deny policies have priority < 200.
        42 CFR Part 2 (Sensitivity-5) tables are never overridden.
        """
        # Sensitivity-5 tables are always blocked
        if meta.sensitivity_level >= 5:
            return False

        # Hard DENYs (priority >= 200) are never overridden
        for p in meta.table_policies:
            if p.is_deny and p.priority >= 200:
                return False

        return True

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_user_context(ctx: SecurityContext) -> dict[str, Any]:
        """Flatten SecurityContext into a dict for parameter injection."""
        return {
            "user_id": ctx.identity.oid,
            "department": ctx.org_context.department,
            "facility_ids": ctx.org_context.facility_ids,
            "unit_ids": ctx.org_context.unit_ids,
            "provider_npi": ctx.org_context.provider_npi,
            "clearance_level": ctx.authorization.clearance_level,
            "employee_id": ctx.org_context.employee_id,
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _resolve_context_value(var: str, ctx: dict[str, Any]) -> str:
    """Resolve a variable path against the user context dict."""
    clean = var
    if clean.startswith("user."):
        clean = clean[5:]

    parts = clean.split(".")
    val: Any = ctx
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        else:
            val = getattr(val, part, None)
        if val is None:
            break

    if val is None:
        return "NULL"
    if isinstance(val, (int, float, bool)):
        return str(val)
    safe = str(val).replace("'", "''")
    return f"'{safe}'"
