"""KG-003 Domain Tagger -- rule-based domain classification for tables.

Groups tables into business domains (Clinical, Billing, Pharmacy, Lab,
HR, Scheduling, Financial) using keyword matching against table names,
schema names, and column names.  Detects cross-domain foreign keys and
builds a domain affinity map for retrieval ranking.

This module is purely about schema organization.  It does NOT handle
access control, policies, or PII classification (those belong to QueryVault).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from xensql.app.models.enums import DomainType
from xensql.app.models.schema import ForeignKey, TableInfo

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Domain keyword rules
# ---------------------------------------------------------------------------

# Each domain maps to keywords that may appear in table names, schema names,
# or column names.  Keywords are checked with substring matching.
_DOMAIN_KEYWORDS: dict[DomainType, list[str]] = {
    DomainType.CLINICAL: [
        "patient", "clinical", "medical", "emr", "ehr", "diagnosis",
        "encounter", "visit", "admission", "discharge", "procedure",
        "vitals", "allergy", "immunization", "condition", "observation",
        "care_plan", "referral", "treatment",
    ],
    DomainType.BILLING: [
        "billing", "invoice", "claims", "claim", "payment", "charge",
        "revenue", "remittance", "copay", "deductible", "payer",
        "accounts_receivable", "ar_",
    ],
    DomainType.PHARMACY: [
        "pharmacy", "rx", "prescription", "medication", "drug",
        "dispens", "formulary", "ndc", "dose", "refill",
    ],
    DomainType.LABORATORY: [
        "lab", "laboratory", "pathology", "specimen", "test_result",
        "lab_result", "lab_order", "culture", "microbiology", "cytology",
    ],
    DomainType.HR: [
        "hr", "human_resource", "employee", "payroll", "staff",
        "department", "position", "hire", "termination", "benefits",
        "compensation", "attendance", "leave", "pto",
    ],
    DomainType.SCHEDULING: [
        "schedul", "appointment", "slot", "calendar", "booking",
        "availability", "waitlist", "roster", "shift",
    ],
    DomainType.FINANCIAL: [
        "financial", "finance", "ledger", "journal", "gl_",
        "general_ledger", "budget", "cost_center", "account",
        "fiscal", "asset", "liability", "equity",
    ],
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CrossDomainFK:
    """A foreign key that bridges two different domains."""

    fk: ForeignKey
    source_table_id: str
    source_domain: DomainType
    target_table_id: str
    target_domain: DomainType


@dataclass
class DomainAffinityMap:
    """Maps each domain to related domains ranked by FK connectivity."""

    # domain -> list of (related_domain, strength) ordered descending
    affinities: dict[DomainType, list[tuple[DomainType, float]]] = field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# DomainTagger
# ---------------------------------------------------------------------------

class DomainTagger:
    """Rule-based domain tagger for schema tables.

    Uses keyword matching against table names, schema names, and column
    names to assign a primary domain.  Produces a domain affinity map
    from cross-domain FK analysis for retrieval ranking.
    """

    def __init__(self, graph_store: Any | None = None) -> None:
        self._graph_store = graph_store

    async def tag(
        self,
        tables: list[TableInfo],
    ) -> dict[str, DomainType]:
        """Assign a domain to each table based on keyword rules.

        Args:
            tables: Tables to classify.

        Returns:
            Mapping of table_id to DomainType.
        """
        result: dict[str, DomainType] = {}

        for table in tables:
            domain = self._classify_table(table)
            result[table.table_id] = domain

            # Persist to graph if available
            if self._graph_store is not None:
                table.domain = domain
                await self._graph_store.upsert_table(table)

            logger.debug(
                "table_domain_tagged",
                table_id=table.table_id,
                domain=domain.value,
            )

        # Summary log
        domain_counts: dict[str, int] = {}
        for d in result.values():
            domain_counts[d.value] = domain_counts.get(d.value, 0) + 1
        logger.info(
            "domain_tagging_complete",
            tables_tagged=len(result),
            distribution=domain_counts,
        )

        return result

    def detect_cross_domain_fks(
        self,
        fks: list[ForeignKey],
        domain_map: dict[str, DomainType],
    ) -> list[CrossDomainFK]:
        """Identify foreign keys that cross domain boundaries.

        Args:
            fks: All foreign keys to analyze.
            domain_map: table_id -> DomainType mapping (output of tag()).

        Returns:
            List of CrossDomainFK instances for FKs that bridge domains.
        """
        cross_domain: list[CrossDomainFK] = []

        for fk in fks:
            src_domain = domain_map.get(fk.from_table)
            tgt_domain = domain_map.get(fk.to_table)

            if src_domain and tgt_domain and src_domain != tgt_domain:
                cross_domain.append(CrossDomainFK(
                    fk=fk,
                    source_table_id=fk.from_table,
                    source_domain=src_domain,
                    target_table_id=fk.to_table,
                    target_domain=tgt_domain,
                ))

        logger.info(
            "cross_domain_fks_detected",
            total_fks=len(fks),
            cross_domain_count=len(cross_domain),
        )
        return cross_domain

    def build_affinity_map(
        self,
        cross_domain_fks: list[CrossDomainFK],
    ) -> DomainAffinityMap:
        """Build a domain affinity map from cross-domain FK relationships.

        Affinity strength is proportional to the number of cross-domain
        FK connections between two domains.  Used by retrieval to rank
        related tables from adjacent domains.
        """
        # Count connections between domain pairs
        pair_counts: dict[tuple[DomainType, DomainType], int] = {}
        for cdfk in cross_domain_fks:
            pair = (cdfk.source_domain, cdfk.target_domain)
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
            # Symmetric
            reverse = (cdfk.target_domain, cdfk.source_domain)
            pair_counts[reverse] = pair_counts.get(reverse, 0) + 1

        # Normalize and build affinity map
        affinity_map = DomainAffinityMap()
        domains_seen: set[DomainType] = set()

        for (src, tgt), count in pair_counts.items():
            domains_seen.add(src)

        # Find max count for normalization
        max_count = max(pair_counts.values()) if pair_counts else 1

        for domain in domains_seen:
            related: list[tuple[DomainType, float]] = []
            for (src, tgt), count in pair_counts.items():
                if src == domain and tgt != domain:
                    strength = count / max_count
                    related.append((tgt, round(strength, 3)))
            # Sort descending by strength
            related.sort(key=lambda x: x[1], reverse=True)
            affinity_map.affinities[domain] = related

        logger.info(
            "affinity_map_built",
            domains=len(affinity_map.affinities),
        )
        return affinity_map

    # ---- Private helpers ----

    def _classify_table(self, table: TableInfo) -> DomainType:
        """Classify a single table using keyword matching.

        Scoring:
        - Schema name match:  3 points per keyword
        - Table name match:   3 points per keyword
        - Column name match:  1 point per keyword

        The domain with the highest score wins.  Ties are broken by enum
        order (which is arbitrary but deterministic).
        """
        scores: dict[DomainType, int] = {d: 0 for d in DomainType}

        schema_lower = (table.schema_name or "").lower()
        table_lower = (table.table_name or "").lower()
        col_names_lower = [c.column_name.lower() for c in table.columns]

        for domain, keywords in _DOMAIN_KEYWORDS.items():
            for kw in keywords:
                # Schema name matches (high signal)
                if kw in schema_lower:
                    scores[domain] += 3

                # Table name matches (high signal)
                if kw in table_lower:
                    scores[domain] += 3

                # Column name matches (lower signal, but additive)
                for col_name in col_names_lower:
                    if kw in col_name:
                        scores[domain] += 1

        # Find the highest-scoring domain
        best_domain = DomainType.CLINICAL  # default fallback
        best_score = 0
        for domain, score in scores.items():
            if score > best_score:
                best_score = score
                best_domain = domain

        # If no keywords matched at all, try schema name as direct domain hint
        if best_score == 0:
            best_domain = self._infer_from_schema_name(schema_lower)

        return best_domain

    @staticmethod
    def _infer_from_schema_name(schema_name: str) -> DomainType:
        """Last-resort domain inference from schema name."""
        direct_map: dict[str, DomainType] = {
            "clinical": DomainType.CLINICAL,
            "billing": DomainType.BILLING,
            "pharmacy": DomainType.PHARMACY,
            "lab": DomainType.LABORATORY,
            "laboratory": DomainType.LABORATORY,
            "hr": DomainType.HR,
            "human_resources": DomainType.HR,
            "scheduling": DomainType.SCHEDULING,
            "finance": DomainType.FINANCIAL,
            "financial": DomainType.FINANCIAL,
        }
        for key, domain in direct_map.items():
            if key in schema_name:
                return domain
        return DomainType.CLINICAL  # default
