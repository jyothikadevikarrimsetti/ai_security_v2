"""Domain Filter -- Zero Trust Control ZT-003.

Removes tables outside the user's accessible domains before any further
processing.  This is the first gate in the RBAC pipeline: if a table
belongs to a domain the user cannot access, it is silently dropped.

Security invariants:
  - Tables from inaccessible domains are removed silently (no signal
    about denied tables -- prevents information leakage per Section 13.2).
  - Role-to-domain mapping is the single source of truth.
  - Unknown domains are denied by default.
  - Tables with no domain tag are denied by default (fail closed).
"""

from __future__ import annotations

from typing import Any

import structlog

from queryvault.app.models.enums import ColumnVisibility, PolicyDecision
from queryvault.app.models.security_context import SecurityContext

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Default role-to-domain mapping
# ---------------------------------------------------------------------------
# In production this would be loaded from Neo4j or a config store.
# Keys are role names (lowercased for matching); values are sets of
# domain tags the role may access.

_DEFAULT_ROLE_DOMAIN_MAP: dict[str, set[str]] = {
    # Clinical roles
    "attending_physician": {"CLINICAL", "ADMINISTRATIVE"},
    "resident": {"CLINICAL"},
    "nurse": {"CLINICAL"},
    "nurse_practitioner": {"CLINICAL"},
    "pharmacist": {"CLINICAL"},
    "lab_technician": {"CLINICAL"},
    "radiologist": {"CLINICAL"},
    "surgeon": {"CLINICAL"},
    "therapist": {"CLINICAL"},
    # Administrative roles
    "admin": {"ADMINISTRATIVE", "CLINICAL", "FINANCIAL", "IT_OPERATIONS"},
    "department_head": {"ADMINISTRATIVE", "CLINICAL"},
    "unit_clerk": {"ADMINISTRATIVE"},
    "receptionist": {"ADMINISTRATIVE"},
    # Financial / billing roles
    "billing_specialist": {"FINANCIAL"},
    "revenue_analyst": {"FINANCIAL"},
    "cfo": {"FINANCIAL", "ADMINISTRATIVE"},
    # HR / people roles
    "hr_manager": {"HR", "ADMINISTRATIVE"},
    "hr_analyst": {"HR"},
    # Research roles
    "researcher": {"RESEARCH"},
    "data_scientist": {"RESEARCH", "CLINICAL"},
    "irb_coordinator": {"RESEARCH", "COMPLIANCE"},
    # Compliance / audit roles
    "compliance_officer": {"COMPLIANCE", "CLINICAL", "FINANCIAL", "ADMINISTRATIVE"},
    "auditor": {"COMPLIANCE", "CLINICAL", "FINANCIAL"},
    "privacy_officer": {"COMPLIANCE", "CLINICAL"},
    # IT roles
    "dba": {"IT_OPERATIONS"},
    "sysadmin": {"IT_OPERATIONS"},
    "security_analyst": {"IT_OPERATIONS", "COMPLIANCE"},
}


class DomainFilter:
    """Filters tables by the user's accessible domains (ZT-003).

    Usage::

        df = DomainFilter()
        accessible = await df.filter(candidate_tables, security_context)
    """

    def __init__(
        self,
        role_domain_map: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise with an optional custom role-to-domain mapping.

        Args:
            role_domain_map: Override mapping from role name (lowercase)
                to set of accessible domain tags.  Falls back to the
                built-in default map when ``None``.
        """
        self._role_map: dict[str, set[str]] = (
            role_domain_map if role_domain_map is not None else _DEFAULT_ROLE_DOMAIN_MAP
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def filter(
        self,
        tables: list[dict[str, Any]],
        security_context: SecurityContext,
    ) -> list[dict[str, Any]]:
        """Remove tables outside the user's accessible domains.

        Args:
            tables: List of table metadata dicts.  Each dict must have at
                least ``"table_id"`` and should have ``"domain"`` (str).
            security_context: The authenticated user's security context.

        Returns:
            A new list containing only those tables whose domain is
            accessible to the user.  Removed tables produce no signal.
        """
        accessible_domains = self._get_accessible_domains(security_context)

        if not accessible_domains:
            logger.info(
                "domain_filter_no_domains",
                user=security_context.identity.oid,
                roles=security_context.authorization.effective_roles,
            )
            return []

        filtered: list[dict[str, Any]] = []
        denied_count = 0

        for table in tables:
            table_domain = (table.get("domain") or "").upper().strip()

            if not table_domain:
                # No domain tag -- fail closed
                denied_count += 1
                continue

            if table_domain in accessible_domains:
                filtered.append(table)
            else:
                denied_count += 1

        logger.info(
            "domain_filter_applied",
            user=security_context.identity.oid,
            accessible_domains=sorted(accessible_domains),
            tables_in=len(tables),
            tables_out=len(filtered),
            tables_denied=denied_count,
        )

        return filtered

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_accessible_domains(
        self, security_context: SecurityContext
    ) -> set[str]:
        """Compute the union of domains accessible via the user's roles."""
        domains: set[str] = set()
        for role in security_context.authorization.effective_roles:
            role_lower = role.lower().strip()
            role_domains = self._role_map.get(role_lower)
            if role_domains:
                domains.update(role_domains)
        return domains

    def get_domains_for_role(self, role: str) -> set[str]:
        """Return the set of domains accessible to a single role.

        Useful for diagnostics and policy inspection.
        """
        return set(self._role_map.get(role.lower().strip(), set()))

    def register_role_domains(self, role: str, domains: set[str]) -> None:
        """Register or update a role's accessible domains at runtime.

        Args:
            role: Role name (will be stored lowercase).
            domains: Set of domain tags the role may access.
        """
        self._role_map[role.lower().strip()] = {d.upper() for d in domains}
