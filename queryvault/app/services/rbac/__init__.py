"""QueryVault RBAC & Zero Trust Module.

Enforces Zero Trust access control across the NL-to-SQL pipeline:

  ZT-002  PolicyResolver     -- Full policy resolution pipeline with
                                HMAC-SHA256 signed Permission Envelopes.
  ZT-003  DomainFilter       -- Remove tables outside the user's domains.
  ZT-004  ColumnScoper       -- Per-table column visibility scoping.
  ZT-005  RowFilter          -- Mandatory WHERE-clause injection rules.
  ZT-009  BreakGlassManager  -- Emergency 4-hour elevated access with
                                42 CFR Part 2 hard-block.
"""

from queryvault.app.services.rbac.break_glass import (
    BreakGlassManager,
    BTGToken,
    ComplianceNotification,
)
from queryvault.app.services.rbac.column_scoper import (
    ColumnInfo,
    ColumnPolicy,
    ColumnScoper,
    ScopedColumn,
    ScopedColumns,
)
from queryvault.app.services.rbac.domain_filter import DomainFilter
from queryvault.app.services.rbac.policy_resolver import (
    PolicyResolver,
    get_resolution_stats,
    clear_resolution_stats,
)
from queryvault.app.services.rbac.row_filter import (
    RowFilter,
    RowFilterRule,
)

__all__ = [
    # ZT-002: Policy Resolution
    "PolicyResolver",
    "get_resolution_stats",
    "clear_resolution_stats",
    # ZT-003: Domain Filter
    "DomainFilter",
    # ZT-004: Column Scoper
    "ColumnScoper",
    "ColumnInfo",
    "ColumnPolicy",
    "ScopedColumn",
    "ScopedColumns",
    # ZT-005: Row Filter
    "RowFilter",
    "RowFilterRule",
    # ZT-009: Break-the-Glass
    "BreakGlassManager",
    "BTGToken",
    "ComplianceNotification",
]
