"""Join Path Discovery -- FK graph construction and multi-hop path finding.

Builds an FK graph from the schema catalog and discovers optimal join paths
via 1-hop, 2-hop, and 3-hop FK traversal. Automatically includes bridge /
junction tables detected by naming convention.

XenSQL is a pure NL-to-SQL pipeline engine. No RBAC, no policy-based edge
exclusion, no restricted_joins logic. QueryVault handles all access-control
filtering upstream -- XenSQL operates on whatever tables it receives.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import structlog

from xensql.app.models.enums import IntentType
from xensql.app.models.schema import ForeignKey, TableInfo

logger = structlog.get_logger(__name__)

# Bridge / junction table name patterns
_BRIDGE_PATTERNS = (
    "_to_", "_x_", "_map", "_link", "_bridge", "_assoc",
    "_rel", "_xref", "mapping", "junction",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class JoinEdge:
    """A single FK edge in the join graph."""

    source_table: str
    source_column: str
    target_table: str
    target_column: str
    constraint_name: str = ""
    is_bridge: bool = False


@dataclass
class JoinPath:
    """An ordered sequence of join edges connecting two tables."""

    edges: list[JoinEdge] = field(default_factory=list)
    hop_count: int = 0
    includes_bridge: bool = False

    @property
    def tables(self) -> list[str]:
        """Return all tables in path order."""
        if not self.edges:
            return []
        result = [self.edges[0].source_table]
        for e in self.edges:
            result.append(e.target_table)
        return result


@dataclass
class FKGraph:
    """Adjacency-list representation of FK relationships."""

    # table_id -> list of JoinEdge from that table
    adjacency: dict[str, list[JoinEdge]] = field(default_factory=lambda: defaultdict(list))
    # All table IDs present in the graph
    table_ids: set[str] = field(default_factory=set)
    # Known bridge / junction tables
    bridge_tables: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class JoinPathDiscovery:
    """Builds an FK graph and discovers optimal join paths.

    No policy-based edge exclusion -- the graph includes all FK edges
    present in the tables XenSQL receives.
    """

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_fk_graph(self, tables: list[TableInfo]) -> FKGraph:
        """Build an FK graph from a list of TableInfo objects.

        Scans each table's columns for FK references and constructs
        bidirectional adjacency lists. Also detects bridge tables by
        naming patterns.

        Args:
            tables: Pre-filtered tables from the schema catalog.

        Returns:
            FKGraph with adjacency lists and bridge table set.
        """
        graph = FKGraph()
        table_id_set = {t.table_id for t in tables}

        for table in tables:
            graph.table_ids.add(table.table_id)

            # Detect bridge tables
            if _is_bridge_table(table.table_name):
                graph.bridge_tables.add(table.table_id)

            # Build edges from column FK references
            for col in table.columns:
                if col.is_fk and col.fk_ref:
                    # Parse fk_ref format: "schema.table.column" or "table.column"
                    target_table, target_column = _parse_fk_ref(
                        col.fk_ref, table, tables
                    )
                    if not target_table:
                        continue

                    # Only include edges where both endpoints are in the table set
                    if target_table not in table_id_set:
                        logger.debug(
                            "fk_target_not_in_set",
                            source=table.table_id,
                            target=target_table,
                        )
                        continue

                    is_bridge = (
                        table.table_id in graph.bridge_tables
                        or target_table in graph.bridge_tables
                    )

                    edge = JoinEdge(
                        source_table=table.table_id,
                        source_column=col.column_name,
                        target_table=target_table,
                        target_column=target_column,
                        is_bridge=is_bridge,
                    )
                    graph.adjacency[table.table_id].append(edge)

                    # Add reverse edge for bidirectional traversal
                    reverse_edge = JoinEdge(
                        source_table=target_table,
                        source_column=target_column,
                        target_table=table.table_id,
                        target_column=col.column_name,
                        is_bridge=is_bridge,
                    )
                    graph.adjacency[target_table].append(reverse_edge)

        logger.info(
            "fk_graph_built",
            tables=len(graph.table_ids),
            edges=sum(len(v) for v in graph.adjacency.values()),
            bridges=len(graph.bridge_tables),
        )
        return graph

    def build_fk_graph_from_fks(
        self,
        foreign_keys: list[ForeignKey],
        table_ids: set[str] | None = None,
    ) -> FKGraph:
        """Build an FK graph from explicit ForeignKey objects.

        Args:
            foreign_keys: List of FK relationships.
            table_ids: Optional set of valid table IDs. If provided,
                       only edges where both endpoints are in the set
                       are included.

        Returns:
            FKGraph with adjacency lists.
        """
        graph = FKGraph()

        for fk in foreign_keys:
            # Filter to known tables if table_ids provided
            if table_ids:
                if fk.from_table not in table_ids or fk.to_table not in table_ids:
                    continue

            graph.table_ids.add(fk.from_table)
            graph.table_ids.add(fk.to_table)

            if _is_bridge_table(fk.from_table.split(".")[-1]):
                graph.bridge_tables.add(fk.from_table)
            if _is_bridge_table(fk.to_table.split(".")[-1]):
                graph.bridge_tables.add(fk.to_table)

            is_bridge = (
                fk.from_table in graph.bridge_tables
                or fk.to_table in graph.bridge_tables
            )

            edge = JoinEdge(
                source_table=fk.from_table,
                source_column=fk.from_column,
                target_table=fk.to_table,
                target_column=fk.to_column,
                is_bridge=is_bridge,
            )
            graph.adjacency[fk.from_table].append(edge)

            reverse = JoinEdge(
                source_table=fk.to_table,
                source_column=fk.to_column,
                target_table=fk.from_table,
                target_column=fk.from_column,
                is_bridge=is_bridge,
            )
            graph.adjacency[fk.to_table].append(reverse)

        return graph

    # ------------------------------------------------------------------
    # Path discovery
    # ------------------------------------------------------------------

    def discover(
        self,
        tables: list[str],
        fk_graph: FKGraph,
        max_hops: int = 3,
    ) -> list[JoinPath]:
        """Discover optimal join paths connecting the given tables.

        Uses BFS-based multi-hop traversal (1, 2, 3 hops) to find paths
        between each pair of requested tables. Automatically includes
        bridge/junction tables when they appear on a path.

        Args:
            tables: Table IDs that need to be connected.
            fk_graph: Pre-built FK graph.
            max_hops: Maximum FK hops to traverse (default 3).

        Returns:
            List of JoinPath objects connecting the requested tables.
        """
        if len(tables) < 2:
            return []

        all_paths: list[JoinPath] = []
        seen_pairs: set[tuple[str, str]] = set()

        for i, source in enumerate(tables):
            for target in tables[i + 1:]:
                pair = (min(source, target), max(source, target))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                path = self._find_shortest_path(
                    source, target, fk_graph, max_hops
                )
                if path:
                    all_paths.append(path)

        # Auto-include bridge tables that sit on discovered paths
        bridge_additions = self._discover_bridge_shortcuts(
            tables, fk_graph, all_paths
        )
        all_paths.extend(bridge_additions)

        logger.info(
            "join_paths_discovered",
            requested_tables=len(tables),
            paths_found=len(all_paths),
        )
        return all_paths

    def _find_shortest_path(
        self,
        source: str,
        target: str,
        fk_graph: FKGraph,
        max_hops: int,
    ) -> JoinPath | None:
        """BFS to find the shortest FK path from source to target.

        Returns None if no path exists within max_hops.
        """
        if source not in fk_graph.adjacency or target not in fk_graph.table_ids:
            return None

        # BFS
        queue: deque[tuple[str, list[JoinEdge]]] = deque()
        queue.append((source, []))
        visited: set[str] = {source}

        while queue:
            current, path_edges = queue.popleft()

            if len(path_edges) >= max_hops:
                continue

            for edge in fk_graph.adjacency.get(current, []):
                if edge.target_table in visited:
                    continue

                new_path = path_edges + [edge]

                if edge.target_table == target:
                    includes_bridge = any(e.is_bridge for e in new_path)
                    return JoinPath(
                        edges=new_path,
                        hop_count=len(new_path),
                        includes_bridge=includes_bridge,
                    )

                visited.add(edge.target_table)
                queue.append((edge.target_table, new_path))

        return None

    def _discover_bridge_shortcuts(
        self,
        tables: list[str],
        fk_graph: FKGraph,
        existing_paths: list[JoinPath],
    ) -> list[JoinPath]:
        """Find paths through bridge tables not yet covered.

        If a bridge table connects two requested tables and no direct
        path was found, add it.
        """
        additions: list[JoinPath] = []

        # Collect tables already connected
        connected_pairs: set[tuple[str, str]] = set()
        for p in existing_paths:
            t = p.tables
            if len(t) >= 2:
                connected_pairs.add((min(t[0], t[-1]), max(t[0], t[-1])))

        for bridge_id in fk_graph.bridge_tables:
            if bridge_id in tables:
                continue  # Already requested

            # Check if this bridge connects two of our requested tables
            bridge_neighbors = {
                e.target_table for e in fk_graph.adjacency.get(bridge_id, [])
            }
            connected_requested = [t for t in tables if t in bridge_neighbors]

            if len(connected_requested) >= 2:
                # Build a path through the bridge for the first pair
                src = connected_requested[0]
                tgt = connected_requested[1]
                pair = (min(src, tgt), max(src, tgt))

                if pair not in connected_pairs:
                    # Find edges
                    edge_to_bridge = None
                    edge_from_bridge = None
                    for e in fk_graph.adjacency.get(src, []):
                        if e.target_table == bridge_id:
                            edge_to_bridge = e
                            break
                    for e in fk_graph.adjacency.get(bridge_id, []):
                        if e.target_table == tgt:
                            edge_from_bridge = e
                            break

                    if edge_to_bridge and edge_from_bridge:
                        additions.append(JoinPath(
                            edges=[edge_to_bridge, edge_from_bridge],
                            hop_count=2,
                            includes_bridge=True,
                        ))
                        connected_pairs.add(pair)

        return additions

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_required_tables(
        self,
        join_paths: list[JoinPath],
        seed_tables: list[str],
    ) -> list[str]:
        """Return deduplicated list of all tables needed for the join paths.

        Includes seed tables plus any intermediate tables (bridges, etc.).
        """
        required: dict[str, None] = {}  # ordered set via dict
        for t in seed_tables:
            required[t] = None
        for path in join_paths:
            for t in path.tables:
                required[t] = None
        return list(required.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_bridge_table(table_name: str) -> bool:
    """Detect bridge/junction tables by naming patterns."""
    name = table_name.lower()
    return any(p in name for p in _BRIDGE_PATTERNS)


def _parse_fk_ref(
    fk_ref: str,
    source_table: TableInfo,
    all_tables: list[TableInfo],
) -> tuple[str, str]:
    """Parse an FK reference string into (target_table_id, target_column).

    Handles formats:
    - "schema.table.column" -> find matching table_id, return column
    - "table.column" -> match by table_name, return column
    - "table_id.column" -> direct match

    Returns ("", "") if no match found.
    """
    parts = fk_ref.split(".")

    if len(parts) >= 3:
        # Could be "db.schema.table.column" or "schema.table.column"
        target_column = parts[-1]
        # Try to match table_id by joining all but last part
        candidate_id = ".".join(parts[:-1])
        for t in all_tables:
            if t.table_id == candidate_id:
                return t.table_id, target_column
        # Try matching by table_name (last two parts before column)
        candidate_name = parts[-2]
        for t in all_tables:
            if t.table_name == candidate_name:
                return t.table_id, target_column

    elif len(parts) == 2:
        # "table.column"
        target_name, target_column = parts
        for t in all_tables:
            if t.table_name == target_name:
                return t.table_id, target_column
        # Try table_id direct match
        for t in all_tables:
            if t.table_id == target_name:
                return t.table_id, target_column

    return "", ""
