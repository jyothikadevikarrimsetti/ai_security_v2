"""KG-004 Schema Change Detector -- scheduled or manual schema drift detection.

Compares the current live database schema against the stored catalog in
the graph.  Produces a ChangeReport identifying added, modified, removed,
and breaking changes.  Breaking changes (dropped tables, column type
changes) trigger alerts and can optionally re-embed affected descriptions.

This module is about detecting schema *drift*, not about access control
or policy changes (those belong to QueryVault).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from xensql.app.models.enums import SQLDialect
from xensql.app.models.schema import ColumnInfo, TableInfo
from xensql.app.services.knowledge_graph.schema_crawler import (
    DatabaseConfig,
    SchemaCrawler,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Change types
# ---------------------------------------------------------------------------

class ChangeType(str, Enum):
    """Categories of detected schema change."""

    TABLE_ADDED = "TABLE_ADDED"
    TABLE_REMOVED = "TABLE_REMOVED"
    COLUMN_ADDED = "COLUMN_ADDED"
    COLUMN_REMOVED = "COLUMN_REMOVED"
    COLUMN_TYPE_CHANGED = "COLUMN_TYPE_CHANGED"
    COLUMN_NULLABLE_CHANGED = "COLUMN_NULLABLE_CHANGED"
    TABLE_ROW_COUNT_CHANGED = "TABLE_ROW_COUNT_CHANGED"


class Severity(str, Enum):
    """Severity of a detected change for alerting."""

    INFO = "INFO"
    WARNING = "WARNING"
    BREAKING = "BREAKING"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SchemaChange:
    """A single detected schema change."""

    change_type: ChangeType
    severity: Severity
    entity_fqn: str
    description: str
    old_value: Any = None
    new_value: Any = None


@dataclass
class ChangeReport:
    """Full change report from a detection run."""

    database_name: str = ""
    detection_time: float = 0.0
    duration_seconds: float = 0.0

    added: list[SchemaChange] = field(default_factory=list)
    modified: list[SchemaChange] = field(default_factory=list)
    removed: list[SchemaChange] = field(default_factory=list)
    breaking_changes: list[SchemaChange] = field(default_factory=list)

    @property
    def has_breaking_changes(self) -> bool:
        return len(self.breaking_changes) > 0

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.modified) + len(self.removed)

    @property
    def all_changes(self) -> list[SchemaChange]:
        return self.added + self.modified + self.removed


# ---------------------------------------------------------------------------
# Breaking change classification
# ---------------------------------------------------------------------------

# Change types that are considered breaking (require alerts / re-embedding)
_BREAKING_CHANGE_TYPES = {
    ChangeType.TABLE_REMOVED,
    ChangeType.COLUMN_REMOVED,
    ChangeType.COLUMN_TYPE_CHANGED,
}


# ---------------------------------------------------------------------------
# SchemaChangeDetector
# ---------------------------------------------------------------------------

class SchemaChangeDetector:
    """Detects schema drift between the live database and the stored catalog.

    Typical usage:
        detector = SchemaChangeDetector(graph_store=gs, crawler=crawler)
        report = await detector.detect_changes(db_config)
        if report.has_breaking_changes:
            await notify_admins(report.breaking_changes)
    """

    def __init__(
        self,
        graph_store: Any,
        crawler: SchemaCrawler | None = None,
        re_embed_callback: Any | None = None,
    ) -> None:
        """
        Args:
            graph_store: GraphStore instance for reading current catalog state.
            crawler: SchemaCrawler for extracting live schema.  If None, a
                     default instance is created.
            re_embed_callback: Optional async callable(list[str]) to trigger
                               re-embedding for affected entity FQNs.
        """
        self._graph_store = graph_store
        self._crawler = crawler or SchemaCrawler()
        self._re_embed_callback = re_embed_callback

    async def detect_changes(
        self,
        database_config: DatabaseConfig,
    ) -> ChangeReport:
        """Compare live DB schema against stored catalog.

        1. Crawl the live database.
        2. Load the stored catalog from the graph.
        3. Diff tables and columns.
        4. Classify changes by severity.
        5. Optionally trigger re-embedding for affected entities.

        Returns:
            ChangeReport with all detected changes categorized.
        """
        start = time.monotonic()
        report = ChangeReport(
            database_name=database_config.name,
            detection_time=time.time(),
        )

        try:
            # 1. Crawl live schema
            crawl_result = await self._crawler.crawl(database_config)
            if crawl_result.errors:
                logger.error(
                    "change_detection_crawl_errors",
                    database=database_config.name,
                    errors=crawl_result.errors,
                )
                return report

            if crawl_result.extracted is None:
                logger.warning(
                    "change_detection_no_extraction",
                    database=database_config.name,
                )
                return report

            # 2. Load existing catalog from graph
            existing_tables = await self._graph_store.get_tables(
                database_config.name
            )
            existing_by_fqn: dict[str, TableInfo] = {
                t.table_id: t for t in existing_tables
            }

            # Load columns for existing tables
            existing_columns: dict[str, list[ColumnInfo]] = {}
            for table in existing_tables:
                cols = await self._graph_store.get_table_columns(table.table_id)
                existing_columns[table.table_id] = cols

            # 3. Build live table map from crawl extraction
            live_fqns: set[str] = set()
            live_columns: dict[str, list[ColumnInfo]] = {}

            for schema_name, tables in crawl_result.extracted.schemas.items():
                for tbl in tables:
                    fqn = (
                        f"{database_config.name}.{schema_name}.{tbl.table_name}"
                    )
                    live_fqns.add(fqn)

                    live_columns[fqn] = [
                        ColumnInfo(
                            column_id=f"{fqn}.{c.name}",
                            column_name=c.name,
                            data_type=c.data_type,
                            is_pk=c.is_pk,
                        )
                        for c in tbl.columns
                    ]

            existing_fqns = set(existing_by_fqn.keys())

            # 4. Detect added tables
            for fqn in live_fqns - existing_fqns:
                change = SchemaChange(
                    change_type=ChangeType.TABLE_ADDED,
                    severity=Severity.INFO,
                    entity_fqn=fqn,
                    description=f"New table discovered: {fqn}",
                )
                report.added.append(change)

            # 5. Detect removed tables (BREAKING)
            for fqn in existing_fqns - live_fqns:
                change = SchemaChange(
                    change_type=ChangeType.TABLE_REMOVED,
                    severity=Severity.BREAKING,
                    entity_fqn=fqn,
                    description=f"Table no longer exists in source: {fqn}",
                )
                report.removed.append(change)
                report.breaking_changes.append(change)

            # 6. Detect column-level changes for tables that exist in both
            affected_fqns: list[str] = []

            for fqn in live_fqns & existing_fqns:
                live_cols = {c.column_name: c for c in live_columns.get(fqn, [])}
                stored_cols = {
                    c.column_name: c for c in existing_columns.get(fqn, [])
                }

                # New columns
                for col_name in set(live_cols) - set(stored_cols):
                    col_fqn = f"{fqn}.{col_name}"
                    change = SchemaChange(
                        change_type=ChangeType.COLUMN_ADDED,
                        severity=Severity.INFO,
                        entity_fqn=col_fqn,
                        description=f"New column: {col_fqn}",
                        new_value=live_cols[col_name].data_type,
                    )
                    report.added.append(change)
                    affected_fqns.append(fqn)

                # Removed columns (BREAKING)
                for col_name in set(stored_cols) - set(live_cols):
                    col_fqn = f"{fqn}.{col_name}"
                    change = SchemaChange(
                        change_type=ChangeType.COLUMN_REMOVED,
                        severity=Severity.BREAKING,
                        entity_fqn=col_fqn,
                        description=f"Column removed: {col_fqn}",
                        old_value=stored_cols[col_name].data_type,
                    )
                    report.removed.append(change)
                    report.breaking_changes.append(change)
                    affected_fqns.append(fqn)

                # Modified columns (type changes are BREAKING)
                for col_name in set(live_cols) & set(stored_cols):
                    live_col = live_cols[col_name]
                    stored_col = stored_cols[col_name]
                    col_fqn = f"{fqn}.{col_name}"

                    if live_col.data_type != stored_col.data_type:
                        change = SchemaChange(
                            change_type=ChangeType.COLUMN_TYPE_CHANGED,
                            severity=Severity.BREAKING,
                            entity_fqn=col_fqn,
                            description=(
                                f"Column type changed: {col_fqn} "
                                f"({stored_col.data_type} -> {live_col.data_type})"
                            ),
                            old_value=stored_col.data_type,
                            new_value=live_col.data_type,
                        )
                        report.modified.append(change)
                        report.breaking_changes.append(change)
                        affected_fqns.append(fqn)

            # 7. Trigger re-embedding for affected entities
            if affected_fqns and self._re_embed_callback:
                unique_fqns = list(set(affected_fqns))
                try:
                    await self._re_embed_callback(unique_fqns)
                    logger.info(
                        "re_embedding_triggered",
                        affected_count=len(unique_fqns),
                    )
                except Exception as exc:
                    logger.error(
                        "re_embedding_failed",
                        error=str(exc),
                        affected_count=len(unique_fqns),
                    )

        except Exception as exc:
            logger.error(
                "change_detection_failed",
                database=database_config.name,
                error=str(exc),
            )

        report.duration_seconds = round(time.monotonic() - start, 3)

        logger.info(
            "change_detection_complete",
            database=database_config.name,
            added=len(report.added),
            modified=len(report.modified),
            removed=len(report.removed),
            breaking=len(report.breaking_changes),
            duration_s=report.duration_seconds,
        )
        return report
