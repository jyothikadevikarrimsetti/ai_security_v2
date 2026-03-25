"""KG-002 Description Generator -- LLM-powered natural-language descriptions.

Generates human-readable descriptions for tables and columns using the
configured LLM provider.  Descriptions are generated once and cached;
subsequent calls skip already-described entities unless force=True.

Descriptions serve as the primary input for semantic embedding and
retrieval ranking.  An expert review/correction workflow allows human
overrides that are preserved across re-generation runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from xensql.app.models.schema import ColumnInfo, TableInfo

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DescriptionResult:
    """Outcome of a description generation batch."""

    generated: int = 0
    skipped: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ReviewableDescription:
    """A generated description awaiting expert review."""

    entity_id: str
    entity_type: str  # "table" or "column"
    generated_description: str
    reviewed: bool = False
    reviewer: str = ""
    corrected_description: str = ""


# ---------------------------------------------------------------------------
# LLM provider protocol
# ---------------------------------------------------------------------------

class LLMProvider:
    """Adapter for the configured LLM backend.

    In production, this wraps the actual LLM client (OpenAI, Azure, etc.).
    The DescriptionGenerator depends only on this interface.
    """

    async def complete(self, prompt: str, system: str = "") -> str:
        """Return the LLM completion for the given prompt."""
        raise NotImplementedError("LLMProvider.complete must be overridden")


# ---------------------------------------------------------------------------
# DescriptionGenerator
# ---------------------------------------------------------------------------

class DescriptionGenerator:
    """Generates NL descriptions for tables and columns via LLM.

    Descriptions are idempotent -- already-described entities are skipped
    unless force=True.  Human-reviewed descriptions (corrected_description
    set) are never overwritten.
    """

    # Prompt templates
    _TABLE_SYSTEM = (
        "You are a database documentation expert.  Given a table's name, "
        "schema, columns, and any foreign keys, produce a concise (1-3 sentence) "
        "natural-language description of the table's purpose and contents.  "
        "Focus on what business data the table stores and how it relates to "
        "other entities.  Do not include SQL or technical jargon."
    )

    _COLUMN_SYSTEM = (
        "You are a database documentation expert.  Given a column name, its "
        "data type, the parent table name, and surrounding column context, "
        "produce a concise (1 sentence) description of what the column stores.  "
        "Use plain business language."
    )

    def __init__(
        self,
        llm: LLMProvider,
        graph_store: Any | None = None,
    ) -> None:
        self._llm = llm
        self._graph_store = graph_store
        # In-memory review queue; production implementation would persist this
        self._review_queue: list[ReviewableDescription] = []

    async def generate(
        self,
        tables: list[TableInfo],
        *,
        force: bool = False,
    ) -> dict[str, str]:
        """Generate NL descriptions for a list of tables.

        Args:
            tables: Tables to describe.
            force: If True, regenerate even if a description already exists.
                   Human-reviewed descriptions are never overwritten.

        Returns:
            Mapping of table_id to generated description.
        """
        results: dict[str, str] = {}
        stats = DescriptionResult()

        for table in tables:
            # Skip if already described (and not forcing)
            if table.description and not force:
                stats.skipped += 1
                continue

            # Never overwrite human-reviewed descriptions
            if self._is_human_reviewed(table.table_id):
                stats.skipped += 1
                continue

            prompt = self._build_table_prompt(table)
            try:
                description = await self._llm.complete(
                    prompt, system=self._TABLE_SYSTEM
                )
                description = description.strip()
                results[table.table_id] = description
                stats.generated += 1

                # Queue for expert review
                self._review_queue.append(ReviewableDescription(
                    entity_id=table.table_id,
                    entity_type="table",
                    generated_description=description,
                ))

                # Persist if graph_store available
                if self._graph_store is not None:
                    table.description = description
                    await self._graph_store.upsert_table(table)

                logger.info(
                    "table_description_generated",
                    table_id=table.table_id,
                    description_length=len(description),
                )

            except Exception as exc:
                stats.failed += 1
                stats.errors.append(f"{table.table_id}: {exc}")
                logger.error(
                    "table_description_failed",
                    table_id=table.table_id,
                    error=str(exc),
                )

        logger.info(
            "table_descriptions_complete",
            generated=stats.generated,
            skipped=stats.skipped,
            failed=stats.failed,
        )
        return results

    async def generate_column_descriptions(
        self,
        table_id: str,
        columns: list[ColumnInfo],
        *,
        table_name: str = "",
        force: bool = False,
    ) -> dict[str, str]:
        """Generate NL descriptions for columns of a single table.

        Args:
            table_id: Parent table identifier.
            columns: Columns to describe.
            table_name: Human-readable table name for prompt context.
            force: If True, regenerate even if description exists.

        Returns:
            Mapping of column_id to generated description.
        """
        results: dict[str, str] = {}
        stats = DescriptionResult()

        # Build column context string for the prompt
        col_context = ", ".join(
            f"{c.column_name} ({c.data_type})" for c in columns
        )

        for col in columns:
            col_id = col.column_id or f"{table_id}.{col.column_name}"

            if col.description and not force:
                stats.skipped += 1
                continue

            if self._is_human_reviewed(col_id):
                stats.skipped += 1
                continue

            prompt = (
                f"Table: {table_name or table_id}\n"
                f"All columns: {col_context}\n"
                f"Target column: {col.column_name}\n"
                f"Data type: {col.data_type}\n"
                f"Is primary key: {col.is_pk}\n"
                f"Is foreign key: {col.is_fk}\n"
            )
            if col.fk_ref:
                prompt += f"References: {col.fk_ref}\n"
            prompt += "\nDescribe this column:"

            try:
                description = await self._llm.complete(
                    prompt, system=self._COLUMN_SYSTEM
                )
                description = description.strip()
                results[col_id] = description
                stats.generated += 1

                self._review_queue.append(ReviewableDescription(
                    entity_id=col_id,
                    entity_type="column",
                    generated_description=description,
                ))

                logger.info(
                    "column_description_generated",
                    column_id=col_id,
                    description_length=len(description),
                )

            except Exception as exc:
                stats.failed += 1
                stats.errors.append(f"{col_id}: {exc}")
                logger.error(
                    "column_description_failed",
                    column_id=col_id,
                    error=str(exc),
                )

        logger.info(
            "column_descriptions_complete",
            table_id=table_id,
            generated=stats.generated,
            skipped=stats.skipped,
            failed=stats.failed,
        )
        return results

    # ---- Expert review workflow ----

    def get_pending_reviews(self) -> list[ReviewableDescription]:
        """Return descriptions awaiting expert review."""
        return [r for r in self._review_queue if not r.reviewed]

    async def approve_description(
        self,
        entity_id: str,
        reviewer: str,
        corrected: str | None = None,
    ) -> None:
        """Approve (optionally correct) a generated description.

        If corrected is provided, the corrected text replaces the generated
        description.  The original is preserved in generated_description.
        """
        for item in self._review_queue:
            if item.entity_id == entity_id and not item.reviewed:
                item.reviewed = True
                item.reviewer = reviewer
                if corrected is not None:
                    item.corrected_description = corrected
                else:
                    item.corrected_description = item.generated_description

                # Persist corrected description
                if self._graph_store is not None:
                    final = item.corrected_description
                    if item.entity_type == "table":
                        existing_tables = await self._graph_store.get_tables("")
                        for t in existing_tables:
                            if t.table_id == entity_id:
                                t.description = final
                                await self._graph_store.upsert_table(t)
                                break

                logger.info(
                    "description_approved",
                    entity_id=entity_id,
                    reviewer=reviewer,
                    was_corrected=corrected is not None,
                )
                return

        raise ValueError(f"No pending review found for entity: {entity_id}")

    # ---- Private helpers ----

    def _is_human_reviewed(self, entity_id: str) -> bool:
        """Check if this entity has an approved human review."""
        return any(
            r.entity_id == entity_id and r.reviewed
            for r in self._review_queue
        )

    @staticmethod
    def _build_table_prompt(table: TableInfo) -> str:
        """Build the LLM prompt for a table description."""
        col_lines = []
        for c in table.columns:
            parts = [f"  - {c.column_name} ({c.data_type})"]
            if c.is_pk:
                parts.append("[PK]")
            if c.is_fk and c.fk_ref:
                parts.append(f"[FK -> {c.fk_ref}]")
            col_lines.append(" ".join(parts))

        prompt = (
            f"Table: {table.schema_name}.{table.table_name}\n"
            f"Database: {table.database_name}\n"
        )
        if table.row_count is not None:
            prompt += f"Approximate rows: {table.row_count:,}\n"
        if table.domain:
            prompt += f"Domain: {table.domain.value}\n"
        prompt += f"Columns:\n" + "\n".join(col_lines) + "\n"
        prompt += "\nDescribe this table:"
        return prompt
