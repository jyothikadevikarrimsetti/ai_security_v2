"""Schema models consumed by XenSQL NL-to-SQL Pipeline Engine.

These represent the pre-filtered schema that XenSQL receives from
QueryVault. XenSQL never fetches or filters schema itself.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from xensql.app.models.enums import DomainType


class ForeignKey(BaseModel):
    """A foreign-key relationship between two tables."""

    model_config = ConfigDict(frozen=True)

    from_table: str
    from_column: str
    to_table: str
    to_column: str


class ColumnInfo(BaseModel):
    """Metadata for a single column within a table."""

    model_config = ConfigDict(frozen=True)

    column_id: str = ""
    column_name: str
    data_type: str = ""
    description: str = ""
    is_pk: bool = False
    is_fk: bool = False
    fk_ref: str | None = Field(
        default=None, description="FK reference in 'schema.table.column' format"
    )


class TableInfo(BaseModel):
    """Metadata for a single table in the filtered schema."""

    model_config = ConfigDict()

    table_id: str = Field(
        ..., description="Fully-qualified table identifier"
    )
    database_name: str = ""
    schema_name: str = ""
    table_name: str
    description: str = ""
    domain: DomainType | None = None
    columns: list[ColumnInfo] = Field(default_factory=list)
    row_count: int | None = Field(
        default=None, description="Approximate row count for query planning hints"
    )


class SchemaContext(BaseModel):
    """Complete schema context assembled for the LLM prompt.

    This is the internal representation XenSQL builds from the
    filtered_schema dict received in PipelineRequest.
    """

    model_config = ConfigDict()

    tables: list[TableInfo] = Field(default_factory=list)
    join_paths: list[ForeignKey] = Field(default_factory=list)
    token_count: int = Field(
        default=0, description="Estimated token count of the serialised schema"
    )
