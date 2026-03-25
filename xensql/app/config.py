"""Configuration for XenSQL - NL-to-SQL Pipeline Engine.

All settings are loaded from environment variables with XENSQL_ prefix,
with optional overrides from config/settings.yaml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _load_settings_yaml() -> dict[str, Any]:
    """Load defaults from config/settings.yaml if it exists."""
    yaml_path = _CONFIG_DIR / "settings.yaml"
    if yaml_path.exists():
        with open(yaml_path) as fh:
            data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
    return {}


class Settings(BaseSettings):
    """XenSQL configuration.

    Precedence: env vars (XENSQL_ prefix) > .env file > settings.yaml defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="XENSQL_",
        env_file=("../.env.local", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Service ---------------------------------------------------------------

    service_port: int = 8900
    app_env: str = "development"
    log_level: str = "INFO"

    # -- LLM providers ---------------------------------------------------------

    llm_primary_provider: str = Field(
        default="ollama", description="Primary LLM provider: ollama, vllm, tgi, litellm"
    )
    llm_primary_base_url: str = "http://localhost:11434/v1"
    llm_primary_model: str = "llama3.1:8b"
    llm_primary_api_key: str = ""
    llm_primary_timeout: int = 60

    llm_fallback_provider: str = Field(
        default="litellm", description="Fallback LLM provider"
    )
    llm_fallback_base_url: str = "http://localhost:4000/v1"
    llm_fallback_model: str = "gpt-4o-mini"
    llm_fallback_api_key: str = ""
    llm_fallback_timeout: int = 90

    llm_temperature: float = 0.0
    llm_max_tokens: int = 2048

    # -- Neo4j (knowledge graph) -----------------------------------------------

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"

    # -- Redis (conversation context + caching) --------------------------------

    redis_url: str = "redis://localhost:6379/3"
    redis_max_connections: int = 10
    conversation_max_turns: int = 10
    conversation_ttl_seconds: int = 1800  # 30 minutes

    # -- pgvector (schema embeddings) ------------------------------------------

    pgvector_dsn: str = "postgresql://xensql:xensql@localhost:5432/xensql_vectors"
    pgvector_pool_min: int = 2
    pgvector_pool_max: int = 10
    pgvector_table: str = "schema_embeddings"

    # -- Embedding provider ----------------------------------------------------

    embedding_provider: str = Field(
        default="voyage",
        description="Primary embedding provider: voyage, openai, azure",
    )

    embedding_voyage_api_key: str = ""
    embedding_voyage_model: str = "voyage-3-large"

    embedding_openai_api_key: str = ""
    embedding_openai_model: str = "text-embedding-3-small"

    embedding_azure_api_key: str = ""
    embedding_azure_endpoint: str = ""
    embedding_azure_deployment: str = "text-embedding-ada-002"
    embedding_azure_api_version: str = "2024-02-01"

    embedding_dimensions: int = 1024

    # -- Token budget ----------------------------------------------------------

    token_budget: int = Field(
        default=4096, description="Max tokens for assembled LLM prompt context"
    )

    # -- Retrieval settings ----------------------------------------------------

    retrieval_top_k: int = Field(default=10, ge=1, le=50, description="Top-K candidates for schema retrieval")
    retrieval_strategies: str = Field(
        default="semantic,keyword,graph",
        description="Comma-separated retrieval strategies to use",
    )
    retrieval_rerank_top_n: int = Field(default=5, ge=1, le=25, description="Re-rank candidates down to N")

    # -- Ambiguity detection ---------------------------------------------------

    ambiguity_threshold: float = 0.8

    # -- Confidence scoring weights --------------------------------------------

    confidence_retrieval_weight: float = 0.40
    confidence_intent_weight: float = 0.25
    confidence_generation_weight: float = 0.35

    # -- Derived helpers -------------------------------------------------------

    @property
    def retrieval_strategy_list(self) -> list[str]:
        return [s.strip() for s in self.retrieval_strategies.split(",") if s.strip()]


# -- Singleton -----------------------------------------------------------------

_settings: Settings | None = None
_yaml_applied = False


def get_settings() -> Settings:
    """Return the cached Settings singleton, applying YAML defaults on first call."""
    global _settings, _yaml_applied

    if _settings is None:
        _settings = Settings()

    if not _yaml_applied:
        _yaml_applied = True
        yaml_defaults = _load_settings_yaml()
        for key, value in yaml_defaults.items():
            # Only apply YAML value if the field was not set via env/dotenv
            if hasattr(_settings, key):
                current = getattr(_settings, key)
                field_info = _settings.model_fields.get(key)
                if field_info and current == field_info.default:
                    object.__setattr__(_settings, key, value)

    return _settings
