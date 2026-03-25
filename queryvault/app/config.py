"""Configuration for QueryVault AI Security Framework.

Loads all settings from environment variables with the QV_ prefix.
Uses pydantic-settings for type-safe configuration with validation.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """QueryVault configuration — all settings load from QV_* env vars."""

    model_config = SettingsConfigDict(
        env_prefix="QV_",
        env_file=(".env.local", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    app_port: int = 8950
    app_env: str = "development"
    log_level: str = "INFO"

    # ── XenSQL Pipeline (downstream NL-to-SQL engine) ────────
    xensql_base_url: str = "http://localhost:8900"
    xensql_timeout: int = 45

    # ── Neo4j (policy graph) ─────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    neo4j_database: str = "neo4j"

    # ── Redis (behavioral fingerprints, probing detection) ───
    redis_url: str = "redis://localhost:6379/4"
    redis_max_connections: int = 20

    # ── PostgreSQL (audit store) ─────────────────────────────
    postgres_dsn: str = "postgresql://queryvault:queryvault@localhost:5432/queryvault"
    postgres_pool_min: int = 2
    postgres_pool_max: int = 10

    # ── JWT / Authentication ─────────────────────────────────
    jwt_issuer: str = "queryvault"
    jwt_audience: str = "queryvault-api"
    jwt_jwks_uri: str = ""
    jwt_algorithm: str = "RS256"
    jwt_secret_fallback: str = "dev-jwt-secret-change-in-production-min-32-chars"

    # ── HMAC / Service Authentication ────────────────────────
    hmac_secret: str = "dev-hmac-secret-change-in-production-min-32-chars-xx"
    service_id: str = "queryvault"
    service_role: str = "security_gateway"
    allowed_service_ids: str = "frontend,orchestrator,xensql"

    # ── Injection / Probing Detection ────────────────────────
    injection_threshold: float = 0.6
    attack_patterns_file: str = "data/attack_patterns.json"
    probing_window_seconds: int = 300
    probing_threshold: int = 5

    # ── Behavioral Fingerprinting ────────────────────────────
    fingerprint_ttl_days: int = 30
    behavioral_anomaly_threshold: float = 0.7

    # ── Query Execution (Zone 4) ─────────────────────────────
    execution_enabled: bool = True
    execution_timeout_ms: int = 15000
    execution_row_limit: int = 1000

    # ── Circuit Breaker ──────────────────────────────────────
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: int = 30
    circuit_breaker_half_open_max_calls: int = 3

    # ── Alerting Channels ────────────────────────────────────
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""
    alert_email_smtp_host: str = ""
    alert_email_smtp_port: int = 587
    alert_email_from: str = ""
    alert_email_to: str = ""
    alert_email_username: str = ""
    alert_email_password: str = ""

    # ── Compliance ───────────────────────────────────────────
    compliance_standards: str = "HIPAA_PRIVACY,HIPAA_SECURITY,SOX,GDPR,EU_AI_ACT,ISO_42001,42_CFR_PART_2"
    compliance_report_timeout: int = 30

    # ── Audit ────────────────────────────────────────────────
    audit_retention_days: int = 2555
    audit_batch_size: int = 100
    audit_flush_interval_seconds: int = 5

    # ── Derived helpers ──────────────────────────────────────

    @property
    def allowed_service_id_set(self) -> set[str]:
        return {s.strip() for s in self.allowed_service_ids.split(",") if s.strip()}

    @property
    def compliance_standard_list(self) -> list[str]:
        return [s.strip() for s in self.compliance_standards.split(",") if s.strip()]


# ── Singleton accessor ───────────────────────────────────────

_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the cached Settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
