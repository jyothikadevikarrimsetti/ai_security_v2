"""Execution security zone -- resource-bounded, read-only SQL execution.

Public API:
  QueryExecutor      -- real database execution (PostgreSQL / MySQL)
  MockExecutor       -- synthetic data for dev/test
  ResourceGovernor   -- enforce timeout, row, memory, concurrency limits
  ResourceLimits     -- configurable limit parameters
  CircuitBreaker     -- per-database fault tolerance
  CircuitBreakerRegistry -- manage breakers across databases
  ResultSanitizer    -- last-line-of-defense PII scanning
  ContextMinimizer   -- reduce schema context for LLM
"""

from queryvault.app.services.execution.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitState,
)
from queryvault.app.services.execution.context_minimizer import (
    ContextMinimizer,
)
from queryvault.app.services.execution.executor import (
    ColumnInfo,
    DatabaseConfig,
    ExecutionResult,
    MockExecutor,
    QueryExecutor,
)
from queryvault.app.services.execution.resource_governor import (
    ResourceGovernor,
    ResourceLimitExceeded,
    ResourceLimits,
)
from queryvault.app.services.execution.result_sanitizer import (
    ResultSanitizer,
    SanitizationEvent,
    SanitizationReport,
)

__all__ = [
    # Executor
    "QueryExecutor",
    "MockExecutor",
    "ExecutionResult",
    "ColumnInfo",
    "DatabaseConfig",
    # Resource Governor
    "ResourceGovernor",
    "ResourceLimits",
    "ResourceLimitExceeded",
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitState",
    # Result Sanitizer
    "ResultSanitizer",
    "SanitizationEvent",
    "SanitizationReport",
    # Context Minimizer
    "ContextMinimizer",
]
