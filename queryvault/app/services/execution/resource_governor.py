"""Resource Governor -- enforces execution resource limits.

EXECUTION security zone: prevents runaway queries from consuming unbounded
resources. Enforces timeout, row count, memory, result size, and concurrency
limits. Supports elevated limits during Break-the-Glass (BTG) emergencies.

Default limits:
  - Query timeout:         30s  (BTG: 60s)
  - Row limit:             10,000  (BTG: 50,000)
  - Max query memory:      100MB
  - Max result size:       50MB
  - Max concurrent/user:   5
  - Max concurrent/total:  50
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Approximate bytes per cell for memory estimation
_BYTES_PER_CELL_ESTIMATE = 64


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ResourceLimitExceeded(Exception):
    """Raised when a resource limit is breached during execution."""

    def __init__(self, limit_type: str, detail: str = "") -> None:
        self.limit_type = limit_type
        self.detail = detail
        super().__init__(f"{limit_type}: {detail}")


# ---------------------------------------------------------------------------
# ResourceLimits dataclass
# ---------------------------------------------------------------------------


@dataclass
class ResourceLimits:
    """Configurable resource limits for a single query execution.

    All fields have sensible defaults. BTG (Break-the-Glass) fields
    are used when emergency access is active.
    """

    # Normal limits
    timeout_seconds: int = 30
    max_rows: int = 10_000
    max_memory_mb: int = 100
    max_result_size_mb: int = 50
    max_concurrent_per_user: int = 5
    max_concurrent_total: int = 50

    # BTG elevated limits
    btg_active: bool = False
    btg_timeout_seconds: int = 60
    btg_max_rows: int = 50_000
    btg_max_memory_mb: int = 250

    @property
    def effective_timeout(self) -> int:
        """Timeout in seconds, accounting for BTG elevation."""
        return self.btg_timeout_seconds if self.btg_active else self.timeout_seconds

    @property
    def effective_max_rows(self) -> int:
        """Row limit, accounting for BTG elevation."""
        return self.btg_max_rows if self.btg_active else self.max_rows

    @property
    def effective_max_memory_mb(self) -> int:
        """Memory limit in MB, accounting for BTG elevation."""
        return self.btg_max_memory_mb if self.btg_active else self.max_memory_mb


# ---------------------------------------------------------------------------
# Concurrency tracker
# ---------------------------------------------------------------------------


class _ConcurrencyTracker:
    """Tracks per-user and global concurrent query counts."""

    def __init__(self) -> None:
        self._user_counts: dict[str, int] = {}
        self._total: int = 0
        self._lock = asyncio.Lock()

    async def acquire(
        self, user_id: str, max_per_user: int, max_total: int,
    ) -> None:
        """Acquire a concurrency slot. Raises ResourceLimitExceeded if full."""
        async with self._lock:
            if self._total >= max_total:
                raise ResourceLimitExceeded(
                    "CONCURRENCY_TOTAL_EXCEEDED",
                    f"System concurrency limit of {max_total} reached",
                )
            user_count = self._user_counts.get(user_id, 0)
            if user_count >= max_per_user:
                raise ResourceLimitExceeded(
                    "CONCURRENCY_USER_EXCEEDED",
                    f"User concurrency limit of {max_per_user} reached for '{user_id}'",
                )
            self._user_counts[user_id] = user_count + 1
            self._total += 1

    async def release(self, user_id: str) -> None:
        """Release a concurrency slot."""
        async with self._lock:
            current = self._user_counts.get(user_id, 0)
            if current > 0:
                self._user_counts[user_id] = current - 1
            if self._total > 0:
                self._total -= 1

    @property
    def total_active(self) -> int:
        return self._total


# ---------------------------------------------------------------------------
# ResourceGovernor
# ---------------------------------------------------------------------------


class ResourceGovernor:
    """Enforces resource limits during query execution.

    Usage:
        governor = ResourceGovernor()
        governed = await governor.enforce(execution_coro, limits, user_id)

    The governor wraps the execution coroutine with timeout enforcement,
    and validates row count, memory, and result size of the returned data.
    Concurrency limits are enforced before execution begins.
    """

    def __init__(self) -> None:
        self._concurrency = _ConcurrencyTracker()
        self._start_time: float | None = None
        self._row_count: int = 0
        self._estimated_memory_bytes: int = 0

    # -- Core enforcement ---------------------------------------------------

    async def enforce(
        self,
        execution: Any,
        limits: ResourceLimits,
        user_id: str = "anonymous",
    ) -> Any:
        """Execute with resource governance.

        Args:
            execution: An awaitable that returns an ExecutionResult.
            limits: ResourceLimits defining the bounds.
            user_id: User identifier for per-user concurrency tracking.

        Returns:
            The ExecutionResult from the awaitable, after limit checks.

        Raises:
            ResourceLimitExceeded: If any resource limit is breached.
            asyncio.TimeoutError: If execution exceeds the timeout.
        """
        # Concurrency gate
        await self._concurrency.acquire(
            user_id,
            limits.max_concurrent_per_user,
            limits.max_concurrent_total,
        )

        self._start_time = time.monotonic()
        self._row_count = 0
        self._estimated_memory_bytes = 0

        try:
            # Timeout enforcement
            effective_timeout = limits.effective_timeout
            result = await asyncio.wait_for(
                execution,
                timeout=effective_timeout,
            )

            # Post-execution limit checks
            self._validate_result(result, limits)

            return result

        except asyncio.TimeoutError:
            raise ResourceLimitExceeded(
                "QUERY_TIMEOUT",
                f"Query exceeded {limits.effective_timeout}s timeout",
            )
        finally:
            await self._concurrency.release(user_id)

    def _validate_result(self, result: Any, limits: ResourceLimits) -> None:
        """Check row count, memory, and result size against limits."""
        max_rows = limits.effective_max_rows
        max_memory_mb = limits.effective_max_memory_mb

        # Row count check
        rows = getattr(result, "rows", [])
        row_count = len(rows)
        if row_count > max_rows:
            raise ResourceLimitExceeded(
                "ROW_LIMIT_EXCEEDED",
                f"Result has {row_count} rows, exceeding limit of {max_rows}",
            )

        # Memory estimation
        num_columns = len(getattr(result, "columns", []))
        estimated_bytes = row_count * max(num_columns, 1) * _BYTES_PER_CELL_ESTIMATE
        estimated_mb = estimated_bytes / (1024 * 1024)
        if estimated_mb > max_memory_mb:
            raise ResourceLimitExceeded(
                "MEMORY_EXCEEDED",
                f"Estimated memory {estimated_mb:.1f}MB exceeds "
                f"limit of {max_memory_mb}MB",
            )

        # Result size estimation (rough -- sum string lengths of all cells)
        result_size_bytes = 0
        for row in rows:
            for cell in row:
                if cell is not None:
                    result_size_bytes += len(str(cell))
        result_size_mb = result_size_bytes / (1024 * 1024)
        if result_size_mb > limits.max_result_size_mb:
            raise ResourceLimitExceeded(
                "RESULT_SIZE_EXCEEDED",
                f"Result size {result_size_mb:.1f}MB exceeds "
                f"limit of {limits.max_result_size_mb}MB",
            )

    # -- Streaming row-by-row checks (for cursor-based execution) -----------

    def start(self) -> None:
        """Mark the start of execution for elapsed-time tracking."""
        self._start_time = time.monotonic()
        self._row_count = 0
        self._estimated_memory_bytes = 0

    def elapsed_seconds(self) -> float:
        """Seconds elapsed since start()."""
        if self._start_time is None:
            return 0.0
        return time.monotonic() - self._start_time

    def check_row(self, num_columns: int, limits: ResourceLimits) -> None:
        """Call per row during streaming. Raises on limit breach."""
        # Timeout
        if self._start_time is not None:
            elapsed = time.monotonic() - self._start_time
            if elapsed > limits.effective_timeout:
                raise ResourceLimitExceeded(
                    "QUERY_TIMEOUT",
                    f"Query exceeded {limits.effective_timeout}s timeout "
                    f"(elapsed: {elapsed:.1f}s)",
                )

        # Row count
        self._row_count += 1
        if self._row_count > limits.effective_max_rows:
            raise ResourceLimitExceeded(
                "ROW_LIMIT_EXCEEDED",
                f"Row limit of {limits.effective_max_rows} exceeded",
            )

        # Memory
        self._estimated_memory_bytes += num_columns * _BYTES_PER_CELL_ESTIMATE
        mem_mb = self._estimated_memory_bytes / (1024 * 1024)
        if mem_mb > limits.effective_max_memory_mb:
            raise ResourceLimitExceeded(
                "MEMORY_EXCEEDED",
                f"Memory cap of {limits.effective_max_memory_mb}MB exceeded "
                f"(estimated: {mem_mb:.1f}MB)",
            )

    @property
    def row_count(self) -> int:
        return self._row_count

    @property
    def memory_mb(self) -> float:
        return self._estimated_memory_bytes / (1024 * 1024)

    def finalize(self) -> dict[str, Any]:
        """Return summary metrics after execution completes."""
        return {
            "rows_fetched": self._row_count,
            "estimated_memory_mb": round(self.memory_mb, 2),
            "elapsed_seconds": round(self.elapsed_seconds(), 3),
            "concurrent_active": self._concurrency.total_active,
        }
