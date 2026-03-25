"""Circuit Breaker -- per-database fault tolerance.

EXECUTION security zone: prevents cascading failures by tracking error
rates per database and temporarily blocking requests to unhealthy targets.

State machine:
  CLOSED    -- normal operation; errors counted in a rolling 60s window.
  OPEN      -- all requests rejected; entered when error rate >= 50%
               with at least 5 requests in the window.
  HALF_OPEN -- one probe request allowed after 30s cooldown.
               Success -> CLOSED, failure -> OPEN.

Thread-safe: all state mutations are guarded by a threading Lock so the
breaker can be shared across async tasks safely.
"""

from __future__ import annotations

import time
from collections import deque
from enum import Enum
from threading import Lock
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# State enum
# ---------------------------------------------------------------------------


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Thread-safe per-database circuit breaker.

    Args:
        database_id: Unique identifier for the database this breaker guards.
        error_threshold: Fraction of errors (0.0-1.0) that triggers OPEN.
        cooldown_seconds: How long OPEN lasts before transitioning to HALF_OPEN.
        window_seconds: Rolling window for counting requests.
        min_requests: Minimum requests in the window before threshold applies.
    """

    def __init__(
        self,
        database_id: str,
        error_threshold: float = 0.5,
        cooldown_seconds: int = 30,
        window_seconds: int = 60,
        min_requests: int = 5,
    ) -> None:
        self.database_id = database_id
        self.error_threshold = error_threshold
        self.cooldown_seconds = cooldown_seconds
        self.window_seconds = window_seconds
        self.min_requests = min_requests

        self._state = CircuitState.CLOSED
        self._open_at: float | None = None
        # Rolling window: deque of (timestamp, is_error)
        self._request_window: deque[tuple[float, bool]] = deque()
        self._probe_in_flight = False
        self._lock = Lock()

    # -- Public API ---------------------------------------------------------

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state (may trigger OPEN -> HALF_OPEN)."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    def allow_request(self) -> bool:
        """Check whether a request should be allowed through.

        Returns:
            True if the request is allowed, False if it should be rejected.

        In HALF_OPEN state, only one probe request is allowed at a time.
        """
        with self._lock:
            self._maybe_transition_to_half_open()

            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.OPEN:
                return False

            # HALF_OPEN -- allow one probe
            if self._state == CircuitState.HALF_OPEN:
                if self._probe_in_flight:
                    return False  # Only one probe at a time
                self._probe_in_flight = True
                return True

            return False

    def record_success(self) -> None:
        """Record a successful request. Transitions HALF_OPEN -> CLOSED."""
        with self._lock:
            now = time.monotonic()
            self._request_window.append((now, False))
            self._prune_window()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._probe_in_flight = False
                logger.info(
                    "circuit_breaker_closed",
                    database=self.database_id,
                    reason="probe_succeeded",
                )

    def record_failure(self) -> None:
        """Record a failed request. May trigger CLOSED -> OPEN or HALF_OPEN -> OPEN."""
        with self._lock:
            now = time.monotonic()
            self._request_window.append((now, True))
            self._prune_window()

            if self._state == CircuitState.HALF_OPEN:
                # Probe failed -- go back to OPEN
                self._state = CircuitState.OPEN
                self._open_at = now
                self._probe_in_flight = False
                logger.warning(
                    "circuit_breaker_open",
                    database=self.database_id,
                    reason="probe_failed",
                )
                return

            if self._state == CircuitState.CLOSED:
                total = len(self._request_window)
                if total >= self.min_requests:
                    errors = sum(1 for _, is_err in self._request_window if is_err)
                    rate = errors / total
                    if rate >= self.error_threshold:
                        self._state = CircuitState.OPEN
                        self._open_at = now
                        logger.warning(
                            "circuit_breaker_open",
                            database=self.database_id,
                            error_rate=f"{rate:.2%}",
                            total_requests=total,
                        )

    def get_status(self) -> dict[str, Any]:
        """Return a status snapshot for monitoring."""
        with self._lock:
            self._maybe_transition_to_half_open()
            self._prune_window()
            total = len(self._request_window)
            errors = sum(1 for _, is_err in self._request_window if is_err)
            return {
                "database": self.database_id,
                "state": self._state.value,
                "error_count": errors,
                "total_requests": total,
                "error_rate": errors / total if total > 0 else 0.0,
                "cooldown_remaining_s": self._cooldown_remaining(),
            }

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED (for ops tooling)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._open_at = None
            self._probe_in_flight = False
            self._request_window.clear()
            logger.info(
                "circuit_breaker_manual_reset",
                database=self.database_id,
            )

    # -- Internal -----------------------------------------------------------

    def _maybe_transition_to_half_open(self) -> None:
        """Transition OPEN -> HALF_OPEN after cooldown. Must hold lock."""
        if (
            self._state == CircuitState.OPEN
            and self._open_at is not None
            and time.monotonic() - self._open_at >= self.cooldown_seconds
            and not self._probe_in_flight
        ):
            self._state = CircuitState.HALF_OPEN
            logger.info(
                "circuit_breaker_half_open",
                database=self.database_id,
            )

    def _prune_window(self) -> None:
        """Remove entries older than window_seconds. Must hold lock."""
        cutoff = time.monotonic() - self.window_seconds
        while self._request_window and self._request_window[0][0] < cutoff:
            self._request_window.popleft()

    def _cooldown_remaining(self) -> float:
        """Seconds remaining in cooldown. Must hold lock. Returns 0 if not OPEN."""
        if self._state != CircuitState.OPEN or self._open_at is None:
            return 0.0
        elapsed = time.monotonic() - self._open_at
        remaining = self.cooldown_seconds - elapsed
        return max(0.0, remaining)


# ---------------------------------------------------------------------------
# CircuitBreakerRegistry -- manages per-database breakers
# ---------------------------------------------------------------------------


class CircuitBreakerRegistry:
    """Registry of per-database circuit breakers.

    Breakers are lazily created on first access. Default parameters
    can be overridden at registry construction time.
    """

    def __init__(
        self,
        error_threshold: float = 0.5,
        cooldown_seconds: int = 30,
        window_seconds: int = 60,
        min_requests: int = 5,
    ) -> None:
        self._error_threshold = error_threshold
        self._cooldown_seconds = cooldown_seconds
        self._window_seconds = window_seconds
        self._min_requests = min_requests
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = Lock()

    def get(self, database_id: str) -> CircuitBreaker:
        """Get or create a circuit breaker for the given database."""
        if database_id not in self._breakers:
            with self._lock:
                if database_id not in self._breakers:
                    self._breakers[database_id] = CircuitBreaker(
                        database_id=database_id,
                        error_threshold=self._error_threshold,
                        cooldown_seconds=self._cooldown_seconds,
                        window_seconds=self._window_seconds,
                        min_requests=self._min_requests,
                    )
        return self._breakers[database_id]

    def all_statuses(self) -> list[dict[str, Any]]:
        """Return status snapshots for all known breakers."""
        return [cb.get_status() for cb in self._breakers.values()]

    def reset_all(self) -> None:
        """Reset all breakers to CLOSED. For ops tooling only."""
        for cb in self._breakers.values():
            cb.reset()

    @property
    def database_ids(self) -> list[str]:
        """List of all tracked database identifiers."""
        return list(self._breakers.keys())
