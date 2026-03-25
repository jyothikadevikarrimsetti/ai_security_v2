"""CC-005 Provider Fallback Chain — resilient LLM generation with automatic failover.

On primary provider failure (timeout, rate limit, error):
  - Auto-fallback to secondary provider
  - Configurable chain (e.g. Claude -> GPT-4 -> local Ollama)
  - Exponential backoff with jitter between retries
  - Providers tried in priority order (lowest priority number first)
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Any

from xensql.app.services.context_construction.llm_provider import (
    LLMProviderError,
    LLMProviderRegistry,
    LLMResponse,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class FallbackConfig:
    """Configuration for the fallback chain behaviour."""

    max_retries_per_provider: int = 2
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 10.0
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.25  # 0.0 - 1.0
    timeout_seconds: float = 120.0  # total timeout across all providers


@dataclass
class FallbackAttempt:
    """Record of a single attempt within the fallback chain."""

    provider: str
    attempt: int
    success: bool
    error: str = ""
    latency_ms: float = 0.0


@dataclass
class FallbackResult:
    """Result of the fallback chain execution."""

    response: LLMResponse | None
    attempts: list[FallbackAttempt] = field(default_factory=list)
    total_latency_ms: float = 0.0
    providers_tried: int = 0

    @property
    def success(self) -> bool:
        return self.response is not None


# ---------------------------------------------------------------------------
# ProviderFallbackChain
# ---------------------------------------------------------------------------


class ProviderFallbackChain:
    """Resilient LLM generation with automatic provider failover.

    Tries providers in priority order. On failure, applies exponential
    backoff with jitter before retrying or moving to the next provider.

    Usage::

        registry = LLMProviderRegistry()
        registry.register(LLMProviderConfig(
            name="claude", type="anthropic", priority=1, ...
        ))
        registry.register(LLMProviderConfig(
            name="gpt4", type="openai", priority=2, ...
        ))
        registry.register(LLMProviderConfig(
            name="local", type="ollama", priority=10, ...
        ))

        chain = ProviderFallbackChain(registry)
        response = await chain.generate(messages)
    """

    def __init__(
        self,
        registry: LLMProviderRegistry,
        config: FallbackConfig | None = None,
    ) -> None:
        self._registry = registry
        self._config = config or FallbackConfig()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def generate(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
        *,
        provider_override: str | None = None,
    ) -> LLMResponse:
        """Generate a completion, falling back through providers on failure.

        Parameters
        ----------
        messages:
            Chat messages in OpenAI format.
        config:
            Optional per-request overrides passed to each provider.
        provider_override:
            If set, skip fallback and use only this provider.

        Returns
        -------
        LLMResponse from the first provider that succeeds.

        Raises
        ------
        LLMProviderError
            If all providers in the chain fail.
        """
        # Direct override — no fallback
        if provider_override:
            return await self._try_provider(
                provider_override, messages, config, attempt=1
            )

        providers = self._registry.available_providers
        if not providers:
            raise LLMProviderError("No LLM providers registered in the registry")

        last_error: Exception | None = None
        all_attempts: list[FallbackAttempt] = []
        attempt_global = 0

        for provider in providers:
            for retry in range(1, self._config.max_retries_per_provider + 1):
                attempt_global += 1
                try:
                    response = await self._try_provider(
                        provider.name, messages, config, attempt=attempt_global
                    )
                    all_attempts.append(
                        FallbackAttempt(
                            provider=provider.name,
                            attempt=retry,
                            success=True,
                            latency_ms=response.latency_ms,
                        )
                    )
                    response.attempt = attempt_global
                    if attempt_global > 1:
                        logger.info(
                            "fallback_chain_succeeded: provider=%s attempt=%d",
                            provider.name,
                            attempt_global,
                        )
                    return response

                except LLMProviderError as exc:
                    last_error = exc
                    all_attempts.append(
                        FallbackAttempt(
                            provider=provider.name,
                            attempt=retry,
                            success=False,
                            error=str(exc),
                        )
                    )
                    logger.warning(
                        "provider_attempt_failed: provider=%s retry=%d/%d error=%s",
                        provider.name,
                        retry,
                        self._config.max_retries_per_provider,
                        str(exc),
                    )

                    # Backoff before next retry (but not after last retry
                    # before switching providers)
                    if retry < self._config.max_retries_per_provider:
                        backoff = self._compute_backoff(retry)
                        logger.info(
                            "backoff_before_retry: %.2fs", backoff
                        )
                        await asyncio.sleep(backoff)

            # Log provider exhaustion before moving to next
            logger.warning(
                "provider_exhausted: provider=%s, moving to next",
                provider.name,
            )

        raise LLMProviderError(
            f"All {len(providers)} provider(s) failed after "
            f"{attempt_global} total attempt(s). "
            f"Last error: {last_error}"
        )

    async def generate_with_details(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> FallbackResult:
        """Like ``generate`` but returns detailed attempt information.

        Does not raise on failure — check ``result.success`` instead.
        """
        import time

        start = time.monotonic()
        attempts: list[FallbackAttempt] = []

        providers = self._registry.available_providers
        if not providers:
            return FallbackResult(response=None, providers_tried=0)

        attempt_global = 0
        for provider in providers:
            for retry in range(1, self._config.max_retries_per_provider + 1):
                attempt_global += 1
                try:
                    response = await self._try_provider(
                        provider.name, messages, config, attempt=attempt_global
                    )
                    attempts.append(
                        FallbackAttempt(
                            provider=provider.name,
                            attempt=retry,
                            success=True,
                            latency_ms=response.latency_ms,
                        )
                    )
                    response.attempt = attempt_global
                    total_ms = (time.monotonic() - start) * 1000
                    return FallbackResult(
                        response=response,
                        attempts=attempts,
                        total_latency_ms=total_ms,
                        providers_tried=len(
                            {a.provider for a in attempts}
                        ),
                    )
                except LLMProviderError as exc:
                    attempts.append(
                        FallbackAttempt(
                            provider=provider.name,
                            attempt=retry,
                            success=False,
                            error=str(exc),
                        )
                    )
                    if retry < self._config.max_retries_per_provider:
                        backoff = self._compute_backoff(retry)
                        await asyncio.sleep(backoff)

        total_ms = (time.monotonic() - start) * 1000
        return FallbackResult(
            response=None,
            attempts=attempts,
            total_latency_ms=total_ms,
            providers_tried=len({a.provider for a in attempts}),
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _try_provider(
        self,
        provider_name: str,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None,
        attempt: int,
    ) -> LLMResponse:
        """Call a single provider through the registry."""
        return await self._registry.generate(provider_name, messages, config)

    def _compute_backoff(self, retry: int) -> float:
        """Compute exponential backoff with jitter.

        backoff = min(base * multiplier^(retry-1), max) * (1 + random jitter)
        """
        base = self._config.base_backoff_seconds
        multiplier = self._config.backoff_multiplier
        cap = self._config.max_backoff_seconds
        jitter = self._config.jitter_factor

        delay = min(base * (multiplier ** (retry - 1)), cap)
        # Add jitter: +/- jitter_factor of the delay
        jitter_amount = delay * jitter * (2 * random.random() - 1)
        return max(0.0, delay + jitter_amount)
