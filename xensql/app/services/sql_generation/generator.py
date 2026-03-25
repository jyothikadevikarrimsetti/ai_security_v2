"""SG-001: SQL Generator -- sends assembled prompt to configured LLM.

Calls Azure OpenAI or Anthropic Claude with retry, exponential backoff
(0.5s, 1s, 2s) plus jitter, model fallback on retry, and timeout
enforcement.  Returns raw LLM output -- no validation or execution.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Backoff schedule: attempt 1 -> 0.5s, attempt 2 -> 1.0s, attempt 3 -> 2.0s
_BACKOFF_BASE = 0.5
_JITTER_MAX = 0.2


@dataclass(frozen=True)
class GenerationResult:
    """Output of a single SQL generation call."""

    sql: str
    tokens_used: int
    attempts: int
    provider_used: str
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0


@dataclass(frozen=True)
class ProviderConfig:
    """LLM provider configuration for a generation request."""

    provider: str = "azure_openai"  # "azure_openai" | "anthropic"
    primary_model: str = ""
    fallback_model: str = ""
    max_retries: int = 2
    timeout_seconds: float = 30.0
    temperature: float = 0.0
    max_tokens: int = 2048

    # Azure OpenAI
    azure_endpoint: str = ""
    azure_api_key: str = ""
    azure_api_version: str = "2024-02-15-preview"

    # Anthropic
    anthropic_api_key: str = ""


class GenerationError(Exception):
    """Raised when all LLM attempts fail."""


class SQLGenerator:
    """Sends assembled prompt to the configured LLM and returns raw output.

    Handles retries with exponential backoff + jitter and model fallback.
    Does NOT validate, sanitise, or execute the returned SQL.
    """

    async def generate(
        self,
        messages: list[dict[str, str]],
        provider_config: ProviderConfig,
    ) -> GenerationResult:
        """Generate SQL from prompt messages via the configured LLM.

        Args:
            messages: Chat messages, e.g. [{"role": "system", "content": ...},
                      {"role": "user", "content": ...}].
            provider_config: LLM provider settings including model names,
                             credentials, retry policy, and timeout.

        Returns:
            GenerationResult with raw SQL text and metadata.

        Raises:
            GenerationError: When all attempts (including fallback) fail.
        """
        provider = provider_config.provider.lower()
        max_attempts = provider_config.max_retries + 1

        last_error: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            # Use fallback model on retries
            model = (
                provider_config.fallback_model or provider_config.primary_model
                if attempt > 1
                else provider_config.primary_model
            )

            start_ts = time.monotonic()

            try:
                async with asyncio.timeout(provider_config.timeout_seconds):
                    if provider == "azure_openai":
                        text, pt, ct = await self._call_azure_openai(
                            messages, model, provider_config
                        )
                    elif provider == "anthropic":
                        text, pt, ct = await self._call_anthropic(
                            messages, model, provider_config
                        )
                    else:
                        raise GenerationError(
                            f"Unsupported LLM provider: {provider}"
                        )

                latency_ms = (time.monotonic() - start_ts) * 1000
                logger.info(
                    "llm_call_succeeded",
                    provider=provider,
                    model=model,
                    attempt=attempt,
                    latency_ms=round(latency_ms, 1),
                )

                return GenerationResult(
                    sql=text,
                    tokens_used=pt + ct,
                    attempts=attempt,
                    provider_used=provider,
                    model=model,
                    prompt_tokens=pt,
                    completion_tokens=ct,
                    latency_ms=latency_ms,
                )

            except (TimeoutError, asyncio.TimeoutError) as exc:
                last_error = exc
                logger.warning(
                    "llm_timeout",
                    provider=provider,
                    model=model,
                    attempt=attempt,
                    timeout=provider_config.timeout_seconds,
                )
            except GenerationError:
                raise
            except Exception as exc:
                last_error = exc
                err_str = str(exc).lower()
                # Non-retriable auth errors -- fail immediately
                if any(
                    kw in err_str for kw in ("401", "authentication", "api key")
                ):
                    raise GenerationError(
                        f"LLM auth failure: {exc}"
                    ) from exc
                logger.warning(
                    "llm_call_failed",
                    provider=provider,
                    model=model,
                    attempt=attempt,
                    error=str(exc),
                )

            # Exponential backoff + jitter before next attempt
            if attempt < max_attempts:
                backoff = (_BACKOFF_BASE * (2 ** (attempt - 1))) + random.uniform(
                    0, _JITTER_MAX
                )
                await asyncio.sleep(backoff)

        raise GenerationError(
            f"All {max_attempts} LLM attempts failed. Last error: {last_error}"
        )

    # ------------------------------------------------------------------
    # Provider-specific call methods
    # ------------------------------------------------------------------

    @staticmethod
    async def _call_azure_openai(
        messages: list[dict[str, str]],
        deployment: str,
        config: ProviderConfig,
    ) -> tuple[str, int, int]:
        """Call Azure OpenAI. Returns (text, prompt_tokens, completion_tokens)."""
        try:
            from openai import AsyncAzureOpenAI
        except ImportError as exc:
            raise GenerationError("openai package not installed") from exc

        client = AsyncAzureOpenAI(
            azure_endpoint=config.azure_endpoint,
            api_key=config.azure_api_key,
            api_version=config.azure_api_version,
        )
        response = await client.chat.completions.create(
            model=deployment,
            messages=messages,  # type: ignore[arg-type]
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
        text = response.choices[0].message.content or ""
        pt = response.usage.prompt_tokens if response.usage else 0
        ct = response.usage.completion_tokens if response.usage else 0
        return text, pt, ct

    @staticmethod
    async def _call_anthropic(
        messages: list[dict[str, str]],
        model: str,
        config: ProviderConfig,
    ) -> tuple[str, int, int]:
        """Call Anthropic Claude. Returns (text, input_tokens, output_tokens)."""
        try:
            import anthropic
        except ImportError as exc:
            raise GenerationError("anthropic package not installed") from exc

        # Separate system prompt from user messages
        system_prompt = ""
        user_messages: list[dict[str, str]] = []
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                user_messages.append(msg)

        client = anthropic.AsyncAnthropic(api_key=config.anthropic_api_key)
        response = await client.messages.create(
            model=model,
            system=system_prompt,
            messages=user_messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
        text = response.content[0].text if response.content else ""
        pt = response.usage.input_tokens
        ct = response.usage.output_tokens
        return text, pt, ct
