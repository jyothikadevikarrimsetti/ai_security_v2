"""Universal LLM client for OpenAI-compatible APIs.

Supports any LLM backend that exposes an OpenAI-compatible /v1/chat/completions
endpoint, including:
  - Ollama
  - vLLM
  - TGI (Text Generation Inference)
  - LiteLLM

Provides primary + fallback provider failover.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from xensql.app.config import Settings

logger = structlog.get_logger(__name__)


@dataclass
class LLMResponse:
    """Structured response from an LLM generation call."""

    content: str = ""
    model: str = ""
    provider: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    generation_quality: float = 0.7  # Default quality signal
    raw: dict[str, Any] = field(default_factory=dict)


class OpenAICompatClient:
    """Async LLM client for OpenAI-compatible APIs with failover.

    Usage:
        client = OpenAICompatClient(settings)
        await client.connect()
        response = await client.generate(messages, config)
        await client.close()
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._primary_http: httpx.AsyncClient | None = None
        self._fallback_http: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        """Initialize HTTP clients for primary and fallback providers."""
        self._primary_http = httpx.AsyncClient(
            base_url=self._settings.llm_primary_base_url,
            timeout=httpx.Timeout(float(self._settings.llm_primary_timeout)),
        )
        if self._settings.llm_fallback_base_url:
            self._fallback_http = httpx.AsyncClient(
                base_url=self._settings.llm_fallback_base_url,
                timeout=httpx.Timeout(float(self._settings.llm_fallback_timeout)),
            )

    async def close(self) -> None:
        """Close all HTTP clients."""
        if self._primary_http and not self._primary_http.is_closed:
            await self._primary_http.aclose()
            self._primary_http = None
        if self._fallback_http and not self._fallback_http.is_closed:
            await self._fallback_http.aclose()
            self._fallback_http = None

    async def generate(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Generate a completion using the configured LLM providers.

        Tries the primary provider first. On failure, falls back to the
        fallback provider if configured.

        Args:
            messages: OpenAI-format message list.
            config: Optional overrides (temperature, max_tokens, provider_override).

        Returns:
            LLMResponse with generated content and metadata.
        """
        config = config or {}
        provider_override = config.get("provider_override")

        # Build provider chain
        providers = self._build_provider_chain(provider_override)

        last_error: Exception | None = None
        for provider_name, http_client, model, api_key in providers:
            try:
                return await self._call_provider(
                    provider_name=provider_name,
                    http_client=http_client,
                    model=model,
                    api_key=api_key,
                    messages=messages,
                    config=config,
                )
            except Exception as exc:
                logger.warning(
                    "llm_provider_failed",
                    provider=provider_name,
                    model=model,
                    error=str(exc),
                )
                last_error = exc

        raise RuntimeError(
            f"All LLM providers failed. Last error: {last_error}"
        )

    def _build_provider_chain(
        self, provider_override: str | None
    ) -> list[tuple[str, httpx.AsyncClient | None, str, str]]:
        """Build ordered list of (name, http_client, model, api_key) tuples."""
        chain = []

        if provider_override:
            # If user specified a provider, try that first
            if provider_override == self._settings.llm_primary_provider:
                chain.append((
                    self._settings.llm_primary_provider,
                    self._primary_http,
                    self._settings.llm_primary_model,
                    self._settings.llm_primary_api_key,
                ))
            elif provider_override == self._settings.llm_fallback_provider:
                chain.append((
                    self._settings.llm_fallback_provider,
                    self._fallback_http,
                    self._settings.llm_fallback_model,
                    self._settings.llm_fallback_api_key,
                ))

        # Always include primary + fallback as defaults
        chain.append((
            self._settings.llm_primary_provider,
            self._primary_http,
            self._settings.llm_primary_model,
            self._settings.llm_primary_api_key,
        ))
        if self._fallback_http:
            chain.append((
                self._settings.llm_fallback_provider,
                self._fallback_http,
                self._settings.llm_fallback_model,
                self._settings.llm_fallback_api_key,
            ))

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for entry in chain:
            key = (entry[0], entry[2])  # (provider, model)
            if key not in seen:
                seen.add(key)
                deduped.append(entry)

        return deduped

    async def _call_provider(
        self,
        provider_name: str,
        http_client: httpx.AsyncClient | None,
        model: str,
        api_key: str,
        messages: list[dict[str, str]],
        config: dict[str, Any],
    ) -> LLMResponse:
        """Make an OpenAI-compatible chat completion request.

        Detects Azure OpenAI models (prefixed with 'azure/') and uses
        the Azure-specific URL format and api-key header.
        """
        if http_client is None or http_client.is_closed:
            raise RuntimeError(f"HTTP client not initialized for provider: {provider_name}")

        temperature = config.get("temperature", self._settings.llm_temperature)
        max_tokens = config.get("max_tokens", self._settings.llm_max_tokens)

        # Detect Azure OpenAI model (e.g., "azure/gpt-4.1")
        is_azure = model.startswith("azure/")
        actual_model = model.removeprefix("azure/") if is_azure else model

        payload: dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers: dict[str, str] = {"Content-Type": "application/json"}

        if is_azure:
            # Azure OpenAI: use /openai/deployments/{deployment}/chat/completions
            api_version = self._settings.embedding_azure_api_version or "2024-12-01-preview"
            url = f"/openai/deployments/{actual_model}/chat/completions?api-version={api_version}"
            headers["api-key"] = api_key
        else:
            url = "/chat/completions"
            payload["model"] = model
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

        start = time.monotonic()

        resp = await http_client.post(
            url,
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()

        elapsed_ms = (time.monotonic() - start) * 1000
        body = resp.json()

        # Parse OpenAI-format response
        choices = body.get("choices", [])
        content = ""
        if choices:
            content = choices[0].get("message", {}).get("content", "")

        usage = body.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        # Estimate generation quality from response characteristics
        quality = self._estimate_quality(content, completion_tokens)

        logger.info(
            "llm_generation_complete",
            provider=provider_name,
            model=body.get("model", model),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=round(elapsed_ms, 1),
        )

        return LLMResponse(
            content=content,
            model=body.get("model", model),
            provider=provider_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=elapsed_ms,
            generation_quality=quality,
            raw=body,
        )

    @staticmethod
    def _estimate_quality(content: str, completion_tokens: int) -> float:
        """Heuristic quality estimation based on response characteristics."""
        if not content.strip():
            return 0.0

        score = 0.5

        # Has SQL code block
        if "```sql" in content.lower():
            score += 0.2

        # Reasonable length (not too short, not absurdly long)
        if 50 < len(content) < 5000:
            score += 0.1

        # Contains SELECT (likely valid SQL)
        if "SELECT" in content.upper():
            score += 0.1

        # Has explanation after code block
        import re
        if re.search(r"```\s*\n\s*\S", content):
            score += 0.1

        return min(score, 1.0)

    async def health_check(self) -> bool:
        """Check if the primary LLM provider is reachable."""
        if self._primary_http is None or self._primary_http.is_closed:
            return False
        try:
            resp = await self._primary_http.get("/models")
            return resp.status_code in (200, 404)  # 404 is ok, means server is up
        except Exception:
            return False
