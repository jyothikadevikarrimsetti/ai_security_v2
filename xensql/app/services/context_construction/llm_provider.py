"""CC-003 LLM Provider — unified interface for multiple LLM backends.

Supports:
  - Anthropic Claude (via anthropic SDK)
  - OpenAI GPT-4 / GPT-4o (via openai SDK)
  - Azure OpenAI (via openai SDK with azure endpoint)
  - Ollama (OpenAI-compatible /v1 endpoint)
  - vLLM (OpenAI-compatible mode)
  - TGI (Text Generation Inference, OpenAI-compatible)
  - Any OpenAI-API-compatible server

Provider selection is purely config-driven — swap via configuration, zero
code changes required.
"""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class LLMProviderConfig:
    """Configuration for a single LLM provider."""

    name: str
    type: str  # "anthropic", "openai", "azure_openai", "openai_compat"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    priority: int = 10  # lower = tried first
    max_tokens: int = 2048
    temperature: float = 0.0
    timeout_seconds: int = 60
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Response from an LLM provider call."""

    text: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    attempt: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


class LLMProviderError(Exception):
    """Raised when an LLM provider call fails."""


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMProvider(abc.ABC):
    """Abstract interface for LLM providers.

    All concrete implementations must provide ``generate``.
    """

    def __init__(self, config: LLMProviderConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def priority(self) -> int:
        return self._config.priority

    @abc.abstractmethod
    async def generate(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Generate a completion from the given messages.

        Parameters
        ----------
        messages:
            Chat messages in OpenAI format:
            ``[{"role": "system", "content": "..."}, ...]``
        config:
            Optional per-request overrides (temperature, max_tokens, etc.).

        Returns
        -------
        LLMResponse
        """


# ---------------------------------------------------------------------------
# OpenAI-compatible provider (covers OpenAI, Ollama, vLLM, TGI, etc.)
# ---------------------------------------------------------------------------


class OpenAICompatProvider(LLMProvider):
    """Provider for any OpenAI-API-compatible endpoint.

    Works with: OpenAI, Ollama (/v1), vLLM, TGI, LiteLLM, etc.
    """

    async def generate(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> LLMResponse:
        try:
            from openai import AsyncOpenAI
        except ImportError:
            raise LLMProviderError(
                "openai package not installed. Install with: pip install openai"
            )

        overrides = config or {}
        model = overrides.get("model", self._config.model)
        temperature = overrides.get("temperature", self._config.temperature)
        max_tokens = overrides.get("max_tokens", self._config.max_tokens)
        timeout = overrides.get("timeout_seconds", self._config.timeout_seconds)

        client = AsyncOpenAI(
            base_url=self._config.base_url or None,
            api_key=self._config.api_key or "not-needed",
        )

        start = time.monotonic()
        try:
            async with asyncio.timeout(timeout):
                response = await client.chat.completions.create(
                    model=model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
        except (TimeoutError, asyncio.TimeoutError) as exc:
            raise LLMProviderError(
                f"Timeout after {timeout}s calling {self._config.base_url} "
                f"with model {model}"
            ) from exc
        except Exception as exc:
            raise LLMProviderError(
                f"OpenAI-compat provider '{self.name}' failed: {exc}"
            ) from exc

        latency_ms = (time.monotonic() - start) * 1000
        text = (
            response.choices[0].message.content or ""
            if response.choices
            else ""
        )
        pt = response.usage.prompt_tokens if response.usage else 0
        ct = response.usage.completion_tokens if response.usage else 0

        logger.info(
            "openai_compat_call_success: provider=%s model=%s latency=%.1fms",
            self.name,
            model,
            latency_ms,
        )

        return LLMResponse(
            text=text,
            model=model,
            provider=self.name,
            prompt_tokens=pt,
            completion_tokens=ct,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Azure OpenAI provider
# ---------------------------------------------------------------------------


class AzureOpenAIProvider(LLMProvider):
    """Provider for Azure OpenAI endpoints."""

    async def generate(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> LLMResponse:
        try:
            from openai import AsyncAzureOpenAI
        except ImportError:
            raise LLMProviderError(
                "openai package not installed. Install with: pip install openai"
            )

        overrides = config or {}
        model = overrides.get("model", self._config.model)
        temperature = overrides.get("temperature", self._config.temperature)
        max_tokens = overrides.get("max_tokens", self._config.max_tokens)
        timeout = overrides.get("timeout_seconds", self._config.timeout_seconds)

        api_version = self._config.extra.get("api_version", "2024-02-01")

        client = AsyncAzureOpenAI(
            azure_endpoint=self._config.base_url,
            api_key=self._config.api_key,
            api_version=api_version,
        )

        start = time.monotonic()
        try:
            async with asyncio.timeout(timeout):
                response = await client.chat.completions.create(
                    model=model,
                    messages=messages,  # type: ignore[arg-type]
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
        except (TimeoutError, asyncio.TimeoutError) as exc:
            raise LLMProviderError(
                f"Azure OpenAI timeout after {timeout}s"
            ) from exc
        except Exception as exc:
            raise LLMProviderError(
                f"Azure OpenAI provider '{self.name}' failed: {exc}"
            ) from exc

        latency_ms = (time.monotonic() - start) * 1000
        text = (
            response.choices[0].message.content or ""
            if response.choices
            else ""
        )
        pt = response.usage.prompt_tokens if response.usage else 0
        ct = response.usage.completion_tokens if response.usage else 0

        return LLMResponse(
            text=text,
            model=model,
            provider=self.name,
            prompt_tokens=pt,
            completion_tokens=ct,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Anthropic Claude provider
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """Provider for Anthropic Claude models."""

    async def generate(
        self,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> LLMResponse:
        try:
            from anthropic import AsyncAnthropic
        except ImportError:
            raise LLMProviderError(
                "anthropic package not installed. "
                "Install with: pip install anthropic"
            )

        overrides = config or {}
        model = overrides.get("model", self._config.model or "claude-sonnet-4-20250514")
        temperature = overrides.get("temperature", self._config.temperature)
        max_tokens = overrides.get("max_tokens", self._config.max_tokens)
        timeout = overrides.get("timeout_seconds", self._config.timeout_seconds)

        client = AsyncAnthropic(api_key=self._config.api_key)

        # Anthropic API uses a separate system parameter
        system_text = ""
        chat_messages: list[dict[str, str]] = []
        for msg in messages:
            if msg["role"] == "system":
                system_text = msg["content"]
            else:
                chat_messages.append(msg)

        # Ensure at least one user message
        if not chat_messages:
            chat_messages = [{"role": "user", "content": ""}]

        start = time.monotonic()
        try:
            async with asyncio.timeout(timeout):
                response = await client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=system_text,
                    messages=chat_messages,  # type: ignore[arg-type]
                    temperature=temperature,
                )
        except (TimeoutError, asyncio.TimeoutError) as exc:
            raise LLMProviderError(
                f"Anthropic timeout after {timeout}s"
            ) from exc
        except Exception as exc:
            raise LLMProviderError(
                f"Anthropic provider '{self.name}' failed: {exc}"
            ) from exc

        latency_ms = (time.monotonic() - start) * 1000
        text = (
            response.content[0].text
            if response.content
            else ""
        )
        pt = response.usage.input_tokens if response.usage else 0
        ct = response.usage.output_tokens if response.usage else 0

        return LLMResponse(
            text=text,
            model=model,
            provider=self.name,
            prompt_tokens=pt,
            completion_tokens=ct,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

_PROVIDER_TYPES: dict[str, type[LLMProvider]] = {
    "openai": OpenAICompatProvider,
    "openai_compat": OpenAICompatProvider,
    "ollama": OpenAICompatProvider,
    "vllm": OpenAICompatProvider,
    "tgi": OpenAICompatProvider,
    "azure_openai": AzureOpenAIProvider,
    "anthropic": AnthropicProvider,
}


def _create_provider(config: LLMProviderConfig) -> LLMProvider:
    """Instantiate the correct provider class from config."""
    cls = _PROVIDER_TYPES.get(config.type)
    if cls is None:
        raise LLMProviderError(
            f"Unknown provider type '{config.type}'. "
            f"Supported: {sorted(_PROVIDER_TYPES.keys())}"
        )
    return cls(config)


# ---------------------------------------------------------------------------
# LLMProviderRegistry
# ---------------------------------------------------------------------------


class LLMProviderRegistry:
    """Manages multiple LLM providers with config-driven registration.

    Usage::

        registry = LLMProviderRegistry()
        registry.register(LLMProviderConfig(
            name="claude", type="anthropic",
            api_key="sk-...", model="claude-sonnet-4-20250514", priority=1,
        ))
        registry.register(LLMProviderConfig(
            name="gpt4", type="openai",
            api_key="sk-...", model="gpt-4o", priority=2,
        ))
        registry.register(LLMProviderConfig(
            name="local-ollama", type="ollama",
            base_url="http://localhost:11434/v1",
            model="llama3", priority=10,
        ))

        # Use a specific provider
        response = await registry.generate("claude", messages)

        # Or get all sorted by priority for fallback
        providers = registry.available_providers
    """

    def __init__(self) -> None:
        self._providers: dict[str, LLMProvider] = {}
        self._configs: dict[str, LLMProviderConfig] = {}

    def register(self, config: LLMProviderConfig) -> None:
        """Register an LLM provider from its configuration."""
        provider = _create_provider(config)
        self._providers[config.name] = provider
        self._configs[config.name] = config
        logger.info(
            "llm_provider_registered: name=%s type=%s model=%s priority=%d",
            config.name,
            config.type,
            config.model,
            config.priority,
        )

    def register_many(self, configs: list[LLMProviderConfig]) -> None:
        """Register multiple providers at once."""
        for cfg in configs:
            self.register(cfg)

    def has_provider(self, name: str) -> bool:
        """Check if a provider with the given name is registered."""
        return name in self._providers

    def get_provider(self, name: str) -> LLMProvider:
        """Get a specific provider by name."""
        if name not in self._providers:
            raise LLMProviderError(f"Unknown provider: {name}")
        return self._providers[name]

    @property
    def available_providers(self) -> list[LLMProvider]:
        """All registered providers sorted by priority (lowest first)."""
        return sorted(self._providers.values(), key=lambda p: p.priority)

    @property
    def provider_names(self) -> list[str]:
        """Names of all registered providers."""
        return list(self._providers.keys())

    async def generate(
        self,
        provider_name: str,
        messages: list[dict[str, str]],
        config: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Call a specific provider by name.

        Parameters
        ----------
        provider_name:
            Name of the registered provider.
        messages:
            Chat messages in OpenAI format.
        config:
            Optional per-request overrides.

        Returns
        -------
        LLMResponse

        Raises
        ------
        LLMProviderError
            If the provider is unknown or the call fails.
        """
        provider = self.get_provider(provider_name)
        try:
            return await provider.generate(messages, config)
        except LLMProviderError:
            raise
        except Exception as exc:
            raise LLMProviderError(
                f"Provider '{provider_name}' failed: {exc}"
            ) from exc
