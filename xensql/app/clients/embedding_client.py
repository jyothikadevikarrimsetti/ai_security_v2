"""Multi-provider embedding client for XenSQL.

Supports three providers with automatic failover:
  1. Voyage AI   (voyage-3-large)
  2. OpenAI      (text-embedding-3-small)
  3. Azure OpenAI (text-embedding-ada-002)

Provider order is determined by configuration. All vectors are L2-normalized
to the configured dimensionality.
"""

from __future__ import annotations

import math
from typing import Any

import httpx
import structlog

from xensql.app.config import Settings

logger = structlog.get_logger(__name__)


def _l2_normalize(vec: list[float]) -> list[float]:
    """Apply L2 normalization to the embedding vector."""
    norm = math.sqrt(sum(x * x for x in vec))
    if norm < 1e-12:
        return vec
    return [x / norm for x in vec]


def _truncate_or_pad(vec: list[float], dim: int) -> list[float]:
    """Ensure the vector matches expected dimensions."""
    if len(vec) >= dim:
        return vec[:dim]
    return vec + [0.0] * (dim - len(vec))


class EmbeddingClient:
    """Async multi-provider embedding client with 3-provider failover.

    Usage:
        client = EmbeddingClient(settings)
        await client.connect()
        vector = await client.embed("some text")
        vectors = await client.embed_batch(["text1", "text2"])
        await client.close()
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._http: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        """Initialize the HTTP client."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=httpx.Timeout(30.0))

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    async def embed(self, text: str) -> list[float]:
        """Generate an embedding vector with provider failover.

        Tries configured providers in order: primary -> fallbacks.
        Returns L2-normalized vector of configured dimensions.
        Raises RuntimeError if all providers fail.
        """
        providers = self._build_provider_chain()

        last_error: Exception | None = None
        for name, fn in providers:
            try:
                raw = await fn(text)
                vec = _truncate_or_pad(raw, self._settings.embedding_dimensions)
                return _l2_normalize(vec)
            except Exception as exc:
                logger.warning("embedding_provider_failed", provider=name, error=str(exc))
                last_error = exc

        raise RuntimeError(f"All embedding providers failed. Last error: {last_error}")

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a batch of texts.

        Tries batch-capable endpoints first, falls back to sequential calls.
        Returns list of L2-normalized vectors.
        """
        providers = self._build_provider_chain()

        last_error: Exception | None = None
        for name, fn in providers:
            try:
                if name == "voyage":
                    raws = await self._embed_voyage_batch(texts)
                elif name == "openai":
                    raws = await self._embed_openai_batch(texts)
                elif name == "azure":
                    raws = await self._embed_azure_batch(texts)
                else:
                    # Sequential fallback
                    raws = [await fn(t) for t in texts]

                dim = self._settings.embedding_dimensions
                return [_l2_normalize(_truncate_or_pad(v, dim)) for v in raws]
            except Exception as exc:
                logger.warning("embedding_batch_provider_failed", provider=name, error=str(exc))
                last_error = exc

        raise RuntimeError(f"All embedding providers failed for batch. Last error: {last_error}")

    def _build_provider_chain(self) -> list[tuple[str, Any]]:
        """Build the ordered provider chain based on configuration."""
        providers: list[tuple[str, Any]] = []
        primary = self._settings.embedding_provider.lower()

        # Map provider names to callables
        provider_map = {
            "voyage": ("voyage", self._embed_voyage),
            "openai": ("openai", self._embed_openai),
            "azure": ("azure", self._embed_azure),
        }

        # Primary first
        if primary in provider_map:
            providers.append(provider_map[primary])

        # Then remaining as fallbacks
        for name, entry in provider_map.items():
            if name != primary:
                providers.append(entry)

        return providers

    def _require_http(self) -> httpx.AsyncClient:
        """Return the HTTP client or raise."""
        if self._http is None or self._http.is_closed:
            raise RuntimeError("EmbeddingClient not connected -- call connect() first")
        return self._http

    # -- Voyage AI -------------------------------------------------------------

    async def _embed_voyage(self, text: str) -> list[float]:
        """Voyage AI single embedding."""
        api_key = self._settings.embedding_voyage_api_key
        if not api_key:
            raise RuntimeError("Voyage API key not configured")

        http = self._require_http()
        resp = await http.post(
            "https://api.voyageai.com/v1/embeddings",
            json={
                "input": [text],
                "model": self._settings.embedding_voyage_model,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()["data"][0]["embedding"]

    async def _embed_voyage_batch(self, texts: list[str]) -> list[list[float]]:
        """Voyage AI batch embedding."""
        api_key = self._settings.embedding_voyage_api_key
        if not api_key:
            raise RuntimeError("Voyage API key not configured")

        http = self._require_http()
        resp = await http.post(
            "https://api.voyageai.com/v1/embeddings",
            json={
                "input": texts,
                "model": self._settings.embedding_voyage_model,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        # Voyage returns items sorted by index
        sorted_data = sorted(data, key=lambda d: d.get("index", 0))
        return [item["embedding"] for item in sorted_data]

    # -- OpenAI ----------------------------------------------------------------

    async def _embed_openai(self, text: str) -> list[float]:
        """Standard OpenAI single embedding."""
        api_key = self._settings.embedding_openai_api_key
        if not api_key:
            raise RuntimeError("OpenAI API key not configured")

        http = self._require_http()
        resp = await http.post(
            "https://api.openai.com/v1/embeddings",
            json={
                "input": text,
                "model": self._settings.embedding_openai_model,
                "dimensions": self._settings.embedding_dimensions,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()["data"][0]["embedding"]

    async def _embed_openai_batch(self, texts: list[str]) -> list[list[float]]:
        """Standard OpenAI batch embedding."""
        api_key = self._settings.embedding_openai_api_key
        if not api_key:
            raise RuntimeError("OpenAI API key not configured")

        http = self._require_http()
        resp = await http.post(
            "https://api.openai.com/v1/embeddings",
            json={
                "input": texts,
                "model": self._settings.embedding_openai_model,
                "dimensions": self._settings.embedding_dimensions,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        sorted_data = sorted(data, key=lambda d: d.get("index", 0))
        return [item["embedding"] for item in sorted_data]

    # -- Azure OpenAI ----------------------------------------------------------

    async def _embed_azure(self, text: str) -> list[float]:
        """Azure OpenAI single embedding."""
        api_key = self._settings.embedding_azure_api_key
        endpoint = self._settings.embedding_azure_endpoint.rstrip("/")
        deployment = self._settings.embedding_azure_deployment
        api_version = self._settings.embedding_azure_api_version

        if not api_key or not endpoint:
            raise RuntimeError("Azure OpenAI API key or endpoint not configured")

        http = self._require_http()
        url = f"{endpoint}/openai/deployments/{deployment}/embeddings?api-version={api_version}"
        resp = await http.post(
            url,
            json={"input": text},
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()["data"][0]["embedding"]

    async def _embed_azure_batch(self, texts: list[str]) -> list[list[float]]:
        """Azure OpenAI batch embedding."""
        api_key = self._settings.embedding_azure_api_key
        endpoint = self._settings.embedding_azure_endpoint.rstrip("/")
        deployment = self._settings.embedding_azure_deployment
        api_version = self._settings.embedding_azure_api_version

        if not api_key or not endpoint:
            raise RuntimeError("Azure OpenAI API key or endpoint not configured")

        http = self._require_http()
        url = f"{endpoint}/openai/deployments/{deployment}/embeddings?api-version={api_version}"
        resp = await http.post(
            url,
            json={"input": texts},
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        sorted_data = sorted(data, key=lambda d: d.get("index", 0))
        return [item["embedding"] for item in sorted_data]

    # -- Health ----------------------------------------------------------------

    async def health_check(self) -> bool:
        """Quick health check -- verifies HTTP client is usable."""
        return self._http is not None and not self._http.is_closed
