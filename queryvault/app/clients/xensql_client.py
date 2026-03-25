"""XenSQL Pipeline HTTP client -- sends question + security context, receives SQL.

Communicates with the XenSQL NL-to-SQL pipeline engine over HTTP.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from queryvault.app.config import Settings

logger = structlog.get_logger(__name__)


class XenSQLClient:
    """Async HTTP client for the XenSQL Pipeline Engine (port 8900)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._http: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        """Initialise the underlying HTTP client."""
        self._http = httpx.AsyncClient(
            base_url=self._settings.xensql_base_url,
            timeout=httpx.Timeout(float(self._settings.xensql_timeout)),
        )
        logger.info("xensql_client_connected", base_url=self._settings.xensql_base_url)

    async def close(self) -> None:
        """Shut down the HTTP client."""
        if self._http:
            await self._http.aclose()
            self._http = None
            logger.info("xensql_client_closed")

    def _auth_headers(self) -> dict[str, str]:
        """Build service-to-service auth headers using HMAC secret."""
        import hashlib
        import time

        timestamp = str(int(time.time()))
        signature = hashlib.sha256(
            f"{self._settings.service_id}:{timestamp}:{self._settings.hmac_secret}".encode()
        ).hexdigest()

        return {
            "X-Service-ID": self._settings.service_id,
            "X-Service-Role": self._settings.service_role,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        }

    async def query(
        self,
        question: str,
        filtered_schema: dict[str, Any] | None = None,
        contextual_rules: list[str] | None = None,
        dialect_hint: str = "postgresql",
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Call XenSQL POST /api/v1/pipeline/query.

        Args:
            question: Natural-language question to translate to SQL.
            filtered_schema: Pre-filtered schema based on RBAC and column scoping.
            contextual_rules: Security-derived rules to constrain SQL generation.
            dialect_hint: SQL dialect hint (e.g. "postgresql", "mysql").
            session_id: Session correlation ID.

        Returns:
            Pipeline response dict containing sql, confidence, status, etc.

        Raises:
            RuntimeError: If XenSQL is unreachable or returns an error.
        """
        http = self._http
        if not http:
            # Create a one-shot client if connect() was not called
            http = httpx.AsyncClient(
                base_url=self._settings.xensql_base_url,
                timeout=httpx.Timeout(float(self._settings.xensql_timeout)),
            )

        payload: dict[str, Any] = {
            "question": question,
            "dialect_hint": dialect_hint,
        }

        if filtered_schema:
            payload["filtered_schema"] = filtered_schema
        if contextual_rules:
            payload["contextual_rules"] = contextual_rules
        if session_id:
            payload["session_id"] = session_id

        try:
            resp = await http.post(
                "/api/v1/pipeline/query",
                json=payload,
                headers=self._auth_headers(),
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info(
                "xensql_query_success",
                status=data.get("status"),
                confidence=data.get("confidence"),
            )
            return data

        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            logger.error("xensql_http_error", status=status)
            raise RuntimeError(f"XenSQL failed: HTTP {status}")
        except httpx.ConnectError as exc:
            logger.error("xensql_unreachable", error=str(exc))
            raise RuntimeError(f"XenSQL unreachable: {exc}")
        except httpx.TimeoutException:
            logger.error("xensql_timeout")
            raise RuntimeError("XenSQL request timed out")
        finally:
            if not self._http and http:
                await http.aclose()

    async def health_check(self) -> bool:
        """Check if XenSQL is reachable."""
        http = self._http
        close_after = False
        if not http:
            http = httpx.AsyncClient(
                base_url=self._settings.xensql_base_url,
                timeout=httpx.Timeout(5.0),
            )
            close_after = True

        try:
            resp = await http.get("/health")
            return resp.status_code == 200
        except Exception:
            return False
        finally:
            if close_after:
                await http.aclose()
