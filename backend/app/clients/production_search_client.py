"""Dedicated READ-ONLY HTTP client for the original production Product & Company Search app.

Target reference: ``origin/main`` (`app.main:app`), which exposes ONLY two
read-only observability endpoints relevant to Product & Company Search:
  - ``GET /api/healthz`` -> ``{"status": "ok"}``
  - ``GET /api/debug/index-status`` -> ``{"b2bCompanies": ..., "b2bProducts": ..., "localProducts": ...}``

Strict safety guarantees:
  1. Disabled by default (``PRODUCTION_OBSERVABILITY_ENABLED=false``). When
     disabled, zero outbound HTTP requests are ever attempted.
  2. Strictly GET-only. Never executes writes, syncs, ingestion, config updates,
     index rebuilds, or rollbacks against production.
  3. BrochureIQ data separation: ``localProducts`` (and any non-allowlisted key)
     is unconditionally stripped from ``/api/debug/index-status`` responses before
     anything leaves this client.
  4. Independent fail-closed authentication: defaults to ``auth_mode="bearer"``;
     never silently falls back to unauthenticated requests if token auth is
     configured without a token, and never forwards browser cookies, CSRF tokens,
     or Search Admin internal/CLI tokens.
"""
from __future__ import annotations

from typing import Any, Literal

import httpx
from fastapi import Request

from app.config import (
    get_production_search_auth_header,
    get_production_search_auth_mode,
    get_production_search_auth_token,
    get_production_search_base_url,
    get_production_search_timeout_seconds,
    is_production_observability_enabled,
)
from app.logger import logger

# Only Product & Company Search keys are allowed. BrochureIQ's ``localProducts``
# is explicitly excluded so zero BrochureIQ data is ever exposed to Search Admin.
ALLOWED_PRODUCTION_INDEX_KEYS: tuple[str, ...] = ("b2bCompanies", "b2bProducts")
FORBIDDEN_BROCHUREIQ_INDEX_KEYS: frozenset[str] = frozenset({"localProducts"})

_ALLOWED_READ_ONLY_PATHS: frozenset[str] = frozenset(
    {"/api/healthz", "/api/debug/index-status"}
)


class ProductionObservabilityDisabledError(RuntimeError):
    """Raised internally when production observability is disabled."""


class ProductionObservabilityConfigError(RuntimeError):
    """Raised when production observability is enabled with missing/invalid config or auth."""


class ProductionObservabilityAuthError(RuntimeError):
    """Raised when the production endpoint rejects configured upstream credentials."""


class ProductionObservabilityUpstreamError(RuntimeError):
    """Raised when the production endpoint times out, fails, or returns invalid JSON."""


def filter_product_company_indexes(raw_payload: Any) -> dict[str, dict[str, Any]]:
    """Strip BrochureIQ keys (``localProducts``) and retain only Product & Company index state."""
    if not isinstance(raw_payload, dict):
        return {}

    filtered: dict[str, dict[str, Any]] = {}
    for key in ALLOWED_PRODUCTION_INDEX_KEYS:
        entry = raw_payload.get(key)
        if not isinstance(entry, dict):
            continue
        count = int(entry.get("count") or 0)
        index_built = bool(entry.get("index_built", False))
        if index_built:
            raw_status = "ready"
            health_state = "healthy"
        elif count == 0:
            raw_status = "ready_empty"
            health_state = "healthy"
        else:
            raw_status = "failed"
            health_state = "unhealthy"
        filtered[key] = {
            "status": raw_status,
            "health_state": health_state,
            "count": count,
            "index_built": index_built,
            "last_error": None,
        }
    return filtered


class ProductionSearchClient:
    """Strictly read-only, disabled-by-default client for original production observability."""

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        base_url: str | None = None,
        auth_mode: Literal["bearer", "api_key", "none"] | None = None,
        auth_token: str | None = None,
        auth_header: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._explicit_enabled = enabled
        self._explicit_base_url = base_url.rstrip("/") if base_url is not None else None
        self._explicit_auth_mode = auth_mode
        self._explicit_auth_token = auth_token
        self._explicit_auth_header = auth_header
        self._explicit_timeout = timeout_seconds
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    def is_enabled(self) -> bool:
        if self._explicit_enabled is not None:
            return bool(self._explicit_enabled)
        return is_production_observability_enabled()

    def _base_url(self) -> str | None:
        if self._explicit_base_url is not None:
            return self._explicit_base_url or None
        return get_production_search_base_url()

    def _auth_mode(self) -> Literal["bearer", "api_key", "none"]:
        if self._explicit_auth_mode is not None:
            return self._explicit_auth_mode
        return get_production_search_auth_mode()

    def _auth_token(self) -> str:
        if self._explicit_auth_token is not None:
            return self._explicit_auth_token.strip()
        return get_production_search_auth_token()

    def _auth_header(self) -> str:
        if self._explicit_auth_header is not None:
            return self._explicit_auth_header.strip() or "X-API-Key"
        return get_production_search_auth_header()

    def _timeout(self) -> float:
        if self._explicit_timeout is not None:
            return float(self._explicit_timeout)
        return get_production_search_timeout_seconds()

    def _build_upstream_headers(self, request_id: str | None = None) -> dict[str, str]:
        """Construct strictly server-side auth headers; fail closed if required auth is absent."""
        headers: dict[str, str] = {"Accept": "application/json"}
        if request_id:
            headers["X-Request-Id"] = request_id

        mode = self._auth_mode()
        token = self._auth_token()
        if mode == "bearer":
            if not token:
                raise ProductionObservabilityConfigError(
                    "Production observability requires PRODUCTION_SEARCH_AUTH_TOKEN when auth mode is 'bearer'."
                )
            headers["Authorization"] = f"Bearer {token}"
        elif mode == "api_key":
            if not token:
                raise ProductionObservabilityConfigError(
                    "Production observability requires PRODUCTION_SEARCH_AUTH_TOKEN when auth mode is 'api_key'."
                )
            headers[self._auth_header()] = token
        elif mode == "none":
            # Allowed only when explicitly opted in after Stage 3 network/Nginx verification.
            pass
        else:
            raise ProductionObservabilityConfigError(
                f"Unsupported production observability auth mode: {mode!r}"
            )
        return headers

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            timeout = self._timeout()
            kwargs: dict[str, Any] = {
                "follow_redirects": False,
                "timeout": httpx.Timeout(connect=3.0, read=timeout, write=3.0, pool=3.0),
            }
            if self._transport is not None:
                kwargs["transport"] = self._transport
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def _get_json(self, path: str, *, request_id: str | None = None) -> Any:
        """Perform an allowlisted GET-only read against the configured production service."""
        if not self.is_enabled():
            raise ProductionObservabilityDisabledError(
                "Production observability integration is disabled by configuration."
            )
        if path not in _ALLOWED_READ_ONLY_PATHS:
            raise ValueError(f"Path {path!r} is not an approved read-only production endpoint")

        base_url = self._base_url()
        if not base_url:
            raise ProductionObservabilityConfigError(
                "Production observability is enabled but PRODUCTION_SEARCH_BASE_URL is not configured."
            )

        headers = self._build_upstream_headers(request_id=request_id)
        url = f"{base_url}{path}"

        try:
            response = await self._get_client().get(url, headers=headers)
        except httpx.TimeoutException as exc:
            logger.warning(
                "Production Search API GET %s timed out (request_id=%s)",
                path,
                request_id,
            )
            raise ProductionObservabilityUpstreamError(
                "Production Search API request timed out"
            ) from exc
        except httpx.TransportError as exc:
            logger.warning(
                "Production Search API GET %s transport failure (exception_type=%s, request_id=%s)",
                path,
                type(exc).__name__,
                request_id,
            )
            raise ProductionObservabilityUpstreamError(
                "Unable to reach Production Search API"
            ) from exc

        if response.status_code in {401, 403}:
            logger.error(
                "Production Search API rejected credentials on GET %s (status=%s, request_id=%s)",
                path,
                response.status_code,
                request_id,
            )
            raise ProductionObservabilityAuthError(
                "Production Search API authentication failed"
            )

        if response.status_code >= 400:
            logger.warning(
                "Production Search API GET %s returned HTTP %s (request_id=%s)",
                path,
                response.status_code,
                request_id,
            )
            raise ProductionObservabilityUpstreamError(
                f"Production Search API returned HTTP {response.status_code}"
            )

        try:
            return response.json()
        except Exception as exc:
            raise ProductionObservabilityUpstreamError(
                "Production Search API returned invalid JSON"
            ) from exc

    async def get_health(self, *, request_id: str | None = None) -> dict[str, Any]:
        """Read-only check of production ``GET /api/healthz``."""
        if not self.is_enabled():
            return {
                "enabled": False,
                "status": "disabled",
                "read_only": True,
                "detail": "Production observability is disabled by configuration.",
            }

        try:
            payload = await self._get_json("/api/healthz", request_id=request_id)
        except ProductionObservabilityConfigError as exc:
            return {
                "enabled": True,
                "status": "unavailable",
                "read_only": True,
                "detail": str(exc),
            }
        except ProductionObservabilityAuthError as exc:
            return {
                "enabled": True,
                "status": "unhealthy",
                "read_only": True,
                "detail": str(exc),
            }
        except ProductionObservabilityUpstreamError as exc:
            return {
                "enabled": True,
                "status": "unavailable",
                "read_only": True,
                "detail": str(exc),
            }

        ok = isinstance(payload, dict) and str(payload.get("status", "")).lower() == "ok"
        return {
            "enabled": True,
            "status": "healthy" if ok else "degraded",
            "read_only": True,
            "upstream_status": payload.get("status") if isinstance(payload, dict) else None,
            "detail": (
                "Production Product & Company Search API responded healthy on GET /api/healthz."
                if ok
                else "Production Search API returned a non-ok health response."
            ),
        }

    async def get_index_status(self, *, request_id: str | None = None) -> dict[str, Any]:
        """Read-only check of production ``GET /api/debug/index-status`` (BrochureIQ stripped)."""
        if not self.is_enabled():
            return {
                "enabled": False,
                "status": "disabled",
                "read_only": True,
                "ready_count": 0,
                "total_count": 0,
                "total_records": 0,
                "detail": (
                    "Optional read-only production Product & Company Search observability "
                    "is disabled until Stage 3 verification."
                ),
                "indexes": {},
            }

        try:
            raw = await self._get_json("/api/debug/index-status", request_id=request_id)
        except ProductionObservabilityConfigError as exc:
            return {
                "enabled": True,
                "status": "unavailable",
                "read_only": True,
                "ready_count": 0,
                "total_count": 0,
                "total_records": 0,
                "detail": str(exc),
                "indexes": {},
            }
        except ProductionObservabilityAuthError as exc:
            return {
                "enabled": True,
                "status": "unhealthy",
                "read_only": True,
                "ready_count": 0,
                "total_count": 0,
                "total_records": 0,
                "detail": str(exc),
                "indexes": {},
            }
        except ProductionObservabilityUpstreamError as exc:
            return {
                "enabled": True,
                "status": "unavailable",
                "read_only": True,
                "ready_count": 0,
                "total_count": 0,
                "total_records": 0,
                "detail": str(exc),
                "indexes": {},
            }

        indexes = filter_product_company_indexes(raw)
        if not indexes:
            return {
                "enabled": True,
                "status": "unavailable",
                "read_only": True,
                "ready_count": 0,
                "total_count": 0,
                "total_records": 0,
                "detail": "Production index status response contained no Product & Company Search index entries.",
                "indexes": {},
            }

        ready_count = sum(1 for item in indexes.values() if item["status"] in {"ready", "ready_empty"})
        total_count = len(indexes)
        total_records = sum(int(item["count"]) for item in indexes.values())
        overall = "healthy" if ready_count == total_count else "unhealthy"
        detail = (
            f"{ready_count}/{total_count} production Product & Company Search indexes ready "
            f"({total_records:,} total records; BrochureIQ localProducts excluded)."
        )
        return {
            "enabled": True,
            "status": overall,
            "read_only": True,
            "ready_count": ready_count,
            "total_count": total_count,
            "total_records": total_records,
            "detail": detail,
            "indexes": indexes,
        }


def get_production_search_client(request: Request) -> ProductionSearchClient:
    """FastAPI dependency returning the app-scoped read-only ProductionSearchClient."""
    client = getattr(request.app.state, "production_search_client", None)
    if client is None:
        client = ProductionSearchClient()
        request.app.state.production_search_client = client
    return client
