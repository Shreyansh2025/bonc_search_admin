"""Centralized Search Admin authentication — BONC JWT (``getUserDetail``) ONLY.

Architecture:
- BONC JWT verification via BONC's ``GET /api/userService/getUserDetail``
  endpoint is the sole supported Search Admin user authentication mechanism.
- There is no local username/password login, no local auth database, no session
  cookies, no CSRF flow, no alternative verification mode, and no auth bypass.
- All Admin routes depend on ``require_admin_principal`` /
  ``require_admin_permission`` / ``authorize_admin_request``.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import (
    get_bonc_auth_admin_roles,
    get_bonc_auth_cache_seconds,
    get_bonc_auth_timeout_seconds,
    get_bonc_auth_verify_url,
)
from app.logger import logger
from app.services.bonc_auth import (
    ADMIN_PERMISSION_ANALYTICS_READ,
    ADMIN_PERMISSION_CATEGORIES_READ,
    ADMIN_PERMISSION_CATEGORIES_WRITE,
    ADMIN_PERMISSION_HEALTH_READ,
    ADMIN_PERMISSION_INGESTION_WRITE,
    ADMIN_PERMISSION_LOGS_READ,
    ADMIN_PERMISSION_PRODUCTION_READ,
    ADMIN_PERMISSION_SEARCH_EXECUTE,
    ADMIN_PERMISSION_SOURCES_READ,
    ALL_ADMIN_PERMISSIONS,
    AdminAuthProvider,
    AdminPrincipal,
    BoncAuthorizationDeniedError,
    BoncAuthNotConfiguredError,
    BoncAuthUnavailableError,
    BoncClaimsValidationConfig,
    BoncJwtAuthProvider,
    BoncRoleAuthorizationPolicy,
    BoncTokenExtractionError,
    BoncTokenInvalidError,
    BoncTokenVerifier,
    VerifiedBoncIdentity,
    attach_request_principal,
)
from app.services.bonc_auth_adapter import (
    BoncUserDetailVerifierAdapter,
    CachedBoncTokenVerifier,
    UserDetailAuth,
    build_bonc_user_detail_provider,
)

# OpenAPI security scheme declaration (Authorization: Bearer <AuthToken>).
# auto_error=False ensures BoncJwtAuthProvider inspects the raw Authorization
# header directly and rejects missing/malformed headers fail-closed with 401.
bearer_security_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BoncBearerAuth",
    bearerFormat="JWT",
    description="BONC-issued Bearer access token (`Authorization: Bearer <AuthToken>`).",
)

_attach_request_principal = attach_request_principal


def format_utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    dt = value
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


# ---------------------------------------------------------------------------
# Provider lifecycle (single BONC getUserDetail provider + test override hook)
# ---------------------------------------------------------------------------

_custom_provider: AdminAuthProvider | None = None
_default_provider_lock = threading.Lock()
_cached_bonc_provider_key: tuple[object, ...] | None = None
_cached_bonc_provider: BoncJwtAuthProvider | None = None


def build_default_auth_provider() -> BoncJwtAuthProvider:
    """Build (and cache per active config) the sole BONC ``getUserDetail`` provider.

    Fails closed (HTTP 503) when ``BONC_AUTH_VERIFY_URL`` is unset.
    """
    verify_url = get_bonc_auth_verify_url()
    if not verify_url:
        return BoncJwtAuthProvider(
            verifier=None,
            claims_config=None,
            role_policy=None,
        )

    admin_roles = get_bonc_auth_admin_roles()
    timeout = get_bonc_auth_timeout_seconds()
    cache_seconds = get_bonc_auth_cache_seconds()
    config_key = (verify_url, admin_roles, timeout, cache_seconds)

    global _cached_bonc_provider_key, _cached_bonc_provider
    with _default_provider_lock:
        if _cached_bonc_provider is not None and _cached_bonc_provider_key == config_key:
            return _cached_bonc_provider
        provider = build_bonc_user_detail_provider(
            verify_url=verify_url,
            admin_roles=admin_roles,
            timeout=timeout,
            cache_seconds=cache_seconds,
        )
        _cached_bonc_provider_key = config_key
        _cached_bonc_provider = provider
        logger.info(
            "BONC admin authentication configured (verify_url=%s, cache_seconds=%g)",
            verify_url,
            cache_seconds,
        )
        return provider


def validate_startup_auth_config() -> None:
    """Validate configured BONC ``getUserDetail`` settings eagerly at app startup.

    Invalid ``BONC_AUTH_VERIFY_URL`` (e.g. non-HTTPS remote URL), empty
    ``BONC_AUTH_ADMIN_ROLES``, or invalid timeout/cache settings fail startup
    with ``ValueError``. Unset ``BONC_AUTH_VERIFY_URL`` leaves the app
    fail-closed (HTTP 503) on all Admin endpoints.
    """
    if _custom_provider is not None:
        return
    if get_bonc_auth_verify_url():
        build_default_auth_provider()


def get_auth_provider() -> AdminAuthProvider:
    if _custom_provider is not None:
        return _custom_provider
    return build_default_auth_provider()


def set_auth_provider(provider: AdminAuthProvider) -> None:
    """Inject an explicit authentication provider (intended for automated tests)."""
    global _custom_provider
    _custom_provider = provider


def reset_auth_provider() -> None:
    """Clear any injected provider and cached default BONC verifier."""
    global _custom_provider, _cached_bonc_provider_key, _cached_bonc_provider
    _custom_provider = None
    with _default_provider_lock:
        _cached_bonc_provider_key = None
        _cached_bonc_provider = None


# ---------------------------------------------------------------------------
# Centralized request authorization & FastAPI dependencies
# ---------------------------------------------------------------------------


def authorize_admin_request(
    request: Request | None = None,
    *,
    authorization: str | None = None,
    required_permission: str | None = None,
) -> AdminPrincipal:
    return get_auth_provider().authorize_permission(
        request,
        authorization=authorization,
        required_permission=required_permission,
    )


def try_resolve_public_authenticated_user(
    request: Request | None = None,
    *,
    authorization: str | None = None,
) -> str | None:
    """Optionally resolve a verified BONC user ID on public routes (never trusts spoofed headers)."""
    return get_auth_provider().try_authenticate_public_request(
        request,
        authorization=authorization,
    )


def require_admin_principal(
    request: Request,
    _bearer: HTTPAuthorizationCredentials | None = Depends(bearer_security_scheme),
) -> AdminPrincipal:
    """Central FastAPI dependency enforcing BONC Admin authentication on Admin routes."""
    return authorize_admin_request(
        request,
        authorization=request.headers.get("authorization"),
    )


def require_admin_permission(permission: str) -> Callable[..., AdminPrincipal]:
    """Dependency factory enforcing BONC authentication and an explicit Search_Admin capability."""

    def _dependency(
        request: Request,
        _bearer: HTTPAuthorizationCredentials | None = Depends(bearer_security_scheme),
    ) -> AdminPrincipal:
        return authorize_admin_request(
            request,
            authorization=request.headers.get("authorization"),
            required_permission=permission,
        )

    return _dependency


def require_admin_actor(
    request: Request | None = None,
    *,
    authorization: str | None = None,
    required_permission: str | None = None,
) -> str:
    return authorize_admin_request(
        request,
        authorization=authorization,
        required_permission=required_permission,
    ).actor
