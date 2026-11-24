"""Centralized Search Admin authentication routes: session status and local-dev login/logout."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from app.logger import logger
from app.schemas.auth import AdminLoginRequest
from app.services import admin_auth

router = APIRouter(prefix="/api/admin/auth", tags=["Search Admin authentication"])

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


def _apply_no_store(response: Response, *, auth_mode: str | None = None) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if auth_mode:
        response.headers["X-Auth-Mode"] = auth_mode


@router.post("/login")
def admin_login(
    body: AdminLoginRequest,
    request: Request,
    response: Response,
):
    """Authenticate a local development administrator (disabled when BONC auth is active)."""
    provider = admin_auth.get_auth_provider()
    _apply_no_store(response, auth_mode=provider.auth_mode)

    if not provider.supports_local_login():
        raise HTTPException(
            status_code=404,
            detail="Local Search Admin login is disabled. Sign in through BONC.",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        )

    if not admin_auth.is_admin_login_configured():
        raise HTTPException(
            status_code=503,
            detail="Admin authentication is not configured",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        )

    client_ip = admin_auth.extract_client_ip(request)
    try:
        allowed, retry_after = admin_auth.check_login_rate_limit(client_ip)
    except admin_auth.AdminAuthStorageError as exc:
        raise HTTPException(
            status_code=503,
            detail="Admin authentication service is unavailable",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        ) from exc

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
            headers={
                "Retry-After": str(retry_after),
                **_NO_STORE_HEADERS,
                "X-Auth-Mode": provider.auth_mode,
            },
        )

    try:
        matched_username = admin_auth.verify_admin_credentials(
            body.username,
            body.password,
        )
    except admin_auth.AdminAuthNotConfiguredError as exc:
        raise HTTPException(
            status_code=503,
            detail="Admin authentication is not configured",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        ) from exc

    if matched_username is None:
        try:
            admin_auth.record_login_attempt(client_ip, succeeded=False)
        except admin_auth.AdminAuthStorageError:
            pass
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        )

    existing_cookie = (request.cookies.get(admin_auth.SESSION_COOKIE_NAME) or "").strip()
    if existing_cookie:
        try:
            admin_auth.revoke_session_by_token(existing_cookie, reason="login_rotation")
        except admin_auth.AdminAuthStorageError:
            pass

    ttl = admin_auth.session_ttl_seconds()
    try:
        admin_auth.record_login_attempt(client_ip, succeeded=True)
        raw_token, session = admin_auth.create_session(
            matched_username,
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent"),
            ttl_seconds=ttl,
        )
    except admin_auth.AdminAuthStorageError as exc:
        raise HTTPException(
            status_code=503,
            detail="Admin authentication service is unavailable",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        ) from exc

    admin_auth.set_session_cookie(response, raw_token, max_age=ttl, request=request)
    request.state.authenticated_user_id = session.username
    request.state.identity_type = "authenticated"
    request.state.admin_auth_method = "session"
    request.state.admin_session_id = session.session_id

    logger.info(
        "Admin login succeeded (actor=%s, request_id=%s)",
        session.username,
        getattr(request.state, "request_id", None),
    )

    return {
        "authenticated": True,
        "auth_method": "session",
        "auth_mode": provider.auth_mode,
        "user_id": None,
        "username": session.username,
        "actor": session.username,
        "roles": ["admin"],
        "permissions": sorted(admin_auth.ALL_ADMIN_PERMISSIONS),
        "expires_at_utc": admin_auth.format_utc_iso(session.expires_at_utc),
        "csrf_token": session.csrf_token,
        "local_login_enabled": True,
    }


@router.get("/session")
def admin_get_session(
    request: Request,
    response: Response,
    _bearer: HTTPAuthorizationCredentials | None = Depends(admin_auth.bearer_security_scheme),
):
    """Validate the active Admin identity (BONC Bearer token or local-dev session)."""
    provider = admin_auth.get_auth_provider()
    _apply_no_store(response, auth_mode=provider.auth_mode)
    raw_authorization = request.headers.get("authorization")
    try:
        principal = admin_auth.authorize_admin_request(
            request,
            authorization=raw_authorization,
            require_csrf=False,
            allow_service_token=provider.supports_local_login(),
        )
    except HTTPException as exc:
        headers = dict(exc.headers or {})
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault("Pragma", "no-cache")
        headers.setdefault("X-Auth-Mode", provider.auth_mode)
        if (
            exc.status_code == 401
            and provider.supports_local_login()
            and request.cookies.get(admin_auth.SESSION_COOKIE_NAME)
        ):
            cleared = JSONResponse(
                status_code=401,
                content={"detail": exc.detail},
                headers=headers,
            )
            admin_auth.clear_session_cookie(cleared, request=request)
            return cleared
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.detail,
            headers=headers,
        ) from exc

    return {
        "authenticated": True,
        "auth_method": principal.auth_method,
        "auth_mode": provider.auth_mode,
        "user_id": principal.user_id,
        "username": principal.username,
        "actor": principal.actor,
        "roles": list(principal.roles),
        "permissions": list(principal.permissions),
        "expires_at_utc": admin_auth.format_utc_iso(principal.expires_at_utc),
        "csrf_token": principal.csrf_token,
        "local_login_enabled": provider.supports_local_login(),
    }


@router.post("/logout")
def admin_logout(
    request: Request,
    response: Response,
    _bearer: HTTPAuthorizationCredentials | None = Depends(admin_auth.bearer_security_scheme),
):
    """Revoke a local-dev admin session (disabled in BONC mode where BONC owns logout)."""
    provider = admin_auth.get_auth_provider()
    _apply_no_store(response, auth_mode=provider.auth_mode)

    if not provider.supports_local_login():
        raise HTTPException(
            status_code=404,
            detail="Local Search Admin logout is disabled. Sign out through BONC.",
            headers={**_NO_STORE_HEADERS, "X-Auth-Mode": provider.auth_mode},
        )

    raw_authorization = request.headers.get("authorization")
    principal = admin_auth.authorize_admin_request(
        request,
        authorization=raw_authorization,
        require_csrf=True,
    )

    if principal.session_id:
        try:
            admin_auth.revoke_session_by_id(principal.session_id, reason="logout")
        except admin_auth.AdminAuthStorageError as exc:
            raise HTTPException(
                status_code=503,
                detail="Admin authentication service is unavailable",
            ) from exc

    admin_auth.clear_session_cookie(response, request=request)
    logger.info(
        "Admin logout completed (actor=%s, request_id=%s)",
        principal.actor,
        getattr(request.state, "request_id", None),
    )
    return {
        "authenticated": False,
        "status": "logged_out",
    }
