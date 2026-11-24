"""Centralized Search Admin BONC authentication session verification route."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials

from app.services import admin_auth

router = APIRouter(prefix="/api/admin/auth", tags=["Search Admin authentication"])


def _apply_no_store(response: Response, *, auth_mode: str | None = None) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if auth_mode:
        response.headers["X-Auth-Mode"] = auth_mode


@router.get("/session")
def admin_get_session(
    request: Request,
    response: Response,
    _bearer: HTTPAuthorizationCredentials | None = Depends(admin_auth.bearer_security_scheme),
):
    """Validate the caller's BONC Bearer token and return verified Admin identity & permissions."""
    provider = admin_auth.get_auth_provider()
    _apply_no_store(response, auth_mode=provider.auth_mode)
    raw_authorization = request.headers.get("authorization")
    try:
        principal = admin_auth.authorize_admin_request(
            request,
            authorization=raw_authorization,
        )
    except HTTPException as exc:
        headers = dict(exc.headers or {})
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault("Pragma", "no-cache")
        headers.setdefault("X-Auth-Mode", provider.auth_mode)
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
    }
