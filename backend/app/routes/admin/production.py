"""Admin-protected, read-only optional Production Product & Company Search observability routes.

Disabled by default (``PRODUCTION_OBSERVABILITY_ENABLED=false``). Never executes
any write operation against production and unconditionally excludes BrochureIQ
(``localProducts``) data.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.clients.production_search_client import (
    ProductionSearchClient,
    get_production_search_client,
)
from app.repositories import observability_store
from app.services import admin_auth

router = APIRouter(
    prefix="/api/admin/production",
    tags=["Production Search Observability (Read-Only)"],
)

_require_production_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_PRODUCTION_READ
)


@router.get("/health")
async def admin_get_production_health(
    request: Request,
    _principal: admin_auth.AdminPrincipal = Depends(_require_production_read),
    production_client: ProductionSearchClient = Depends(get_production_search_client),
):
    """Read-only proxy for original production ``GET /api/healthz`` (disabled by default)."""
    request_id = observability_store.get_or_create_request_id(request)
    return await production_client.get_health(request_id=request_id)


@router.get("/index-status")
async def admin_get_production_index_status(
    request: Request,
    _principal: admin_auth.AdminPrincipal = Depends(_require_production_read),
    production_client: ProductionSearchClient = Depends(get_production_search_client),
):
    """Read-only proxy for original production ``GET /api/debug/index-status`` (BrochureIQ stripped)."""
    request_id = observability_store.get_or_create_request_id(request)
    return await production_client.get_index_status(request_id=request_id)
