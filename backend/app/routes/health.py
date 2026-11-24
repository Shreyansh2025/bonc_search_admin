"""Liveness and readiness probes for the independent General Search Platform & Admin Backend.

Zero runtime dependency on the old split Search AI microservice (port 8002) or
the optional read-only production observability client.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.clients.production_search_client import (
    ProductionSearchClient,
    get_production_search_client,
)
from app.db import platform_db
from app.services import admin_auth, embedding_model

router = APIRouter(tags=["Search Platform health"])


@router.get("/health/live")
async def liveness():
    return {"status": "ok", "service": "search-admin-platform"}


@router.get("/health/ready")
async def readiness(
    request: Request,
    production_client: ProductionSearchClient = Depends(get_production_search_client),
):
    provider = admin_auth.get_auth_provider()
    auth_provider_ok = provider.is_configured()
    auth_provider_state = "ready" if auth_provider_ok else "not_configured"

    platform_db_ok, platform_db_latency_ms, _ = platform_db.check_platform_db_ready()

    init_error = getattr(request.app.state, "initialization_error", None)
    init_task = getattr(request.app.state, "initialization_task", None)
    init_in_progress = bool(init_task is not None and not init_task.done())
    model_ready = bool(getattr(request.app.state, "embedding_model_ready", False))
    cache_info_fn = getattr(embedding_model.get_model, "cache_info", None)
    model_loaded = bool(cache_info_fn().currsize > 0) if callable(cache_info_fn) else model_ready

    if model_ready or model_loaded:
        embedding_state = "ready"
    elif init_error and platform_db_ok:
        embedding_state = "failed"
    elif init_in_progress:
        embedding_state = "warming"
    else:
        embedding_state = "lazy"

    ready = auth_provider_ok and platform_db_ok and embedding_state != "failed"
    body = {
        "status": "ready" if ready else "not_ready",
        "service": "search-admin-platform",
        "checks": {
            "authMode": provider.auth_mode,
            "authProvider": auth_provider_state,
            "platformDatabase": "ready" if platform_db_ok else "not_ready",
            "platformDatabaseLatencyMs": platform_db_latency_ms,
            "embeddingModel": embedding_state,
            "productionObservability": (
                "enabled" if production_client.is_enabled() else "disabled"
            ),
        },
    }
    return JSONResponse(status_code=200 if ready else 503, content=body)
