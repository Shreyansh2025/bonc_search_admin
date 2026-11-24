"""Admin-protected General Search Platform observability, KPI, API failure & relevance routes."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.clients.production_search_client import (
    ProductionSearchClient,
    get_production_search_client,
)
from app.logger import logger
from app.repositories import observability_store
from app.services import admin_auth

router = APIRouter(
    prefix="/api/admin/platform",
    tags=["General Search Platform Observability"],
)

_require_health_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_HEALTH_READ
)
_require_logs_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_LOGS_READ
)
_require_analytics_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_ANALYTICS_READ
)


def _handle_observability_error(exc: Exception, operation: str) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, RuntimeError):
        logger.error(
            "Platform observability %s unavailable (exception_type=%s)",
            operation,
            type(exc).__name__,
        )
        return HTTPException(
            status_code=503,
            detail="Search Platform observability storage is unavailable",
        )
    logger.error(
        "Platform observability %s failed (exception_type=%s)",
        operation,
        type(exc).__name__,
    )
    return HTTPException(
        status_code=500,
        detail="Unable to load Search Platform observability metrics",
    )


@router.get("/system-health")
async def admin_get_system_health(
    request: Request,
    recent_failures_limit: int = Query(default=10, ge=1, le=50),
    _principal: admin_auth.AdminPrincipal = Depends(_require_health_read),
    production_client: ProductionSearchClient = Depends(get_production_search_client),
):
    """Return live health for API, platform DB, embedding model, categories, 5xx & optional prod status."""
    request_id = observability_store.get_or_create_request_id(request)
    production_snapshot = await production_client.get_index_status(request_id=request_id)
    try:
        return observability_store.get_system_health(
            request.app.state,
            recent_failures_limit=recent_failures_limit,
            production_snapshot=production_snapshot,
        )
    except Exception as exc:
        raise _handle_observability_error(exc, "system_health") from exc


@router.get("/search-logs")
def admin_list_search_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    start_utc: str | None = Query(default=None, max_length=64),
    end_utc: str | None = Query(default=None, max_length=64),
    user_id: str | None = Query(default=None, max_length=256),
    identity_type: Literal["authenticated", "anonymous", "session"] | None = Query(
        default=None
    ),
    category: str | None = Query(default=None, max_length=64),
    query: str | None = Query(default=None, max_length=500),
    status_code: int | None = Query(default=None, ge=100, le=599),
    status_class: Literal["2xx", "4xx", "5xx"] | None = Query(default=None),
    outcome: Literal[
        "success", "zero_results", "client_error", "server_error", "failed"
    ]
    | None = Query(default=None),
    zero_results_only: bool = Query(default=False),
    failed_only: bool = Query(default=False),
    surface: Literal["public", "admin"] | None = Query(default=None),
    _principal: admin_auth.AdminPrincipal = Depends(_require_logs_read),
):
    """Return paginated persistent search logs with filtering and matching summary totals."""
    try:
        return observability_store.query_search_logs(
            page=page,
            page_size=page_size,
            start_utc=start_utc,
            end_utc=end_utc,
            user_id=user_id,
            identity_type=identity_type,
            category=category,
            query=query,
            status_code=status_code,
            status_class=status_class,
            outcome=outcome,
            zero_results_only=zero_results_only,
            failed_only=failed_only,
            surface=surface,
        )
    except Exception as exc:
        raise _handle_observability_error(exc, "search_logs") from exc


@router.get("/search-logs/users")
def admin_search_attempts_per_user(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    start_utc: str | None = Query(default=None, max_length=64),
    end_utc: str | None = Query(default=None, max_length=64),
    category: str | None = Query(default=None, max_length=64),
    user_id: str | None = Query(default=None, max_length=256),
    _principal: admin_auth.AdminPrincipal = Depends(_require_logs_read),
):
    """Return search attempts grouped per authenticated user along with unique-user totals."""
    try:
        return observability_store.get_search_attempts_per_user(
            page=page,
            page_size=page_size,
            start_utc=start_utc,
            end_utc=end_utc,
            category=category,
            user_id=user_id,
        )
    except Exception as exc:
        raise _handle_observability_error(exc, "search_attempts_per_user") from exc


@router.get("/metrics/kpis")
def admin_get_kpi_metrics(
    start_utc: str | None = Query(default=None, max_length=64),
    end_utc: str | None = Query(default=None, max_length=64),
    category: str | None = Query(default=None, max_length=64),
    top_endpoints_limit: int = Query(default=10, ge=1, le=50),
    recent_failures_limit: int = Query(default=20, ge=1, le=100),
    _principal: admin_auth.AdminPrincipal = Depends(_require_analytics_read),
):
    """Return backend-calculated Search KPIs, API 5xx failure monitoring, and feedback summary."""
    try:
        return observability_store.get_kpi_metrics(
            start_utc=start_utc,
            end_utc=end_utc,
            category=category,
            top_endpoints_limit=top_endpoints_limit,
            recent_failures_limit=recent_failures_limit,
        )
    except Exception as exc:
        raise _handle_observability_error(exc, "kpis") from exc


@router.get("/metrics/api-failures")
def admin_get_api_failure_metrics(
    start_utc: str | None = Query(default=None, max_length=64),
    end_utc: str | None = Query(default=None, max_length=64),
    endpoint: str | None = Query(default=None, max_length=200),
    top_endpoints_limit: int = Query(default=10, ge=1, le=50),
    recent_failures_limit: int = Query(default=20, ge=1, le=100),
    _principal: admin_auth.AdminPrincipal = Depends(_require_analytics_read),
):
    """Return API request volume, 4xx vs 5xx separation, 5xx failure rate, and top failing endpoints."""
    try:
        return observability_store.get_api_failure_metrics(
            start_utc=start_utc,
            end_utc=end_utc,
            endpoint=endpoint,
            top_endpoints_limit=top_endpoints_limit,
            recent_failures_limit=recent_failures_limit,
        )
    except Exception as exc:
        raise _handle_observability_error(exc, "api_failures") from exc


@router.get("/metrics/relevance")
def admin_get_relevance_metrics(
    start_utc: str | None = Query(default=None, max_length=64),
    end_utc: str | None = Query(default=None, max_length=64),
    category: str | None = Query(default=None, max_length=64),
    recent_negative_limit: int = Query(default=20, ge=1, le=100),
    _principal: admin_auth.AdminPrincipal = Depends(_require_analytics_read),
):
    """Return feedback-derived relevance & rejection metrics from searchai.SearchFeedback."""
    try:
        return observability_store.get_relevance_metrics(
            start_utc=start_utc,
            end_utc=end_utc,
            category=category,
            recent_negative_limit=recent_negative_limit,
        )
    except Exception as exc:
        raise _handle_observability_error(exc, "relevance_metrics") from exc
