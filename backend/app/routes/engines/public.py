"""Public General Search Platform discovery and search routes (/api/platform/*)."""
from __future__ import annotations

import time

from fastapi import APIRouter, Header, HTTPException, Request

from app.logger import logger
from app.repositories import category_store, observability_store
from app.schemas.platform import PlatformSearchRequest
from app.services import platform_search

router = APIRouter(prefix="/api/platform", tags=["General Search Platform (Public)"])


def _set_request_observability_state(
    request: Request | None,
    *,
    identity_type: str,
    authenticated_user_id: str | None,
    error_code: str | None,
) -> None:
    if request is None:
        return
    request.state.identity_type = identity_type
    request.state.authenticated_user_id = authenticated_user_id
    if error_code is not None:
        request.state.observability_error_code = error_code


@router.get("/categories")
def public_categories():
    """Return active search categories explicitly opted into public search."""
    return [
        {
            "category_id": item["config"].category_id,
            "display_name": item["config"].display_name,
            "description": item["config"].description,
        }
        for item in category_store.list_categories(include_document_count=False)
        if (
            item["status"] == "active"
            and item["config"].active
            and item["config"].public_search_enabled
        )
    ]


@router.post("/search")
def public_platform_search(
    body: PlatformSearchRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Execute hybrid search against an active, publicly enabled category."""
    started_at = time.perf_counter()
    request_id = observability_store.get_or_create_request_id(request)
    identity_type, authenticated_user_id, session_id_hash = (
        observability_store.resolve_trusted_identity(
            request,
            authorization=authorization,
        )
    )
    http_status = 500
    result_count: int | None = None
    resolved_category_id: str | None = None
    config_version: int | None = None
    index_version: int | None = None
    error_code: str | None = None
    error_category: str | None = None

    try:
        category = category_store.get_category(body.category)
        resolved_category_id = category["config"].category_id
        config_version = category.get("config_version")
        index_version = category.get("index_version")
        if category["status"] != "active" or not category["config"].active:
            http_status = 404
            error_code = "category_not_found"
            error_category = "not_found"
            raise HTTPException(status_code=404, detail="Search category not found")
        if not category["config"].public_search_enabled:
            http_status = 403
            error_code = "category_not_public"
            error_category = "forbidden"
            raise HTTPException(
                status_code=403,
                detail="This search category is not publicly available",
            )
        result = platform_search.search_category(
            query=body.query,
            category_id=body.category,
            page=body.page,
            page_size=body.page_size,
            filters=[item.model_dump() for item in body.filters],
            category=category,
        )
        http_status = 200
        result_count = int(result.get("total_count", len(result.get("data", []))))
        config_version = result.get("config_version", config_version)
        index_version = result.get("index_version", index_version)
        return result
    except category_store.CategoryNotFoundError as exc:
        http_status = 404
        error_code = "category_not_found"
        error_category = "not_found"
        raise HTTPException(status_code=404, detail="Search category not found") from exc
    except ValueError as exc:
        http_status = 400
        error_code = "invalid_search_parameters"
        error_category = "validation"
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException as exc:
        http_status = exc.status_code
        raise
    except Exception as exc:
        http_status = 500
        error_code = "search_execution_error"
        error_category = "server_error"
        logger.error(
            "Public platform search failed (category=%s, exception_type=%s)",
            body.category,
            type(exc).__name__,
        )
        raise HTTPException(status_code=500, detail="Search request failed") from exc
    finally:
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        _set_request_observability_state(
            request,
            identity_type=identity_type,
            authenticated_user_id=authenticated_user_id,
            error_code=error_code,
        )
        if not getattr(request.state, "_search_log_recorded", False):
            request.state._search_log_recorded = True
            observability_store.safe_record_search_log(
                request_id=request_id,
                endpoint_path="/api/platform/search",
                search_surface="public",
                category_id=body.category,
                resolved_category_id=resolved_category_id,
                query=body.query,
                http_status=http_status,
                duration_ms=duration_ms,
                identity_type=identity_type,
                authenticated_user_id=authenticated_user_id,
                session_id_hash=session_id_hash,
                result_count=result_count,
                page_no=body.page,
                page_size=body.page_size,
                filter_count=len(body.filters),
                config_version=config_version,
                index_version=index_version,
                error_code=error_code,
                error_category=error_category,
            )
