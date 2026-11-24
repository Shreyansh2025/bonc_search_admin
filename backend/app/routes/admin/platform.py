"""Admin-protected General Search Platform management, source sync, and engine testing routes.

All endpoints enforce centralized Admin authorization via ``app.services.admin_auth``
(``AdminAuthProvider``). Per Stage 2 approved decisions:
  - Decision #1: Legacy Catalog Thresholds routes are excluded.
  - Decision #2: ``POST /api/admin/platform/search`` is retained for Generic Engine
    Testing and offline evaluation; ``POST /api/admin/platform/categories/{id}/feedback``
    is excluded, while read-only ``GET /api/admin/platform/categories/{id}/feedback``
    is preserved.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials

from app.logger import logger
from app.repositories import category_store, observability_store
from app.schemas.platform import (
    CATEGORY_ID_RE,
    CategoryConfig,
    CategoryRollbackRequest,
    CategoryUpdateRequest,
    IngestRequest,
    JoinViewPreviewRequest,
    PlatformSearchRequest,
    SourceValidationRequest,
)
from app.services import admin_auth, platform_search, source_sync

_require_sources_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_SOURCES_READ
)
_require_categories_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_CATEGORIES_READ
)
_require_categories_write = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_CATEGORIES_WRITE
)
_require_ingestion_write = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_INGESTION_WRITE
)
_require_analytics_read = admin_auth.require_admin_permission(
    admin_auth.ADMIN_PERMISSION_ANALYTICS_READ
)

router = APIRouter(
    prefix="/api/admin/platform",
    tags=["General Search Platform Admin"],
)


def _validate_category_id_path(category_id: str) -> str:
    cleaned = (category_id or "").strip().lower()
    if not CATEGORY_ID_RE.fullmatch(cleaned):
        raise HTTPException(status_code=422, detail="Invalid search category ID")
    return cleaned


def _not_found(exc: Exception) -> HTTPException:
    return HTTPException(status_code=404, detail="Search category not found")


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


@router.post("/search")
def admin_search_category(
    body: PlatformSearchRequest,
    request: Request,
    _bearer: HTTPAuthorizationCredentials | None = Depends(admin_auth.bearer_security_scheme),
):
    """Execute an Admin-authenticated search query against any configured category.

    Used by the Generic Search Engine Testing UI and automated evaluation tools.
    Supports private (non-public) categories and records persistent search logs.
    """
    started_at = time.perf_counter()
    request_id = observability_store.get_or_create_request_id(request)
    identity_type, authenticated_user_id, session_id_hash = (
        observability_store.resolve_trusted_identity(
            request,
            authorization=None,
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
        principal = admin_auth.authorize_admin_request(
            request,
            authorization=request.headers.get("authorization"),
            require_csrf=True,
            required_permission=admin_auth.ADMIN_PERMISSION_SEARCH_EXECUTE,
        )
        identity_type, authenticated_user_id, session_id_hash = (
            observability_store.resolve_trusted_identity(
                request,
                verified_admin_actor=principal.actor,
            )
        )
        result = platform_search.search_category(
            query=body.query,
            category_id=body.category,
            page=body.page,
            page_size=body.page_size,
            filters=[item.model_dump() for item in body.filters],
        )
        http_status = 200
        resolved_category_id = result.get("category") or body.category
        result_count = int(result.get("total_count", len(result.get("data", []))))
        config_version = result.get("config_version")
        index_version = result.get("index_version")
        return result
    except category_store.CategoryNotFoundError as exc:
        http_status = 404
        error_code = "category_not_found"
        error_category = "not_found"
        raise _not_found(exc) from exc
    except ValueError as exc:
        http_status = 400
        error_code = "invalid_search_parameters"
        error_category = "validation"
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException as exc:
        http_status = exc.status_code
        if exc.status_code == 401:
            error_code = "authentication_required"
            error_category = "auth"
        elif exc.status_code == 403:
            error_code = "forbidden"
            error_category = "forbidden"
        elif exc.status_code == 503:
            error_code = "admin_auth_unconfigured"
            error_category = "dependency_error"
        raise
    except Exception as exc:
        http_status = 500
        error_code = "search_execution_error"
        error_category = "server_error"
        logger.error(
            "Admin platform search failed (category=%s, exception_type=%s)",
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
                endpoint_path="/api/admin/platform/search",
                search_surface="admin",
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


@router.get("/sources")
def admin_list_source_profiles(
    _principal: admin_auth.AdminPrincipal = Depends(_require_sources_read),
):
    """List reusable server-configured SQL source profiles without returning secrets."""
    return {"items": source_sync.list_source_profiles()}


@router.get("/sources/{profile_id}/schema")
def admin_discover_source_schema(
    profile_id: str,
    schema: str | None = Query(default=None, min_length=1, max_length=128),
    _principal: admin_auth.AdminPrincipal = Depends(_require_sources_read),
):
    """Test a named SQL source profile and discover schemas, tables, columns & FKs."""
    try:
        return source_sync.discover_source_schema(profile_id, schema=schema)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning(
            "SQL source schema discovery failed (profile_id=%s, exception_type=%s)",
            profile_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to inspect this SQL source. Check that the profile is valid and has metadata/read access.",
        ) from exc


@router.get("/sources/{profile_id}/mapping-suggestions")
def admin_suggest_source_mapping(
    profile_id: str,
    schema: str = Query(..., min_length=1, max_length=128),
    table: str = Query(..., min_length=1, max_length=128),
    _principal: admin_auth.AdminPrincipal = Depends(_require_sources_read),
):
    """Suggest document ID and field mappings for one discovered SQL table or view."""
    try:
        return source_sync.suggest_source_mapping(
            profile_id,
            schema=schema,
            table=table,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning(
            "SQL source mapping suggestion failed (profile_id=%s, exception_type=%s)",
            profile_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to generate source mapping suggestions. Check source metadata permissions.",
        ) from exc


@router.post("/sources/{profile_id}/join-view-preview")
def admin_preview_join_view(
    profile_id: str,
    body: JoinViewPreviewRequest,
    _principal: admin_auth.AdminPrincipal = Depends(_require_sources_read),
):
    """Generate a reviewable SQL Server view script without executing database DDL."""
    try:
        return source_sync.generate_join_view_preview(
            profile_id,
            base_schema=body.base_schema,
            base_table=body.base_table,
            base_id_column=body.base_id_column,
            view_schema=body.view_schema,
            view_name=body.view_name,
            selected_relationships=[
                relationship.model_dump() for relationship in body.selected_relationships
            ],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning(
            "SQL join view preview failed (profile_id=%s, exception_type=%s)",
            profile_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to generate the view preview from this database schema.",
        ) from exc


@router.post("/sources/{profile_id}/validate")
def admin_validate_source(
    profile_id: str,
    body: SourceValidationRequest,
    _principal: admin_auth.AdminPrincipal = Depends(_require_sources_read),
):
    """Check source row counts and verify that the chosen document ID is unique and non-null."""
    try:
        return source_sync.validate_sqlserver_source(
            profile_id,
            schema=body.schema,
            table=body.table,
            id_column=body.id_column,
            filters=body.filters,
            max_records=body.max_records,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning(
            "SQL source validation failed (profile_id=%s, exception_type=%s)",
            profile_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to validate this source. Check the selected table, ID column and source permissions.",
        ) from exc


@router.get("/categories")
def admin_list_categories(
    _principal: admin_auth.AdminPrincipal = Depends(_require_categories_read),
):
    """List all configured General Search Platform categories with document counts."""
    return category_store.list_categories()


@router.post("/categories", status_code=201)
def admin_create_category(
    body: CategoryConfig,
    principal: admin_auth.AdminPrincipal = Depends(_require_categories_write),
):
    """Create a new configurable search engine category and record v1 history."""
    try:
        return category_store.create_category(body, updated_by=principal.actor)
    except category_store.CategoryAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail="Category ID already exists") from exc
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        logger.error(
            "Create search category failed (category_id=%s, exception_type=%s)",
            body.category_id,
            type(exc).__name__,
        )
        raise HTTPException(status_code=500, detail="Unable to create category") from exc


@router.put("/categories/{category_id}")
def admin_update_category(
    category_id: str,
    body: CategoryUpdateRequest,
    principal: admin_auth.AdminPrincipal = Depends(_require_categories_write),
):
    """Update category configuration with optimistic concurrency and cache invalidation."""
    if body.config.category_id != category_id:
        raise HTTPException(
            status_code=422,
            detail="URL category_id must match config.category_id",
        )
    try:
        result = category_store.update_category(
            body.config,
            expected_version=body.expected_version,
            updated_by=principal.actor,
            change_reason=body.change_reason,
        )
        platform_search.invalidate_category_index(category_id)
        return result
    except category_store.CategoryNotFoundError as exc:
        raise _not_found(exc) from exc
    except category_store.CategoryStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/categories/{category_id}/rollback")
def admin_rollback_category(
    category_id: str,
    body: CategoryRollbackRequest,
    principal: admin_auth.AdminPrincipal = Depends(_require_categories_write),
):
    """Atomically restore a historical configuration version as a new version."""
    validated_category_id = _validate_category_id_path(category_id)
    try:
        result = category_store.rollback_category(
            validated_category_id,
            target_version=body.target_version,
            expected_version=body.expected_version,
            updated_by=principal.actor,
            reason=body.reason,
        )
        platform_search.invalidate_category_index(validated_category_id)
        return result
    except category_store.CategoryNotFoundError as exc:
        raise _not_found(exc) from exc
    except category_store.CategoryHistoryNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except category_store.CategoryVersionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except category_store.CategoryStoreError as exc:
        logger.error(
            "Search category rollback failed (category_id=%s, exception_type=%s)",
            validated_category_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=500, detail="Unable to roll back category configuration"
        ) from exc


@router.get("/categories/{category_id}/feedback")
def admin_get_category_feedback(
    category_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    _principal: admin_auth.AdminPrincipal = Depends(_require_analytics_read),
):
    """Read-only retrieval of historical relevance feedback judgments for one category."""
    try:
        return category_store.get_feedback(category_id, limit=limit)
    except category_store.CategoryNotFoundError as exc:
        raise _not_found(exc) from exc


@router.get("/categories/{category_id}/history")
def admin_category_history(
    category_id: str,
    _principal: admin_auth.AdminPrincipal = Depends(_require_categories_read),
):
    """Return immutable version history for one search category."""
    try:
        return {"items": category_store.get_category_history(category_id)}
    except category_store.CategoryNotFoundError as exc:
        raise _not_found(exc) from exc


@router.post("/categories/{category_id}/ingest")
def admin_ingest_documents(
    category_id: str,
    body: IngestRequest,
    principal: admin_auth.AdminPrincipal = Depends(_require_ingestion_write),
):
    """Push-ingest documents into a category and invalidate its cached index."""
    try:
        category = category_store.get_category(category_id)
        category_config = category["config"]
        allowed_fields = {field.key for field in category_config.fields}
        for document in body.documents:
            unknown_fields = set(document.fields) - allowed_fields
            if unknown_fields:
                raise ValueError(
                    "Document contains fields not configured for this category: "
                    + ", ".join(sorted(unknown_fields))
                )
        count = category_store.replace_documents(
            category_id,
            body.documents,
            updated_by=principal.actor,
            replace_all=body.replace_all,
        )
        platform_search.invalidate_category_index(category_id)
        return {"status": "ok", "category_id": category_id, "documents_ingested": count}
    except category_store.CategoryNotFoundError as exc:
        raise _not_found(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/categories/{category_id}/sync")
def admin_sync_category(
    category_id: str,
    principal: admin_auth.AdminPrincipal = Depends(_require_ingestion_write),
):
    """Preflight and synchronize documents from a category's configured SQL Server source."""
    try:
        category = category_store.get_category(category_id)
        count = source_sync.sync_sqlserver_category(
            category["config"], updated_by=principal.actor
        )
        platform_search.invalidate_category_index(category_id)
        return {"status": "ok", "category_id": category_id, "documents_synced": count}
    except category_store.CategoryNotFoundError as exc:
        raise _not_found(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.error(
            "Search category source sync failed (category_id=%s, exception_type=%s)",
            category_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to synchronize this SQL source. Check source availability and read permissions.",
        ) from exc
