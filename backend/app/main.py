"""Independent General Search Platform & Search Admin FastAPI entrypoint.

Start independently from ``backend/``:
    uvicorn app.main:app --host 127.0.0.1 --port 8004

Zero runtime dependency on the legacy split Search AI microservice (port 8002),
original Product & Company Search internals, or BrochureIQ.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.routing import Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.clients.production_search_client import ProductionSearchClient
from app.config import (
    get_port,
    is_api_docs_enabled,
    resolve_allowed_origins,
    should_warmup_embedding_model_on_startup,
)
from app.db import auth_db, platform_db
from app.logger import logger
from app.repositories import observability_store
from app.routes.admin.observability import router as admin_observability_router
from app.routes.admin.platform import router as admin_platform_router
from app.routes.admin.production import router as admin_production_router
from app.routes.auth import router as auth_router
from app.routes.engines.public import router as public_engines_router
from app.routes.health import router as health_router
from app.services import admin_auth, embedding_model


async def _warmup_embedding_model_background(application: FastAPI) -> None:
    try:
        await asyncio.to_thread(embedding_model.warm_up_model)
        application.state.embedding_model_ready = True
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(
            "Embedding model startup warmup failed (exception_type=%s)",
            type(exc).__name__,
        )
        application.state.embedding_model_ready = False
        application.state.initialization_error = "Embedding model warmup failed"


class _HeadMatchesGetPolicyMiddleware:
    """Route ``HEAD`` requests through the matching ``GET`` handler and strip response bodies.

    Ensures every ``HEAD`` request enforces the exact same public or Admin
    authentication/authorization policy as its corresponding ``GET`` route while
    keeping POST-only routes returning HTTP 405 and keeping OpenAPI clean.
    """

    def __init__(self, app: ASGIApp, *, fastapi_app: FastAPI) -> None:
        self.app = app
        self.fastapi_app = fastapi_app

    def _matches_get_route(self, scope: Scope) -> bool:
        get_scope = {**scope, "method": "GET"}
        for route in self.fastapi_app.router.routes:
            match, _ = route.matches(get_scope)
            if match == Match.FULL:
                return True
        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("method") != "HEAD":
            await self.app(scope, receive, send)
            return

        if not self._matches_get_route(scope):
            await self.app(scope, receive, send)
            return

        get_scope: Scope = {
            **scope,
            "method": "GET",
            "original_http_method": "HEAD",
        }
        body_sent = False

        async def _send_without_body(message: Message) -> None:
            nonlocal body_sent
            if message["type"] == "http.response.body":
                if not body_sent:
                    body_sent = True
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
                return
            await send(message)

        await self.app(get_scope, receive, _send_without_body)


def create_app(
    *,
    production_search_client: ProductionSearchClient | None = None,
    warmup_embedding_model: bool | None = None,
    connect_platform_database: bool = True,
) -> FastAPI:
    """Construct the independent General Search Platform & Search Admin FastAPI app."""

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        if admin_auth.get_auth_provider().supports_local_login():
            auth_db.init_auth_db()
        if getattr(application.state, "production_search_client", None) is None:
            application.state.production_search_client = (
                production_search_client or ProductionSearchClient()
            )

        application.state.initialization_error = None
        application.state.initialization_task = None

        if connect_platform_database:
            try:
                platform_db.connect_platform_db()
                application.state.platform_db_ready = True
            except Exception as exc:
                application.state.platform_db_ready = False
                application.state.initialization_error = (
                    "General Search Platform database initialization failed"
                )
                logger.warning(
                    "Starting without connected platform database (exception_type=%s)",
                    type(exc).__name__,
                )
        else:
            ok, _, _ = platform_db.check_platform_db_ready()
            application.state.platform_db_ready = ok

        do_warmup = (
            should_warmup_embedding_model_on_startup()
            if warmup_embedding_model is None
            else bool(warmup_embedding_model)
        )
        if do_warmup:
            application.state.initialization_task = asyncio.create_task(
                _warmup_embedding_model_background(application)
            )
        else:
            cache_info_fn = getattr(embedding_model.get_model, "cache_info", None)
            application.state.embedding_model_ready = bool(
                callable(cache_info_fn) and cache_info_fn().currsize > 0
            )

        try:
            yield
        finally:
            init_task = getattr(application.state, "initialization_task", None)
            if init_task is not None and not init_task.done():
                init_task.cancel()
                try:
                    await init_task
                except asyncio.CancelledError:
                    pass
            client: ProductionSearchClient | None = getattr(
                application.state, "production_search_client", None
            )
            if client is not None:
                await client.aclose()

    docs_enabled = is_api_docs_enabled()
    application = FastAPI(
        title="BONC General Search Platform & Search Admin API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    application.state.production_search_client = (
        production_search_client or ProductionSearchClient()
    )
    application.state.platform_db_ready = False
    application.state.embedding_model_ready = False
    application.state.initialization_error = None
    application.state.initialization_task = None

    allowed_origins = resolve_allowed_origins()
    allow_credentials = bool(allowed_origins) and "*" not in allowed_origins
    application.add_middleware(
        _HeadMatchesGetPolicyMiddleware,
        fastapi_app=application,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Accept",
            "Authorization",
            "Content-Type",
            "X-CSRF-Token",
            "X-Request-Id",
            "X-Correlation-Id",
        ],
        expose_headers=["X-Request-Id", "X-Auth-Mode"],
    )

    @application.middleware("http")
    async def request_observability_middleware(request: Request, call_next):
        started_at = time.perf_counter()
        request_id = observability_store.get_or_create_request_id(request)
        path = request.url.path
        effective_method = str(
            request.scope.get("original_http_method") or request.method
        ).upper()
        should_record = path.startswith("/api/") and effective_method != "OPTIONS"

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
            logger.error(
                "%s %s -> 500 (%sms, request_id=%s)",
                effective_method,
                path,
                duration_ms,
                request_id,
            )
            if should_record:
                identity_type, authenticated_user_id, _ = (
                    observability_store.resolve_trusted_identity(request)
                )
                observability_store.safe_record_api_request_log(
                    request_id=request_id,
                    http_method=effective_method,
                    endpoint_template=observability_store.resolve_endpoint_template(
                        request
                    ),
                    http_status=500,
                    duration_ms=duration_ms,
                    identity_type=identity_type,
                    authenticated_user_id=authenticated_user_id,
                    error_code="unhandled_exception",
                )
            raise

        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        response.headers["X-Request-Id"] = request_id
        logger.info(
            "%s %s -> %s (%sms, request_id=%s)",
            effective_method,
            path,
            response.status_code,
            duration_ms,
            request_id,
        )
        if should_record:
            state_identity = getattr(request.state, "identity_type", None)
            state_user = getattr(request.state, "authenticated_user_id", None)
            if state_identity in {"authenticated", "anonymous", "session"}:
                identity_type = state_identity
                authenticated_user_id = state_user
            else:
                identity_type, authenticated_user_id, _ = (
                    observability_store.resolve_trusted_identity(request)
                )
            observability_store.safe_record_api_request_log(
                request_id=request_id,
                http_method=effective_method,
                endpoint_template=observability_store.resolve_endpoint_template(request),
                http_status=response.status_code,
                duration_ms=duration_ms,
                identity_type=identity_type,
                authenticated_user_id=authenticated_user_id,
                error_code=getattr(request.state, "observability_error_code", None),
            )
        return response

    application.include_router(health_router)
    application.include_router(auth_router)
    application.include_router(public_engines_router)
    application.include_router(admin_platform_router)
    application.include_router(admin_observability_router)
    application.include_router(admin_production_router)

    return application


PORT = get_port()
app = create_app()


if __name__ == "__main__":
    import uvicorn

    logger.info("BONC General Search Platform & Admin API listening on 127.0.0.1:%s", PORT)
    uvicorn.run("app.main:app", host="127.0.0.1", port=PORT)
