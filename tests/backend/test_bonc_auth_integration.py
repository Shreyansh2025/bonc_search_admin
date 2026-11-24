"""Comprehensive BONC JWT authorization, RBAC capability, route protection & regression tests."""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db import platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import admin_auth, bonc_auth, embedding_model, platform_search  # noqa: E402


class _TestOnlyStubBoncVerifier(bonc_auth.BoncTokenVerifier):
    """Isolated test-only verifier for RBAC, route protection, and claim invariant tests."""

    def __init__(self, identities: dict[str, bonc_auth.VerifiedBoncIdentity], *, unavailable: bool = False) -> None:
        self._identities = dict(identities)
        self._unavailable = unavailable

    def is_configured(self) -> bool:
        return True

    def verify_access_token(self, raw_token: str) -> bonc_auth.VerifiedBoncIdentity:
        if self._unavailable:
            raise bonc_auth.BoncAuthUnavailableError("BONC getUserDetail timed out")
        identity = self._identities.get(raw_token)
        if identity is None:
            raise bonc_auth.BoncTokenInvalidError("Token invalid or revoked")
        return identity


class _TinyEmbeddingModel:
    def encode(self, texts: list[str], convert_to_numpy: bool = True, batch_size: int = 64):
        arr = np.zeros((len(texts), embedding_model.EMBEDDING_DIM), dtype="float32")
        arr[:, 0] = 1.0
        return arr


def _sample_category(category_id: str = "people", *, public: bool = False) -> dict:
    return {
        "category_id": category_id,
        "display_name": category_id.title(),
        "description": f"{category_id.title()} directory",
        "source": {"type": "push"},
        "fields": [
            {
                "key": "title",
                "source_column": "Title",
                "label": "Title",
                "role": "title",
                "weight": 4.0,
                "searchable": True,
                "semantic": False,
                "aliases": [],
            }
        ],
        "active": True,
        "public_search_enabled": public,
    }


class TestBoncAuthIntegrationAndRouteProtection(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["APP_ENV"] = "local"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        for key in (
            "BONC_AUTH_VERIFY_URL",
            "BONC_AUTH_ADMIN_ROLES",
            "BONC_AUTH_CACHE_SECONDS",
            "BONC_AUTH_TIMEOUT",
            "SEARCH_ADMIN_ENABLE_API_DOCS",
            "PRODUCTION_SEARCH_AUTH_TOKEN",
        ):
            os.environ.pop(key, None)

        platform_db.reset_platform_engine()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

        self._model_patch = patch(
            "app.services.platform_search.get_model", return_value=_TinyEmbeddingModel()
        )
        self._model_patch.start()

        self.identities: dict[str, bonc_auth.VerifiedBoncIdentity] = {
            "tok-admin": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-admin-55",
                username="priya@bonc",
                expires_at_utc=None,
                roles=("Admin",),
            ),
            "tok-super": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-super-77",
                username="super@bonc",
                expires_at_utc=None,
                roles=("SuperAdmin",),
            ),
            "tok-basic": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-basic-99",
                username="regular.user",
                expires_at_utc=None,
                roles=("Basic",),
            ),
            "tok-noroles": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-noroles-2",
                username="no.roles",
                expires_at_utc=None,
                roles=(),
            ),
            "tok-unknown": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-unknown-3",
                username="unknown.role",
                expires_at_utc=None,
                roles=("UnknownRole",),
            ),
            "tok-auditor": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-auditor-4",
                username="search.auditor",
                expires_at_utc=None,
                roles=("SearchAuditor",),
            ),
            "tok-expired-ts": bonc_auth.VerifiedBoncIdentity(
                user_id="bonc-exp-1",
                username="exp.admin",
                expires_at_utc=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5),
                roles=("Admin",),
            ),
        }
        self.role_policy = bonc_auth.BoncRoleAuthorizationPolicy(
            allowed_admin_roles=frozenset({"Admin", "SuperAdmin"}),
            role_permission_map={
                "SearchAuditor": frozenset(
                    {
                        bonc_auth.ADMIN_PERMISSION_HEALTH_READ,
                        bonc_auth.ADMIN_PERMISSION_CATEGORIES_READ,
                    }
                ),
            },
        )

    def tearDown(self) -> None:
        self._model_patch.stop()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def _build_provider(
        self,
        *,
        role_policy: bonc_auth.BoncRoleAuthorizationPolicy | None = None,
        unavailable: bool = False,
    ) -> bonc_auth.BoncJwtAuthProvider:
        return bonc_auth.BoncJwtAuthProvider(
            verifier=_TestOnlyStubBoncVerifier(self.identities, unavailable=unavailable),
            claims_config=bonc_auth.BoncClaimsValidationConfig.delegated_server_verification(),
            role_policy=role_policy if role_policy is not None else self.role_policy,
        )

    def test_bearer_token_extraction_cases(self) -> None:
        self.assertEqual(bonc_auth.extract_bearer_token("Bearer abc.def.ghi"), "abc.def.ghi")
        self.assertEqual(bonc_auth.extract_bearer_token("bearer   abc.def.ghi  "), "abc.def.ghi")

        for header in (
            None,
            "",
            "   ",
            "Basic dXNlcjpwYXNz",
            "Token abc.def.ghi",
            "Bearer",
            "Bearer   ",
            "Bearer tok1 tok2",
            "abc.def.ghi",
            "Bearer tok\r\ninjected",
            "Bearer non-ascii-\u00e9",
        ):
            with self.subTest(header=header):
                with self.assertRaises(bonc_auth.BoncTokenExtractionError):
                    bonc_auth.extract_bearer_token(header)

        admin_auth.set_auth_provider(self._build_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            for bad_header in ("Basic dXNlcjpwYXNz", "Bearer ", "Bearer a b", "RawTokenOnly"):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": bad_header},
                )
                self.assertEqual(resp.status_code, 401)

    def test_authorization_denies_basic_unknown_missing_roles_and_enforces_capabilities(self) -> None:
        admin_auth.set_auth_provider(self._build_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        with TestClient(app) as client:
            # Expired timestamp on verified identity -> 401
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer tok-expired-ts"},
                ).status_code,
                401,
            )

            # Ordinary BONC Basic user denied even with spoofed headers -> 403
            resp_basic = client.get(
                "/api/admin/platform/categories",
                headers={
                    "Authorization": "Bearer tok-basic",
                    "X-User-Roles": "SuperAdmin",
                    "X-User-Id": "spoofed-admin",
                },
            )
            self.assertEqual(resp_basic.status_code, 403)

            # Missing / unknown roles denied -> 403
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer tok-noroles"},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get(
                    "/api/admin/platform/search-logs",
                    headers={"Authorization": "Bearer tok-unknown"},
                ).status_code,
                403,
            )

            # Fine-grained role: SearchAuditor allowed health & categories read, denied writes & logs
            auditor_hdr = {"Authorization": "Bearer tok-auditor"}
            self.assertEqual(
                client.get("/api/admin/platform/categories", headers=auditor_hdr).status_code,
                200,
            )
            self.assertEqual(
                client.get("/api/admin/platform/system-health", headers=auditor_hdr).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories",
                    json=_sample_category("blocked"),
                    headers=auditor_hdr,
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get("/api/admin/platform/search-logs", headers=auditor_hdr).status_code,
                403,
            )

        # Unconfigured role policy fails closed -> 503
        admin_auth.set_auth_provider(self._build_provider(role_policy=bonc_auth.BoncRoleAuthorizationPolicy()))
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer tok-admin"},
                ).status_code,
                503,
            )

        # Verifier unavailable -> 503
        admin_auth.set_auth_provider(self._build_provider(unavailable=True))
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer tok-admin"},
                ).status_code,
                503,
            )

    def test_exhaustive_route_protection_public_rules_options_head_and_openapi(self) -> None:
        os.environ["ALLOWED_ORIGINS"] = "https://app.bonc.test"
        admin_auth.set_auth_provider(self._build_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        admin_hdr = {"Authorization": "Bearer tok-admin"}
        basic_hdr = {"Authorization": "Bearer tok-basic"}

        with TestClient(app) as client:
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories",
                    json=_sample_category("people", public=False),
                    headers=admin_hdr,
                ).status_code,
                201,
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories/people/ingest",
                    json={
                        "documents": [
                            {
                                "document_id": "p-1",
                                "title": "Private People Profile",
                                "fields": {"title": "Private People Profile"},
                            }
                        ],
                        "replace_all": True,
                    },
                    headers=admin_hdr,
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories",
                    json=_sample_category("help", public=True),
                    headers=admin_hdr,
                ).status_code,
                201,
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories/help/ingest",
                    json={
                        "documents": [
                            {
                                "document_id": "h-1",
                                "title": "BONC Getting Started",
                                "fields": {"title": "BONC Getting Started"},
                            }
                        ],
                        "replace_all": True,
                    },
                    headers=admin_hdr,
                ).status_code,
                200,
            )

            protected_checks = [
                ("GET", "/api/admin/auth/session", None),
                ("GET", "/api/admin/platform/sources", None),
                ("GET", "/api/admin/platform/sources/BONC_DEV/schema", None),
                ("GET", "/api/admin/platform/sources/BONC_DEV/mapping-suggestions?schema=dbo&table=T", None),
                (
                    "POST",
                    "/api/admin/platform/sources/BONC_DEV/join-view-preview",
                    {
                        "base_schema": "dbo",
                        "base_table": "T",
                        "base_id_column": "Id",
                        "view_schema": "searchai",
                        "view_name": "vw_T",
                        "selected_relationships": [],
                    },
                ),
                (
                    "POST",
                    "/api/admin/platform/sources/BONC_DEV/validate",
                    {"schema": "dbo", "table": "T", "id_column": "Id", "filters": [], "max_records": 10},
                ),
                ("GET", "/api/admin/platform/categories", None),
                ("HEAD", "/api/admin/platform/categories", None),
                ("POST", "/api/admin/platform/categories", _sample_category("unauth")),
                (
                    "PUT",
                    "/api/admin/platform/categories/people",
                    {"expected_version": 1, "config": _sample_category("people")},
                ),
                (
                    "POST",
                    "/api/admin/platform/categories/people/rollback",
                    {"target_version": 1, "expected_version": 1, "reason": "test"},
                ),
                ("GET", "/api/admin/platform/categories/people/history", None),
                ("GET", "/api/admin/platform/categories/people/feedback", None),
                ("POST", "/api/admin/platform/categories/people/ingest", {"documents": []}),
                ("POST", "/api/admin/platform/categories/people/sync", None),
                ("POST", "/api/admin/platform/search", {"category": "people", "query": "test"}),
                ("GET", "/api/admin/platform/system-health", None),
                ("GET", "/api/admin/platform/search-logs", None),
                ("GET", "/api/admin/platform/search-logs/users", None),
                ("GET", "/api/admin/platform/metrics/kpis", None),
                ("GET", "/api/admin/platform/metrics/api-failures", None),
                ("GET", "/api/admin/platform/metrics/relevance", None),
                ("GET", "/api/admin/production/health", None),
                ("GET", "/api/admin/production/index-status", None),
            ]
            for method, path, body in protected_checks:
                with self.subTest(method=method, path=path):
                    resp = client.request(method, path, json=body)
                    self.assertEqual(resp.status_code, 401)

            # Public health & category endpoints + HEAD policy
            self.assertEqual(client.get("/health/live").status_code, 200)
            self.assertEqual(client.head("/health/live").status_code, 200)
            self.assertEqual(client.get("/health/ready").status_code, 200)
            self.assertEqual(
                client.head("/api/admin/platform/categories", headers=basic_hdr).status_code,
                403,
            )
            head_admin = client.head("/api/admin/platform/categories", headers=admin_hdr)
            self.assertEqual(head_admin.status_code, 200)
            self.assertEqual(head_admin.content, b"")
            self.assertEqual(client.head("/api/platform/search").status_code, 405)

            # Public search + private category blocking
            self.assertEqual(
                client.post("/api/platform/search", json={"category": "help", "query": "BONC"}).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/api/platform/search",
                    json={"category": "help", "query": "Getting Started"},
                    headers=basic_hdr,
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/api/platform/search",
                    json={"category": "people", "query": "test"},
                    headers=basic_hdr,
                ).status_code,
                403,
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/search",
                    json={"category": "people", "query": "test"},
                    headers=admin_hdr,
                ).status_code,
                200,
            )

            # CORS OPTIONS preflight (stateless Bearer, no credentials cookie needed)
            preflight = client.options(
                "/api/admin/platform/categories",
                headers={
                    "Origin": "https://app.bonc.test",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization,Content-Type",
                },
            )
            self.assertEqual(preflight.status_code, 200)
            self.assertEqual(
                preflight.headers.get("access-control-allow-origin"),
                "https://app.bonc.test",
            )

            # OpenAPI exposes BoncBearerAuth only and omits removed /login and /logout
            spec = client.get("/openapi.json").json()
            self.assertIn("BoncBearerAuth", spec["components"]["securitySchemes"])
            self.assertNotIn("/api/admin/auth/login", spec["paths"])
            self.assertNotIn("/api/admin/auth/logout", spec["paths"])
            self.assertTrue(spec["paths"]["/api/admin/auth/session"]["get"].get("security"))
            self.assertNotIn("security", spec["paths"]["/api/platform/categories"]["get"])

    def test_end_to_end_admin_workflow_and_audit_actor_propagation(self) -> None:
        admin_auth.set_auth_provider(self._build_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        hdr = {"Authorization": "Bearer tok-admin"}

        with TestClient(app) as client:
            c1 = client.post(
                "/api/admin/platform/categories",
                json=_sample_category("jobs", public=False),
                headers=hdr,
            )
            self.assertEqual(c1.status_code, 201)
            self.assertEqual(c1.json()["updated_by"], "bonc-admin-55")

            v2_cfg = _sample_category("jobs", public=False)
            v2_cfg["display_name"] = "BONC Jobs v2"
            u2 = client.put(
                "/api/admin/platform/categories/jobs",
                json={"expected_version": 1, "config": v2_cfg, "change_reason": "Rename"},
                headers=hdr,
            )
            self.assertEqual(u2.status_code, 200)
            self.assertEqual(u2.json()["updated_by"], "bonc-admin-55")

            rb = client.post(
                "/api/admin/platform/categories/jobs/rollback",
                json={"target_version": 1, "expected_version": 2, "reason": "Restore v1"},
                headers=hdr,
            )
            self.assertEqual(rb.status_code, 200)
            self.assertEqual(rb.json()["config_version"], 3)
            self.assertEqual(rb.json()["updated_by"], "bonc-admin-55")

            history = client.get("/api/admin/platform/categories/jobs/history", headers=hdr).json()["items"]
            self.assertEqual([h["changed_by"] for h in history], ["bonc-admin-55"] * 3)


if __name__ == "__main__":
    unittest.main()
