"""Tests for the ``bonc-auth`` package adapter integrated behind ``BoncTokenVerifier``.

All verification HTTP calls are mocked (``bonc_auth.client.httpx.request``) and
only synthetic test tokens and claims are used. Passing these tests validates
the adapter, fail-closed incomplete-contract behavior (HTTP 503), auth failures,
and route-level RBAC enforcement; it does NOT activate BONC authentication in
``build_default_auth_provider()`` or verify the live .NET contract.
"""
from __future__ import annotations

import ast
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import bonc_auth as bonc_auth_pkg
import httpx
import numpy as np
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db import auth_db, platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import (  # noqa: E402
    admin_auth,
    bonc_auth,
    bonc_auth_adapter,
    embedding_model,
    platform_search,
)

_TEST_VERIFY_URL = "https://auth.bonc.test/api/auth/verify-admin"
_TEST_ISSUER = "https://auth.bonc.test"
_TEST_AUDIENCE = "bonc-search-admin-test"


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


def _complete_verify_payload(
    *,
    admin_id: str = "bonc-admin-uuid-1001",
    username: str | None = "admin.alice",
    role: str | None = "Admin",
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
    session_id: str | None = "sess-test-001",
    issuer: str | None = _TEST_ISSUER,
    audience: str | list[str] | None = _TEST_AUDIENCE,
    exp_delta: timedelta = timedelta(minutes=30),
    exp_override: object = ...,
    nbf_delta: timedelta | None = timedelta(minutes=-1),
    alg: str | None = None,
    kid: str | None = None,
    typ: str | None = None,
    jti: str | None = "jti-test-001",
) -> dict:
    now = datetime.now(timezone.utc)
    payload: dict = {"adminId": admin_id}
    if username is not None:
        payload["username"] = username
    if role is not None:
        payload["role"] = role
    if roles is not None:
        payload["roles"] = roles
    if permissions is not None:
        payload["permissions"] = permissions
    if session_id is not None:
        payload["sessionId"] = session_id
    if issuer is not None:
        payload["iss"] = issuer
    if audience is not None:
        payload["aud"] = audience
    if exp_override is not ...:
        payload["exp"] = exp_override
    else:
        payload["exp"] = int((now + exp_delta).timestamp())
    if nbf_delta is not None:
        payload["nbf"] = int((now + nbf_delta).timestamp())
    payload["iat"] = int(now.timestamp())
    if alg is not None:
        payload["alg"] = alg
    if kid is not None:
        payload["kid"] = kid
    if typ is not None:
        payload["typ"] = typ
    if jti is not None:
        payload["jti"] = jti
    return payload


class TestBoncAuthPackageAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["APP_ENV"] = "local"
        os.environ["SEARCH_ADMIN_AUTH_MODE"] = "bonc_jwt"
        os.environ["SEARCH_ADMIN_AUTH_DB_URL"] = "sqlite:///:memory:"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        os.environ["SEARCH_ADMIN_ALLOW_CLI_SERVICE_TOKEN"] = "false"
        os.environ.pop("SEARCH_ADMIN_USERNAME", None)
        os.environ.pop("SEARCH_ADMIN_PASSWORD_HASH", None)
        os.environ.pop("SEARCH_ADMIN_SERVICE_TOKEN", None)

        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

        self._model_patch = patch(
            "app.services.platform_search.get_model", return_value=_TinyEmbeddingModel()
        )
        self._model_patch.start()

        self.claims_config = bonc_auth.BoncClaimsValidationConfig(
            allowed_algorithms=frozenset(),
            expected_issuer=_TEST_ISSUER,
            expected_audience=_TEST_AUDIENCE,
            clock_skew_seconds=5,
            require_algorithm=False,
        )
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
        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def _build_adapter_provider(
        self,
        *,
        claims_config: bonc_auth.BoncClaimsValidationConfig | None = None,
        role_policy: bonc_auth.BoncRoleAuthorizationPolicy | None = None,
        service_headers: dict[str, str] | None = None,
        client_configured: bool = True,
    ) -> bonc_auth.BoncJwtAuthProvider:
        if client_configured:
            verifier = bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
                verify_url=_TEST_VERIFY_URL,
                method="GET",
                timeout=3.0,
                service_headers=service_headers,
            )
        else:
            verifier = bonc_auth_adapter.BoncAuthPackageVerifierAdapter(client=None)

        return bonc_auth.BoncJwtAuthProvider(
            verifier=verifier,
            claims_config=claims_config or self.claims_config,
            role_policy=role_policy if role_policy is not None else self.role_policy,
            allow_cli_service_token=False,
        )

    # ------------------------------------------------------------------
    # 1. Package import, architecture boundaries & unactivated default
    # ------------------------------------------------------------------

    def test_package_imported_externally_and_routes_do_not_bypass_central_provider(self) -> None:
        pkg_path = Path(bonc_auth_pkg.__file__).resolve()
        project_root = BACKEND_DIR.parent.resolve()
        in_site_packages = any(
            part in {"site-packages", "dist-packages"} for part in pkg_path.parts
        )
        self.assertFalse(
            pkg_path.is_relative_to((BACKEND_DIR / "app").resolve()),
            f"bonc_auth package must not be copied into backend/app: {pkg_path}",
        )
        self.assertFalse(
            pkg_path.is_relative_to(project_root) and not in_site_packages,
            f"bonc_auth package must be imported externally, not copied into {project_root}: {pkg_path}",
        )
        self.assertIs(bonc_auth_adapter.BoncAuth, bonc_auth_pkg.BoncAuth)
        self.assertIs(
            admin_auth.BoncAuthPackageVerifierAdapter,
            bonc_auth_adapter.BoncAuthPackageVerifierAdapter,
        )

        adapter = bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
            verify_url=_TEST_VERIFY_URL
        )
        self.assertIsInstance(adapter, bonc_auth.BoncTokenVerifier)
        self.assertIsInstance(adapter.client, bonc_auth_pkg.BoncAuth)
        self.assertTrue(adapter.is_configured())

        # Ensure FastAPIAdminGuard is never imported/used to bypass BoncJwtAuthProvider
        app_dir = BACKEND_DIR / "app"
        for py_file in app_dir.rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "bonc_auth.fastapi":
                    self.fail(f"FastAPIAdminGuard must not be imported in {py_file}")
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(
                            alias.name,
                            "bonc_auth.fastapi",
                            f"FastAPIAdminGuard must not be imported in {py_file}",
                        )

    def test_default_provider_remains_unactivated_and_fail_closed_in_bonc_mode(self) -> None:
        for env_name in ("local", "staging", "production"):
            os.environ["APP_ENV"] = env_name
            os.environ["SEARCH_ADMIN_AUTH_MODE"] = "bonc_jwt"
            provider = admin_auth.build_default_auth_provider()
            self.assertIsInstance(provider, bonc_auth.BoncJwtAuthProvider)
            self.assertFalse(provider.is_configured())
            self.assertFalse(provider.supports_local_login())

            app = create_app(warmup_embedding_model=False, connect_platform_database=False)
            with TestClient(app) as client:
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer synthetic-token"},
                )
                self.assertEqual(resp.status_code, 503)
                self.assertEqual(resp.headers.get("x-auth-mode"), "bonc_jwt")
                ready = client.get("/health/ready")
                self.assertEqual(ready.status_code, 503)
                self.assertEqual(ready.json()["checks"]["authProvider"], "not_configured")

    # ------------------------------------------------------------------
    # 2. Direct adapter unit tests (parsing, validation, error mapping)
    # ------------------------------------------------------------------

    def test_from_settings_enforces_bonc_auth_package_security_checks(self) -> None:
        with self.assertRaises(ValueError):
            bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
                verify_url="http://remote-insecure.bonc.test/verify"
            )
        with self.assertRaises(ValueError):
            bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
                verify_url=_TEST_VERIFY_URL,
                method="DELETE",
            )
        with self.assertRaises(ValueError):
            bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
                verify_url=_TEST_VERIFY_URL,
                timeout=0,
            )
        with self.assertRaises(ValueError):
            bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
                verify_url=_TEST_VERIFY_URL,
                service_headers={"Authorization": "Bearer disallowed"},
            )

    def test_unconfigured_adapter_fails_closed(self) -> None:
        adapter = bonc_auth_adapter.BoncAuthPackageVerifierAdapter(client=None)
        self.assertFalse(adapter.is_configured())
        with self.assertRaises(bonc_auth.BoncAuthNotConfiguredError):
            adapter.verify_access_token("synthetic-token")

    def test_adapter_parses_complete_verified_payload_and_forwards_headers(self) -> None:
        captured: dict = {}

        def fake_request(method, url, **kwargs):
            captured["method"] = method
            captured["url"] = url
            captured["kwargs"] = kwargs
            return httpx.Response(
                200,
                json=_complete_verify_payload(
                    admin_id="admin-uuid-42",
                    username="ops.bonc",
                    role="Admin",
                    roles=["Admin", "SearchAuditor"],
                    permissions=[bonc_auth.ADMIN_PERMISSION_CATEGORIES_READ],
                    session_id="session-xyz-99",
                    audience=[_TEST_AUDIENCE, "bonc-portal"],
                    exp_override=(datetime.now(timezone.utc) + timedelta(minutes=20))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    alg="RS256",
                    kid="kid-2026-01",
                    typ="JWT",
                    jti="jti-abc-123",
                ),
            )

        adapter = bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
            verify_url=_TEST_VERIFY_URL,
            method="GET",
            timeout=4.5,
            service_headers={"X-Service-Client": "search-admin-test"},
        )
        with patch("bonc_auth.client.httpx.request", side_effect=fake_request):
            identity = adapter.verify_access_token("synthetic-valid-token")

        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["url"], _TEST_VERIFY_URL)
        self.assertEqual(captured["kwargs"]["timeout"], 4.5)
        self.assertFalse(captured["kwargs"]["follow_redirects"])
        self.assertEqual(
            captured["kwargs"]["headers"]["Authorization"],
            "Bearer synthetic-valid-token",
        )
        self.assertEqual(
            captured["kwargs"]["headers"]["X-Service-Client"],
            "search-admin-test",
        )

        self.assertEqual(identity.user_id, "admin-uuid-42")
        self.assertEqual(identity.username, "ops.bonc")
        self.assertEqual(identity.session_id, "session-xyz-99")
        self.assertEqual(identity.issuer, _TEST_ISSUER)
        self.assertEqual(identity.audience, (_TEST_AUDIENCE, "bonc-portal"))
        self.assertIsNotNone(identity.expires_at_utc)
        self.assertIsNotNone(identity.not_before_utc)
        self.assertIsNotNone(identity.issued_at_utc)
        self.assertEqual(identity.algorithm, "RS256")
        self.assertEqual(identity.key_id, "kid-2026-01")
        self.assertEqual(identity.token_type, "JWT")
        self.assertEqual(identity.token_id, "jti-abc-123")
        self.assertEqual(identity.roles, ("Admin", "SearchAuditor"))
        self.assertEqual(identity.permissions, (bonc_auth.ADMIN_PERMISSION_CATEGORIES_READ,))

    def test_adapter_rejects_incomplete_bonc_auth_example_payload_with_503_unavailable(self) -> None:
        # Minimal unconfirmed bonc-auth v0.2.0 example omits iss, aud, and exp.
        # Must fail closed with BoncAuthUnavailableError (HTTP 503), NEVER invent claims or return 401.
        minimal_payload = {"adminId": "admin-1", "role": "Admin", "sessionId": "s1"}
        adapter = bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
            verify_url=_TEST_VERIFY_URL
        )

        with patch(
            "bonc_auth.client.httpx.request",
            return_value=httpx.Response(200, json=minimal_payload),
        ):
            with self.assertRaises(bonc_auth.BoncAuthUnavailableError) as ctx:
                adapter.verify_access_token("synthetic-token")
        self.assertIn("issuer", str(ctx.exception))
        self.assertIn("audience", str(ctx.exception))
        self.assertIn("expires_at_utc", str(ctx.exception))

        # Verify partial omission of any single required claim also raises BoncAuthUnavailableError
        for omitted_key in ("iss", "aud", "exp"):
            partial = _complete_verify_payload()
            partial.pop(omitted_key)
            with self.subTest(omitted_key=omitted_key):
                with patch(
                    "bonc_auth.client.httpx.request",
                    return_value=httpx.Response(200, json=partial),
                ):
                    with self.assertRaises(bonc_auth.BoncAuthUnavailableError):
                        adapter.verify_access_token("synthetic-token")

    def test_adapter_rejects_malformed_or_conflicting_payload_fields_with_503_unavailable(self) -> None:
        adapter = bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
            verify_url=_TEST_VERIFY_URL
        )
        bad_payloads = [
            ("blank_admin_id", {**_complete_verify_payload(), "adminId": "   "}),
            ("non_str_admin_id", {**_complete_verify_payload(), "adminId": 12345}),
            ("bool_exp", {**_complete_verify_payload(), "exp": True}),
            ("naive_iso_exp", {**_complete_verify_payload(), "exp": "2027-01-01T00:00:00"}),
            ("invalid_str_exp", {**_complete_verify_payload(), "exp": "not-a-timestamp"}),
            ("non_list_roles", {**_complete_verify_payload(), "roles": "Admin"}),
            ("non_str_role_item", {**_complete_verify_payload(), "roles": [123]}),
            ("empty_audience_list", {**_complete_verify_payload(), "aud": []}),
            (
                "conflicting_issuer",
                {
                    **_complete_verify_payload(),
                    "iss": _TEST_ISSUER,
                    "issuer": "https://other.bonc.test",
                },
            ),
        ]
        for label, payload in bad_payloads:
            with self.subTest(case=label):
                with patch(
                    "bonc_auth.client.httpx.request",
                    return_value=httpx.Response(200, json=payload),
                ):
                    with self.assertRaises(bonc_auth.BoncAuthUnavailableError):
                        adapter.verify_access_token("synthetic-token")

    def test_adapter_translates_bonc_auth_exceptions_accurately(self) -> None:
        adapter = bonc_auth_adapter.BoncAuthPackageVerifierAdapter.from_settings(
            verify_url=_TEST_VERIFY_URL
        )

        with patch("bonc_auth.client.httpx.request", return_value=httpx.Response(401)):
            with self.assertRaises(bonc_auth.BoncTokenInvalidError):
                adapter.verify_access_token("invalid-or-revoked-token")

        with patch("bonc_auth.client.httpx.request", return_value=httpx.Response(403)):
            with self.assertRaises(bonc_auth.BoncAuthorizationDeniedError):
                adapter.verify_access_token("non-admin-token")

        for status_code in (500, 502, 503, 302):
            with self.subTest(status_code=status_code):
                with patch(
                    "bonc_auth.client.httpx.request",
                    return_value=httpx.Response(status_code),
                ):
                    with self.assertRaises(bonc_auth.BoncAuthUnavailableError):
                        adapter.verify_access_token("synthetic-token")

        with patch(
            "bonc_auth.client.httpx.request",
            return_value=httpx.Response(200, content=b"not-json"),
        ):
            with self.assertRaises(bonc_auth.BoncAuthUnavailableError):
                adapter.verify_access_token("synthetic-token")

        with patch(
            "bonc_auth.client.httpx.request",
            side_effect=httpx.TimeoutException("timed out"),
        ):
            with self.assertRaises(bonc_auth.BoncAuthUnavailableError):
                adapter.verify_access_token("synthetic-token")

    # ------------------------------------------------------------------
    # 3. End-to-end FastAPI integration: valid, failure, 503 & RBAC tests
    # ------------------------------------------------------------------

    def test_end_to_end_valid_admin_token_propagates_actor_and_session_id(self) -> None:
        admin_auth.set_auth_provider(self._build_adapter_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        payload = _complete_verify_payload(
            admin_id="bonc-admin-uuid-777",
            username="priya.admin",
            role="Admin",
            session_id="bonc-sess-777",
        )

        with patch(
            "bonc_auth.client.httpx.request",
            return_value=httpx.Response(200, json=payload),
        ):
            with TestClient(app) as client:
                hdr = {"Authorization": "Bearer synthetic-admin-token"}

                # Readiness reports authProvider=ready when explicitly configured in test fixture
                ready = client.get("/health/ready")
                self.assertEqual(ready.status_code, 200)
                self.assertEqual(ready.json()["checks"]["authProvider"], "ready")

                # Session endpoint returns trusted BONC identity
                sess = client.get("/api/admin/auth/session", headers=hdr)
                self.assertEqual(sess.status_code, 200)
                body = sess.json()
                self.assertTrue(body["authenticated"])
                self.assertEqual(body["auth_method"], "bonc_jwt")
                self.assertEqual(body["user_id"], "bonc-admin-uuid-777")
                self.assertEqual(body["actor"], "bonc-admin-uuid-777")
                self.assertEqual(body["username"], "priya.admin")
                self.assertEqual(body["roles"], ["Admin"])
                self.assertFalse(body["local_login_enabled"])

                # Admin write succeeds without cookie CSRF and propagates verified adminId
                created = client.post(
                    "/api/admin/platform/categories",
                    json=_sample_category("people", public=False),
                    headers=hdr,
                )
                self.assertEqual(created.status_code, 201)
                self.assertEqual(created.json()["updated_by"], "bonc-admin-uuid-777")

                history = client.get(
                    "/api/admin/platform/categories/people/history",
                    headers=hdr,
                )
                self.assertEqual(history.status_code, 200)
                self.assertEqual(history.json()["items"][0]["changed_by"], "bonc-admin-uuid-777")

                # Direct provider check verifies session_id propagation on AdminPrincipal
                principal = admin_auth.authorize_admin_request(
                    authorization="Bearer synthetic-admin-token"
                )
                self.assertEqual(principal.session_id, "bonc-sess-777")
                self.assertEqual(principal.user_id, "bonc-admin-uuid-777")

                # Local login/logout remain disabled (404)
                self.assertEqual(
                    client.post(
                        "/api/admin/auth/login",
                        json={"username": "ops", "password": "secret"},
                    ).status_code,
                    404,
                )
                self.assertEqual(client.post("/api/admin/auth/logout").status_code, 404)

    def test_end_to_end_authentication_failures_and_503_incomplete_or_unavailable_responses(
        self,
    ) -> None:
        admin_auth.set_auth_provider(self._build_adapter_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        with TestClient(app) as client:
            # Missing / malformed Authorization headers fail with 401 before calling verifier
            with patch("bonc_auth.client.httpx.request") as mocked_http:
                for bad_headers in (
                    {},
                    {"Authorization": "Basic dXNlcjpwYXNz"},
                    {"Authorization": "Bearer "},
                    {"Authorization": "Bearer a b"},
                ):
                    resp = client.get("/api/admin/platform/categories", headers=bad_headers)
                    self.assertEqual(resp.status_code, 401)
                    self.assertEqual(resp.headers.get("www-authenticate"), "Bearer")
                mocked_http.assert_not_called()

            # Non-BONC service tokens are rejected with 401 before calling bonc-auth verifier
            os.environ["PRODUCTION_SEARCH_AUTH_TOKEN"] = "prod-obs-secret-test-999"
            with patch("bonc_auth.client.httpx.request") as mocked_http:
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer prod-obs-secret-test-999"},
                )
                self.assertEqual(resp.status_code, 401)
                mocked_http.assert_not_called()

            # .NET 401 (invalid / revoked token) -> HTTP 401
            with patch(
                "bonc_auth.client.httpx.request",
                return_value=httpx.Response(401),
            ):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer revoked-token"},
                )
                self.assertEqual(resp.status_code, 401)
                self.assertEqual(resp.headers.get("www-authenticate"), "Bearer")

            # Expired exp, future nbf, wrong iss, wrong aud -> HTTP 401 via validate_verified_bonc_identity
            claim_failure_payloads = [
                ("expired", _complete_verify_payload(exp_delta=timedelta(minutes=-5))),
                ("future_nbf", _complete_verify_payload(nbf_delta=timedelta(minutes=10))),
                ("wrong_iss", _complete_verify_payload(issuer="https://evil.bonc.test")),
                ("wrong_aud", _complete_verify_payload(audience="other-service")),
            ]
            for label, payload in claim_failure_payloads:
                with self.subTest(case=label):
                    with patch(
                        "bonc_auth.client.httpx.request",
                        return_value=httpx.Response(200, json=payload),
                    ):
                        resp = client.get(
                            "/api/admin/platform/categories",
                            headers={"Authorization": "Bearer synthetic-token"},
                        )
                        self.assertEqual(resp.status_code, 401)
                        self.assertEqual(resp.headers.get("www-authenticate"), "Bearer")

            # Incomplete HTTP 200 verification payload (missing iss/aud/exp) -> HTTP 503 (NOT 401!)
            with patch(
                "bonc_auth.client.httpx.request",
                return_value=httpx.Response(
                    200,
                    json={"adminId": "admin-1", "role": "Admin", "sessionId": "s1"},
                ),
            ):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer synthetic-token"},
                )
                self.assertEqual(resp.status_code, 503)
                self.assertEqual(resp.headers.get("x-auth-mode"), "bonc_jwt")

            # Upstream verifier outage / timeout -> HTTP 503
            with patch(
                "bonc_auth.client.httpx.request",
                side_effect=httpx.ConnectError("connection refused"),
            ):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer synthetic-token"},
                )
                self.assertEqual(resp.status_code, 503)

        # Strict alg/kid validation when claims_config requires algorithm & key ID
        strict_claims = bonc_auth.BoncClaimsValidationConfig(
            allowed_algorithms=frozenset({"RS256"}),
            expected_issuer=_TEST_ISSUER,
            expected_audience=_TEST_AUDIENCE,
            allowed_key_ids=frozenset({"kid-v1"}),
            expected_token_type="JWT",
            clock_skew_seconds=5,
            require_algorithm=True,
        )
        admin_auth.set_auth_provider(self._build_adapter_provider(claims_config=strict_claims))
        with TestClient(app) as client:
            for label, payload in (
                ("disallowed_alg", _complete_verify_payload(alg="HS256", kid="kid-v1", typ="JWT")),
                ("alg_none", _complete_verify_payload(alg="none", kid="kid-v1", typ="JWT")),
                ("unknown_kid", _complete_verify_payload(alg="RS256", kid="unknown-kid", typ="JWT")),
                ("wrong_typ", _complete_verify_payload(alg="RS256", kid="kid-v1", typ="opaque")),
            ):
                with self.subTest(strict_case=label):
                    with patch(
                        "bonc_auth.client.httpx.request",
                        return_value=httpx.Response(200, json=payload),
                    ):
                        resp = client.get(
                            "/api/admin/platform/categories",
                            headers={"Authorization": "Bearer synthetic-token"},
                        )
                        self.assertEqual(resp.status_code, 401)

            with patch(
                "bonc_auth.client.httpx.request",
                return_value=httpx.Response(
                    200,
                    json=_complete_verify_payload(alg="RS256", kid="kid-v1", typ="JWT"),
                ),
            ):
                ok = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer synthetic-token"},
                )
                self.assertEqual(ok.status_code, 200)

        # Unconfigured adapter inside provider -> HTTP 503
        admin_auth.set_auth_provider(self._build_adapter_provider(client_configured=False))
        with TestClient(app) as client:
            resp = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": "Bearer synthetic-token"},
            )
            self.assertEqual(resp.status_code, 503)

    def test_end_to_end_authorization_and_route_level_permission_enforcement(self) -> None:
        admin_auth.set_auth_provider(self._build_adapter_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        with TestClient(app) as client:
            # 1. .NET HTTP 403 -> HTTP 403
            with patch("bonc_auth.client.httpx.request", return_value=httpx.Response(403)):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer ordinary-user-token"},
                )
                self.assertEqual(resp.status_code, 403)

            # 2. .NET HTTP 200 with ordinary/unknown/missing role -> HTTP 403 (even with spoofed headers!)
            denied_payloads = [
                ("basic_role", _complete_verify_payload(role="Basic")),
                ("unknown_role", _complete_verify_payload(role="UnapprovedRole")),
                ("missing_role", _complete_verify_payload(role=None, roles=None)),
            ]
            for label, payload in denied_payloads:
                with self.subTest(case=label):
                    with patch(
                        "bonc_auth.client.httpx.request",
                        return_value=httpx.Response(200, json=payload),
                    ):
                        resp = client.get(
                            "/api/admin/platform/categories",
                            headers={
                                "Authorization": "Bearer synthetic-token",
                                "X-User-Roles": "SuperAdmin",
                                "X-User-Id": "spoofed-admin",
                            },
                        )
                        self.assertEqual(resp.status_code, 403)

            # 3. Fine-grained role (SearchAuditor): allowed health & categories read, denied writes/logs/analytics/prod
            auditor_payload = _complete_verify_payload(
                admin_id="bonc-auditor-10",
                username="auditor.sam",
                role="SearchAuditor",
            )
            with patch(
                "bonc_auth.client.httpx.request",
                return_value=httpx.Response(200, json=auditor_payload),
            ):
                hdr = {"Authorization": "Bearer auditor-token"}
                self.assertEqual(
                    client.get("/api/admin/platform/categories", headers=hdr).status_code,
                    200,
                )
                self.assertEqual(
                    client.get("/api/admin/platform/system-health", headers=hdr).status_code,
                    200,
                )
                self.assertEqual(
                    client.post(
                        "/api/admin/platform/categories",
                        json=_sample_category("blocked"),
                        headers=hdr,
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    client.get("/api/admin/platform/search-logs", headers=hdr).status_code,
                    403,
                )
                self.assertEqual(
                    client.get("/api/admin/platform/metrics/kpis", headers=hdr).status_code,
                    403,
                )
                self.assertEqual(
                    client.get("/api/admin/production/health", headers=hdr).status_code,
                    403,
                )

    def test_zero_local_session_fallback_when_bonc_mode_or_adapter_active(self) -> None:
        # Seed a valid local SQLite session first
        os.environ["SEARCH_ADMIN_AUTH_MODE"] = "local_session"
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password("ValidLocalPass!2026")
        auth_db.init_auth_db("sqlite:///:memory:")
        raw_cookie, session = admin_auth.create_session("ops.admin", ttl_seconds=3600)

        os.environ["SEARCH_ADMIN_AUTH_MODE"] = "bonc_jwt"
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        # With default unactivated provider -> 503 (never falls back to local cookie)
        with TestClient(app) as client:
            client.cookies.set(admin_auth.SESSION_COOKIE_NAME, raw_cookie)
            resp = client.get(
                "/api/admin/platform/categories",
                headers={"X-CSRF-Token": session.csrf_token},
            )
            self.assertEqual(resp.status_code, 503)

        # With adapter provider explicitly attached in test -> 401 (never falls back to local cookie)
        admin_auth.set_auth_provider(self._build_adapter_provider())
        with TestClient(app) as client:
            client.cookies.set(admin_auth.SESSION_COOKIE_NAME, raw_cookie)
            resp = client.get(
                "/api/admin/platform/categories",
                headers={"X-CSRF-Token": session.csrf_token},
            )
            self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
