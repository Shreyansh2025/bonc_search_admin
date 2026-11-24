"""BONC ``getUserDetail`` authentication tests (sole Search Admin user auth method).

Uses a local loopback fake .NET ``getUserDetail`` HTTPServer on ``127.0.0.1``
and synthetic fake-signature JWTs (Search Admin decodes JWT payloads ONLY as
untrusted input to obtain ``UserRowId``, forwarding the original unchanged
Bearer token to .NET for authoritative validation).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import numpy as np
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import config as app_config  # noqa: E402
from app.db import platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import (  # noqa: E402
    admin_auth,
    bonc_auth_adapter,
    embedding_model,
    platform_search,
)


def _fake_jwt(claims: dict) -> str:
    def _enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).rstrip(b"=").decode("ascii")

    return f"{_enc({'alg': 'HS256', 'typ': 'JWT'})}.{_enc(claims)}.fake-signature"


ADMIN_ID = "11111111-aaaa-4bbb-8ccc-000000000001"
SUPER_ID = "22222222-aaaa-4bbb-8ccc-000000000002"
BASIC_ID = "33333333-aaaa-4bbb-8ccc-000000000003"
INACTIVE_ID = "44444444-aaaa-4bbb-8ccc-000000000004"
BARE_ID = "55555555-aaaa-4bbb-8ccc-000000000005"

USERS: dict[str, dict] = {
    ADMIN_ID: {
        "UserRowId": ADMIN_ID,
        "UserName": "admin.demo@bonc.test",
        "UserRoles": "Admin",
        "IsActive": True,
    },
    SUPER_ID: {
        "UserRowId": SUPER_ID,
        "UserName": "superadmin.demo@bonc.test",
        "UserRoles": "Basic, SuperAdmin",
        "IsActive": True,
    },
    BASIC_ID: {
        "UserRowId": BASIC_ID,
        "UserName": "basic.demo@bonc.test",
        "UserRoles": "Basic",
        "IsActive": True,
    },
    INACTIVE_ID: {
        "UserRowId": INACTIVE_ID,
        "UserName": "deactivated.admin@bonc.test",
        "UserRoles": "Admin",
        "IsActive": False,
    },
    BARE_ID: {
        "UserRowId": BARE_ID,
        "UserName": "bare.admin@bonc.test",
        "UserRoles": "Admin",
        "IsActive": True,
    },
    "u-roles-semi": {
        "UserRowId": "u-roles-semi",
        "RoleNames": "basic; superadmin | viewer",
        "IsActive": True,
    },
    "u-roles-list": {
        "UserRowId": "u-roles-list",
        "RoleNames": ["Basic", "ADMIN"],
        "IsActive": True,
    },
    "u-role-singular": {
        "UserRowId": "u-role-singular",
        "RoleName": "  admin ",
        "IsActive": True,
    },
    "u-case-guid": {
        "UserRowId": "ABCDEF01-2345-6789-ABCD-EF0123456789",
        "UserRoles": "Admin",
        "IsActive": True,
    },
}

TOKENS: dict[str, str] = {
    name: _fake_jwt({"UserRowId": uid, "exp": 9999999999})
    for name, uid in [
        ("admin", ADMIN_ID),
        ("super", SUPER_ID),
        ("basic", BASIC_ID),
        ("inactive", INACTIVE_ID),
        ("bare", BARE_ID),
        ("roles_semi", "u-roles-semi"),
        ("roles_list", "u-roles-list"),
        ("role_singular", "u-role-singular"),
        ("case_guid", "abcdef01-2345-6789-abcd-ef0123456789"),
        ("swap", "u-swap"),
        ("falsy", "u-falsy"),
        ("bad_json", "u-bad-json"),
        ("non_dict", "u-non-dict"),
        ("bad_data", "u-bad-data"),
        ("boom_409", "u-boom-409"),
        ("boom_500", "u-boom-500"),
        ("redirect_302", "u-redirect-302"),
        ("slow", "u-slow"),
        ("dotnet_403", "u-dotnet-403"),
    ]
}
REVOKED_OR_EXPIRED_TOKEN = _fake_jwt({"UserRowId": ADMIN_ID, "exp": 1})


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


class _FakeDotNetHandler(BaseHTTPRequestHandler):
    seen: list[tuple[str, str, str]] = []  # (path, raw_token, userRowId)
    revoked_tokens: set[str] = set()

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        auth = self.headers.get("Authorization") or ""
        token = auth[7:] if auth.startswith("Bearer ") else auth
        uid = parse_qs(parsed.query).get("userRowId", [""])[0]
        _FakeDotNetHandler.seen.append((parsed.path, token, uid))

        if token not in TOKENS.values() or token in _FakeDotNetHandler.revoked_tokens:
            return self._send_json(401, {"Success": False, "Message": "Invalid token"})

        if uid == "u-dotnet-403":
            return self._send_json(403, {"Success": False, "Message": "Forbidden"})
        if uid == "u-swap":
            return self._send_json(200, {"Success": True, "Message": "", "Data": USERS[ADMIN_ID]})
        if uid == "u-falsy":
            return self._send_json(200, {"Success": False, "Message": "User not found"})
        if uid == "u-bad-json":
            return self._send_raw(200, b"<html>not json</html>", "text/html")
        if uid == "u-non-dict":
            return self._send_json(200, ["not", "a", "dict"])
        if uid == "u-bad-data":
            return self._send_json(200, {"Success": True, "Data": "unexpected-string"})
        if uid == "u-boom-409":
            return self._send_json(409, {"Success": False, "Message": "Conflict"})
        if uid == "u-boom-500":
            return self._send_json(500, {"Success": False, "Message": "Internal Server Error"})
        if uid == "u-redirect-302":
            self.send_response(302)
            self.send_header("Location", "https://evil.example.com/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if uid == "u-slow":
            time.sleep(0.4)
            return self._send_json(200, {"Success": True, "Data": USERS[ADMIN_ID]})
        if uid == BARE_ID:
            return self._send_json(200, USERS[BARE_ID])

        user_key = "u-case-guid" if uid.lower() == USERS["u-case-guid"]["UserRowId"].lower() else uid
        return self._send_json(200, {"Success": True, "Message": "", "Data": USERS[user_key]})

    def _send_json(self, status: int, body: object) -> None:
        self._send_raw(status, json.dumps(body).encode("utf-8"), "application/json")

    def _send_raw(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class TestBoncUserDetailAuth(unittest.TestCase):
    server: HTTPServer
    server_thread: threading.Thread
    detail_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), _FakeDotNetHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.detail_url = f"http://127.0.0.1:{cls.server.server_port}/api/userService/getUserDetail"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        _FakeDotNetHandler.seen.clear()
        _FakeDotNetHandler.revoked_tokens.clear()

        os.environ["APP_ENV"] = "local"
        os.environ["BONC_AUTH_VERIFY_URL"] = self.detail_url
        os.environ["BONC_AUTH_ADMIN_ROLES"] = "Admin,SuperAdmin"
        os.environ["BONC_AUTH_CACHE_SECONDS"] = "0"
        os.environ["BONC_AUTH_TIMEOUT"] = "5"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        os.environ.pop("SEARCH_ADMIN_ENABLE_API_DOCS", None)

        platform_db.reset_platform_engine()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

        self._model_patch = patch(
            "app.services.platform_search.get_model", return_value=_TinyEmbeddingModel()
        )
        self._model_patch.start()

    def tearDown(self) -> None:
        self._model_patch.stop()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def _client(self) -> TestClient:
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        return TestClient(app)

    # ------------------------------------------------------------------
    # 1. Admin & SuperAdmin authentication and .NET forwarding contract
    # ------------------------------------------------------------------

    def test_valid_admin_and_superadmin_authentication(self) -> None:
        with self._client() as client:
            resp = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['admin']}"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.headers.get("x-auth-mode"), "bonc_jwt")
            body = resp.json()
            self.assertTrue(body["authenticated"])
            self.assertEqual(body["auth_method"], "bonc_jwt")
            self.assertEqual(body["auth_mode"], "bonc_jwt")
            self.assertEqual(body["user_id"], ADMIN_ID)
            self.assertEqual(body["actor"], ADMIN_ID)
            self.assertEqual(body["username"], "admin.demo@bonc.test")
            self.assertEqual(body["roles"], ["Admin"])
            self.assertNotIn("csrf_token", body)
            self.assertNotIn("local_login_enabled", body)
            self.assertIn("admin:categories:write", body["permissions"])

            # Verify exact request forwarded to .NET: unchanged token + token's UserRowId
            self.assertEqual(
                _FakeDotNetHandler.seen,
                [("/api/userService/getUserDetail", TOKENS["admin"], ADMIN_ID)],
            )

            # SuperAdmin
            resp_super = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['super']}"},
            )
            self.assertEqual(resp_super.status_code, 200)
            self.assertEqual(resp_super.json()["user_id"], SUPER_ID)
            self.assertEqual(resp_super.json()["roles"], ["SuperAdmin"])

            # Case-insensitive GUID match between token UserRowId and .NET response
            resp_guid = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['case_guid']}"},
            )
            self.assertEqual(resp_guid.status_code, 200)
            self.assertEqual(
                resp_guid.json()["user_id"],
                "ABCDEF01-2345-6789-ABCD-EF0123456789",
            )

    # ------------------------------------------------------------------
    # 2. Basic user 403, missing/invalid/expired/revoked/inactive 401
    # ------------------------------------------------------------------

    def test_basic_user_and_dotnet_403_rejected_with_403(self) -> None:
        with self._client() as client:
            r_basic = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": f"Bearer {TOKENS['basic']}"},
            )
            self.assertEqual(r_basic.status_code, 403)
            self.assertEqual(r_basic.headers.get("x-auth-mode"), "bonc_jwt")

            self.assertEqual(
                client.get(
                    "/api/admin/auth/session",
                    headers={"Authorization": f"Bearer {TOKENS['basic']}"},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['dotnet_403']}"},
                ).status_code,
                403,
            )

    def test_missing_invalid_expired_revoked_and_inactive_tokens_rejected_with_401(self) -> None:
        with self._client() as client:
            # Missing bearer token -> 401
            r_missing = client.get("/api/admin/platform/categories")
            self.assertEqual(r_missing.status_code, 401)
            self.assertEqual(r_missing.headers.get("www-authenticate"), "Bearer")

            # Expired/revoked token rejected by .NET -> 401
            r_revoked = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": f"Bearer {REVOKED_OR_EXPIRED_TOKEN}"},
            )
            self.assertEqual(r_revoked.status_code, 401)
            self.assertEqual(r_revoked.headers.get("www-authenticate"), "Bearer")

            # Non-JWT / missing UserRowId tokens never call .NET
            _FakeDotNetHandler.seen.clear()
            for junk in (
                "not-a-jwt",
                _fake_jwt({"sub": "x"}),
                _fake_jwt({"UserRowId": ""}),
                _fake_jwt({"UserRowId": True}),
                _fake_jwt({"UserRowId": "a" * 200}),
            ):
                with self.subTest(junk=junk[:30]):
                    r = client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {junk}"},
                    )
                    self.assertEqual(r.status_code, 401)
            self.assertEqual(_FakeDotNetHandler.seen, [])

            # Inactive/deactivated admin account -> 401
            r_inactive = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": f"Bearer {TOKENS['inactive']}"},
            )
            self.assertEqual(r_inactive.status_code, 401)

            # Live revocation with TTL=0: works before logout, fails immediately after logout
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                ).status_code,
                200,
            )
            _FakeDotNetHandler.revoked_tokens.add(TOKENS["admin"])
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                ).status_code,
                401,
            )

    # ------------------------------------------------------------------
    # 3. Bare DTO, mismatched UserRowId, Success:false, malformed, errors, timeouts
    # ------------------------------------------------------------------

    def test_bare_dto_response_is_supported(self) -> None:
        with self._client() as client:
            resp = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['bare']}"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["user_id"], BARE_ID)
            self.assertEqual(resp.json()["roles"], ["Admin"])

    def test_unexpected_responses_and_unavailable_endpoint_fail_closed_503(self) -> None:
        with self._client() as client:
            for label, tok_key in (
                ("mismatched_user_row_id", "swap"),
                ("success_false", "falsy"),
                ("invalid_json", "bad_json"),
                ("non_dict_json", "non_dict"),
                ("non_dict_data", "bad_data"),
                ("http_409", "boom_409"),
                ("http_500", "boom_500"),
                ("http_302_no_redirect", "redirect_302"),
            ):
                with self.subTest(case=label):
                    resp = client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS[tok_key]}"},
                    )
                    self.assertEqual(resp.status_code, 503)

        # Timeout against slow handler -> 503
        os.environ["BONC_AUTH_TIMEOUT"] = "0.1"
        admin_auth.reset_auth_provider()
        with self._client() as client:
            resp = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": f"Bearer {TOKENS['slow']}"},
            )
            self.assertEqual(resp.status_code, 503)

        # Explicit TimeoutException & ConnectError -> 503
        os.environ["BONC_AUTH_TIMEOUT"] = "1.0"
        admin_auth.reset_auth_provider()
        with self._client() as client:
            with patch(
                "app.services.bonc_auth_adapter.httpx.get",
                side_effect=httpx.TimeoutException("timed out"),
            ):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                    ).status_code,
                    503,
                )
            with patch(
                "app.services.bonc_auth_adapter.httpx.get",
                side_effect=httpx.ConnectError("connection refused"),
            ):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                    ).status_code,
                    503,
                )

    # ------------------------------------------------------------------
    # 4. Role parsing, delimiters, case-insensitive matching & custom roles
    # ------------------------------------------------------------------

    def test_role_parsing_delimiters_case_insensitive_and_configurable_roles(self) -> None:
        with self._client() as client:
            r1 = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['roles_semi']}"},
            )
            self.assertEqual(r1.status_code, 200)
            self.assertEqual(r1.json()["roles"], ["SuperAdmin"])

            r2 = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['roles_list']}"},
            )
            self.assertEqual(r2.status_code, 200)
            self.assertEqual(r2.json()["roles"], ["Admin"])

            r3 = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {TOKENS['role_singular']}"},
            )
            self.assertEqual(r3.status_code, 200)
            self.assertEqual(r3.json()["roles"], ["Admin"])

        os.environ["BONC_AUTH_ADMIN_ROLES"] = "SuperAdmin"
        admin_auth.reset_auth_provider()
        with self._client() as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['super']}"},
                ).status_code,
                200,
            )

    # ------------------------------------------------------------------
    # 5. Token caching: SHA-256 keys, hits, expiry, failures uncached, TTL=0
    # ------------------------------------------------------------------

    def test_cache_hit_sha256_keys_expiry_and_failures_never_cached(self) -> None:
        now = [1000.0]

        def fake_clock() -> float:
            return now[0]

        provider = bonc_auth_adapter.build_bonc_user_detail_provider(
            verify_url=self.detail_url,
            admin_roles=("Admin", "SuperAdmin"),
            timeout=5.0,
            cache_seconds=60.0,
            clock=fake_clock,
        )
        admin_auth.set_auth_provider(provider)
        cached_verifier = provider._verifier
        assert isinstance(cached_verifier, bonc_auth_adapter.CachedBoncTokenVerifier)

        with self._client() as client:
            _FakeDotNetHandler.seen.clear()
            for _ in range(4):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                )
                self.assertEqual(resp.status_code, 200)
            self.assertEqual(len(_FakeDotNetHandler.seen), 1)

            expected_hash = hashlib.sha256(TOKENS["admin"].encode("utf-8")).hexdigest()
            self.assertIn(expected_hash, cached_verifier._seen)
            self.assertNotIn(TOKENS["admin"], cached_verifier._seen)

            # Failures (401, 403, 503) are NEVER cached
            _FakeDotNetHandler.seen.clear()
            for _ in range(2):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS['basic']}"},
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {REVOKED_OR_EXPIRED_TOKEN}"},
                    ).status_code,
                    401,
                )
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS['falsy']}"},
                    ).status_code,
                    503,
                )
            self.assertEqual(len(_FakeDotNetHandler.seen), 6)
            self.assertEqual(len(cached_verifier._seen), 1)

            # Advance clock past 60s TTL -> forces fresh .NET call; revocation takes effect
            _FakeDotNetHandler.seen.clear()
            now[0] += 60.1
            _FakeDotNetHandler.revoked_tokens.add(TOKENS["admin"])
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                ).status_code,
                401,
            )
            self.assertEqual(len(_FakeDotNetHandler.seen), 1)

    def test_env_configured_cache_enabled_and_ttl_zero_disabled(self) -> None:
        os.environ["BONC_AUTH_CACHE_SECONDS"] = "60"
        admin_auth.reset_auth_provider()
        with self._client() as client:
            _FakeDotNetHandler.seen.clear()
            for _ in range(4):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                    ).status_code,
                    200,
                )
            self.assertEqual(len(_FakeDotNetHandler.seen), 1)

        os.environ["BONC_AUTH_CACHE_SECONDS"] = "0"
        admin_auth.reset_auth_provider()
        with self._client() as client:
            _FakeDotNetHandler.seen.clear()
            for _ in range(3):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {TOKENS['admin']}"},
                    ).status_code,
                    200,
                )
            self.assertEqual(len(_FakeDotNetHandler.seen), 3)

    # ------------------------------------------------------------------
    # 6. Zero authentication bypass, zero fallback, and no token logging
    # ------------------------------------------------------------------

    def test_no_authentication_bypass_or_fallback_exists(self) -> None:
        # Even if legacy env flags or unrelated tokens are present, BONC auth stays mandatory
        os.environ["AUTH_DISABLED"] = "1"
        os.environ["SEARCH_ADMIN_AUTH_MODE"] = "local_session"
        os.environ["PRODUCTION_SEARCH_AUTH_TOKEN"] = "prod-obs-secret-token-999"
        admin_auth.reset_auth_provider()

        with self._client() as client:
            # Unauthenticated request is still 401 (AUTH_DISABLED=1 has zero bypass effect)
            self.assertEqual(client.get("/api/admin/platform/categories").status_code, 401)
            # X-Admin-Token header never grants access
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"X-Admin-Token": "any-static-token"},
                ).status_code,
                401,
            )
            # Rejected Bearer + X-Admin-Token + cookie never falls back
            client.cookies.set("bonc_search_admin_platform_session", "fake-legacy-cookie")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={
                        "Authorization": f"Bearer {REVOKED_OR_EXPIRED_TOKEN}",
                        "X-Admin-Token": "any-static-token",
                    },
                ).status_code,
                401,
            )
            # Production observability token is rejected before calling BONC .NET
            _FakeDotNetHandler.seen.clear()
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer prod-obs-secret-token-999"},
                ).status_code,
                401,
            )
            self.assertEqual(_FakeDotNetHandler.seen, [])

            # Removed local login & logout routes do not exist (404)
            self.assertEqual(
                client.post(
                    "/api/admin/auth/login",
                    json={"username": "ops", "password": "secret"},
                ).status_code,
                404,
            )
            self.assertEqual(client.post("/api/admin/auth/logout").status_code, 404)

    def test_raw_token_never_logged(self) -> None:
        records: list[str] = []

        class _CaptureHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = _CaptureHandler()
        root_logger = logging.getLogger("search-admin-platform")
        root_logger.addHandler(handler)
        try:
            with self._client() as client:
                for tok in (TOKENS["admin"], TOKENS["basic"], REVOKED_OR_EXPIRED_TOKEN, TOKENS["falsy"]):
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {tok}"},
                    )
        finally:
            root_logger.removeHandler(handler)

        combined_logs = "\n".join(records)
        for tok in (TOKENS["admin"], TOKENS["basic"], REVOKED_OR_EXPIRED_TOKEN, TOKENS["falsy"]):
            self.assertNotIn(tok, combined_logs)

    # ------------------------------------------------------------------
    # 7. Protected routes, APP_ENV behavior, startup validation, unconfigured 503
    # ------------------------------------------------------------------

    def test_existing_protected_search_admin_routes_and_public_routes_work(self) -> None:
        with self._client() as client:
            ready = client.get("/health/ready")
            self.assertEqual(ready.status_code, 200)
            self.assertEqual(ready.json()["checks"]["authMode"], "bonc_jwt")
            self.assertEqual(ready.json()["checks"]["authProvider"], "ready")
            self.assertNotIn("authStore", ready.json()["checks"])

            admin_hdr = {"Authorization": f"Bearer {TOKENS['admin']}"}
            basic_hdr = {"Authorization": f"Bearer {TOKENS['basic']}"}

            created = client.post(
                "/api/admin/platform/categories",
                json=_sample_category("people", public=True),
                headers=admin_hdr,
            )
            self.assertEqual(created.status_code, 201)
            self.assertEqual(created.json()["updated_by"], ADMIN_ID)

            history = client.get(
                "/api/admin/platform/categories/people/history",
                headers=admin_hdr,
            )
            self.assertEqual(history.status_code, 200)
            self.assertEqual(history.json()["items"][0]["changed_by"], ADMIN_ID)

            ing = client.post(
                "/api/admin/platform/categories/people/ingest",
                json={
                    "documents": [
                        {
                            "document_id": "p-1",
                            "title": "Alice Engineer",
                            "fields": {"title": "Alice Engineer"},
                        }
                    ],
                    "replace_all": True,
                },
                headers=admin_hdr,
            )
            self.assertEqual(ing.status_code, 200)

            search = client.post(
                "/api/admin/platform/search",
                json={"category": "people", "query": "Alice"},
                headers=admin_hdr,
            )
            self.assertEqual(search.status_code, 200)
            self.assertEqual(search.json()["total_count"], 1)

            self.assertEqual(
                client.get("/api/admin/platform/system-health", headers=admin_hdr).status_code,
                200,
            )
            self.assertEqual(
                client.get("/api/admin/platform/search-logs", headers=admin_hdr).status_code,
                200,
            )
            self.assertEqual(
                client.get("/api/admin/platform/metrics/kpis", headers=admin_hdr).status_code,
                200,
            )

            for path in (
                "/api/admin/platform/categories",
                "/api/admin/platform/system-health",
                "/api/admin/platform/search-logs",
                "/api/admin/platform/metrics/kpis",
            ):
                self.assertEqual(client.get(path, headers=basic_hdr).status_code, 403)

            self.assertEqual(client.get("/api/platform/categories").status_code, 200)
            self.assertEqual(
                client.post(
                    "/api/platform/search",
                    json={"category": "people", "query": "Alice"},
                ).status_code,
                200,
            )

    def test_app_env_behaviors_and_bad_configuration_fail_closed(self) -> None:
        # Unset BONC_AUTH_VERIFY_URL fails closed with 503 in local, staging, and production
        os.environ.pop("BONC_AUTH_VERIFY_URL", None)
        for env_name, expect_docs in (("local", 200), ("staging", 404), ("production", 404)):
            os.environ["APP_ENV"] = env_name
            admin_auth.reset_auth_provider()
            with self._client() as client:
                self.assertEqual(client.get("/api/admin/platform/categories").status_code, 503)
                ready = client.get("/health/ready")
                self.assertEqual(ready.status_code, 503)
                self.assertEqual(ready.json()["checks"]["authProvider"], "not_configured")
                self.assertEqual(client.get("/docs").status_code, expect_docs)

        # Empty BONC_AUTH_ADMIN_ROLES stops startup
        os.environ["APP_ENV"] = "local"
        os.environ["BONC_AUTH_VERIFY_URL"] = self.detail_url
        os.environ["BONC_AUTH_ADMIN_ROLES"] = " , "
        admin_auth.reset_auth_provider()
        with self.assertRaisesRegex(ValueError, "BONC_AUTH_ADMIN_ROLES"):
            create_app(warmup_embedding_model=False, connect_platform_database=False)

        # Plain HTTP to non-localhost remote host stops startup
        os.environ["BONC_AUTH_ADMIN_ROLES"] = "Admin,SuperAdmin"
        os.environ["BONC_AUTH_VERIFY_URL"] = "http://api.example.com/api/userService/getUserDetail"
        admin_auth.reset_auth_provider()
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            create_app(warmup_embedding_model=False, connect_platform_database=False)

        # Env parsing normalization
        os.environ["BONC_AUTH_ADMIN_ROLES"] = "Admin, SuperAdmin ,"
        os.environ["BONC_AUTH_CACHE_SECONDS"] = "0"
        self.assertEqual(app_config.get_bonc_auth_admin_roles(), ("Admin", "SuperAdmin"))
        self.assertEqual(app_config.get_bonc_auth_cache_seconds(), 0.0)


if __name__ == "__main__":
    unittest.main()
