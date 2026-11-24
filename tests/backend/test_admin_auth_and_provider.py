"""Centralized Admin authentication, CSRF, rate limiting, service token & BONC JWT provider tests."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import select

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db import auth_db, platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import admin_auth  # noqa: E402


def _sample_push_category(category_id: str = "people") -> dict:
    return {
        "category_id": category_id,
        "display_name": "People",
        "description": "People directory",
        "source": {"type": "push"},
        "fields": [
            {
                "key": "full_name",
                "source_column": "FullName",
                "label": "Full Name",
                "role": "title",
                "weight": 4.0,
                "searchable": True,
                "semantic": True,
                "aliases": ["name"],
            }
        ],
        "active": True,
        "public_search_enabled": False,
    }


class TestAdminAuthAndProvider(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["SEARCH_ADMIN_AUTH_DB_URL"] = "sqlite:///:memory:"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        os.environ["SEARCH_ADMIN_LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = "3"
        os.environ["SEARCH_ADMIN_LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = "60"
        os.environ.pop("SEARCH_ADMIN_USERNAME", None)
        os.environ.pop("SEARCH_ADMIN_PASSWORD_HASH", None)
        os.environ.pop("SEARCH_ADMIN_SERVICE_TOKEN", None)

        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        admin_auth.reset_auth_provider()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

    def tearDown(self) -> None:
        admin_auth.reset_auth_provider()
        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_password_hashing_and_validation_bounds(self) -> None:
        scrypt_hash = admin_auth.hash_password("SuperSecretPassword!123", scheme="scrypt")
        self.assertTrue(admin_auth.verify_password("SuperSecretPassword!123", scrypt_hash))
        self.assertFalse(admin_auth.verify_password("WrongPassword!123", scrypt_hash))

        pbkdf2_hash = admin_auth.hash_password("AnotherStrongPass!456", scheme="pbkdf2_sha256")
        self.assertTrue(admin_auth.verify_password("AnotherStrongPass!456", pbkdf2_hash))
        self.assertFalse(admin_auth.verify_password("WrongPass", pbkdf2_hash))

        # Reject weak/malformed hashes
        self.assertIsNone(admin_auth.parse_password_hash("plaintext"))
        self.assertIsNone(admin_auth.parse_password_hash("scrypt$1024$8$1$00$00"))
        self.assertIsNone(admin_auth.parse_password_hash("pbkdf2_sha256$1000$00$00"))

    def test_fail_closed_503_when_unconfigured(self) -> None:
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            resp = client.get("/api/admin/platform/categories")
            self.assertEqual(resp.status_code, 503)
            self.assertEqual(client.get("/api/admin/auth/session").status_code, 503)
            login_resp = client.post(
                "/api/admin/auth/login",
                json={"username": "ops", "password": "secret"},
            )
            self.assertEqual(login_resp.status_code, 503)

    def test_production_forces_secure_cookie_and_rejects_prod_observability_token_as_admin_bearer(
        self,
    ) -> None:
        os.environ["APP_ENV"] = "production"
        os.environ["SEARCH_ADMIN_COOKIE_SECURE"] = "false"
        self.assertTrue(admin_auth.cookie_secure())

        os.environ["APP_ENV"] = "local"
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password(
            "ValidAdminPassword!2026"
        )
        os.environ["PRODUCTION_SEARCH_AUTH_TOKEN"] = "outbound-prod-only-token"
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            resp = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": "Bearer outbound-prod-only-token"},
            )
            self.assertEqual(resp.status_code, 403)

    def test_session_cookie_csrf_actor_propagation_rotation_and_logout(self) -> None:
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password(
            "ValidAdminPassword!2026"
        )

        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            # Unauthenticated -> 401
            self.assertEqual(client.get("/api/admin/platform/categories").status_code, 401)

            # Login sets dedicated cookie name & no-store headers
            login = client.post(
                "/api/admin/auth/login",
                json={"username": "ops.admin", "password": "ValidAdminPassword!2026"},
            )
            self.assertEqual(login.status_code, 200)
            self.assertEqual(login.headers.get("cache-control"), "no-store")
            set_cookie = login.headers.get("set-cookie", "")
            self.assertIn(admin_auth.SESSION_COOKIE_NAME, set_cookie)
            self.assertNotIn("bonc_search_admin_session=", set_cookie)
            self.assertIn("HttpOnly", set_cookie)

            session_body = login.json()
            self.assertTrue(session_body["authenticated"])
            self.assertEqual(session_body["actor"], "ops.admin")
            self.assertEqual(session_body["roles"], ["admin"])
            csrf_token = session_body["csrf_token"]
            self.assertTrue(csrf_token)

            # Raw cookie token is NEVER persisted in SQLite — only its SHA-256 hash
            raw_cookie = client.cookies.get(admin_auth.SESSION_COOKIE_NAME)
            self.assertIsNotNone(raw_cookie)
            with auth_db.get_auth_engine().connect() as conn:
                stored_hashes = conn.execute(
                    select(auth_db.admin_sessions_table.c.SessionTokenHash)
                ).scalars().all()
            self.assertEqual(len(stored_hashes), 1)
            self.assertNotEqual(stored_hashes[0], raw_cookie)
            self.assertEqual(stored_hashes[0], admin_auth.hash_session_token(raw_cookie))

            # GET session works
            sess = client.get("/api/admin/auth/session")
            self.assertEqual(sess.status_code, 200)
            self.assertEqual(sess.json()["actor"], "ops.admin")

            # Write without CSRF -> 403
            no_csrf = client.post(
                "/api/admin/platform/categories",
                json=_sample_push_category("people"),
            )
            self.assertEqual(no_csrf.status_code, 403)
            self.assertIn("CSRF", no_csrf.json()["detail"])

            # Write with wrong CSRF -> 403
            wrong_csrf = client.post(
                "/api/admin/platform/categories",
                json=_sample_push_category("people"),
                headers={"X-CSRF-Token": "wrong-csrf-token"},
            )
            self.assertEqual(wrong_csrf.status_code, 403)

            # Write with CSRF -> 201 and propagates real admin actor to UpdatedBy & History.ChangedBy
            created = client.post(
                "/api/admin/platform/categories",
                json=_sample_push_category("people"),
                headers={"X-CSRF-Token": csrf_token},
            )
            self.assertEqual(created.status_code, 201)
            self.assertEqual(created.json()["updated_by"], "ops.admin")

            history = client.get("/api/admin/platform/categories/people/history")
            self.assertEqual(history.status_code, 200)
            self.assertEqual(history.json()["items"][0]["changed_by"], "ops.admin")

            # Re-login rotates session & revokes previous cookie token
            old_cookie = raw_cookie
            relogin = client.post(
                "/api/admin/auth/login",
                json={"username": "ops.admin", "password": "ValidAdminPassword!2026"},
            )
            self.assertEqual(relogin.status_code, 200)
            new_csrf = relogin.json()["csrf_token"]
            self.assertNotEqual(new_csrf, csrf_token)
            self.assertIsNone(admin_auth.validate_session_token(old_cookie))

            # Logout without CSRF -> 403
            self.assertEqual(client.post("/api/admin/auth/logout").status_code, 403)

            # Logout with valid CSRF revokes active session and invalidates cookie replay
            active_cookie = client.cookies.get(admin_auth.SESSION_COOKIE_NAME)
            logout = client.post(
                "/api/admin/auth/logout",
                headers={"X-CSRF-Token": new_csrf},
            )
            self.assertEqual(logout.status_code, 200)
            self.assertIsNone(admin_auth.validate_session_token(active_cookie))
            client.cookies.set(admin_auth.SESSION_COOKIE_NAME, active_cookie)
            self.assertEqual(client.get("/api/admin/platform/categories").status_code, 401)

    def test_rate_limiting_blocks_after_max_failed_attempts(self) -> None:
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password(
            "ValidAdminPassword!2026"
        )
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            for _ in range(3):
                resp = client.post(
                    "/api/admin/auth/login",
                    json={"username": "ops.admin", "password": "wrong-password"},
                )
                self.assertEqual(resp.status_code, 401)

            blocked = client.post(
                "/api/admin/auth/login",
                json={"username": "ops.admin", "password": "ValidAdminPassword!2026"},
            )
            self.assertEqual(blocked.status_code, 429)
            self.assertIn("retry-after", blocked.headers)

    def test_optional_cli_service_bearer_token(self) -> None:
        os.environ["SEARCH_ADMIN_SERVICE_TOKEN"] = "cli-eval-secret-token-987654"
        os.environ["SEARCH_ADMIN_SERVICE_ACTOR"] = "admin:eval-cli"

        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            bad = client.get(
                "/api/admin/platform/categories",
                headers={"Authorization": "Bearer wrong-token"},
            )
            self.assertEqual(bad.status_code, 403)

            ok = client.post(
                "/api/admin/platform/categories",
                json=_sample_push_category("jobs"),
                headers={"Authorization": "Bearer cli-eval-secret-token-987654"},
            )
            self.assertEqual(ok.status_code, 201)
            self.assertEqual(ok.json()["updated_by"], "admin:eval-cli")

    def test_pluggable_bonc_jwt_auth_provider_without_route_changes(self) -> None:
        class MockBoncJwtAuthProvider(admin_auth.AdminAuthProvider):
            def is_configured(self) -> bool:
                return True

            def authorize_request(
                self,
                request: Request | None = None,
                *,
                authorization: str | None = None,
                require_csrf: bool = True,
            ) -> admin_auth.AdminPrincipal:
                header = authorization or (
                    request.headers.get("authorization") if request is not None else None
                )
                if header != "Bearer bonc-jwt-valid-token":
                    raise HTTPException(status_code=401, detail="Invalid BONC JWT")
                principal = admin_auth.AdminPrincipal(
                    actor="jwt:alice@bonc.in",
                    username="alice@bonc.in",
                    auth_method="jwt",
                    roles=("admin", "bonc_superadmin"),
                )
                admin_auth._attach_request_principal(request, principal)
                return principal

        admin_auth.set_auth_provider(MockBoncJwtAuthProvider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/admin/platform/categories").status_code, 401)
            created = client.post(
                "/api/admin/platform/categories",
                json=_sample_push_category("articles"),
                headers={"Authorization": "Bearer bonc-jwt-valid-token"},
            )
            self.assertEqual(created.status_code, 201)
            self.assertEqual(created.json()["updated_by"], "jwt:alice@bonc.in")

    def test_session_expiration_and_cookie_clearing(self) -> None:
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password(
            "ValidAdminPassword!2026"
        )
        auth_db.init_auth_db("sqlite:///:memory:")
        created_at = admin_auth.utc_now_naive() - timedelta(minutes=10)
        raw_token, session = admin_auth.create_session(
            "ops.admin",
            client_ip="127.0.0.1",
            user_agent="UnitTest/1.0",
            ttl_seconds=60,
            now_utc=created_at,
        )
        # Valid within TTL window
        valid = admin_auth.validate_session_token(
            raw_token,
            now_utc=created_at + timedelta(seconds=30),
            touch=False,
        )
        self.assertIsNotNone(valid)
        self.assertEqual(valid.session_id, session.session_id)

        # Expired once past ExpiresAtUtc
        self.assertIsNone(
            admin_auth.validate_session_token(
                raw_token,
                now_utc=created_at + timedelta(seconds=61),
                touch=False,
            )
        )

        # HTTP /session rejects expired cookie with 401 and clears cookie
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            client.cookies.set(admin_auth.SESSION_COOKIE_NAME, raw_token)
            resp = client.get("/api/admin/auth/session")
            self.assertEqual(resp.status_code, 401)
            self.assertIn(admin_auth.SESSION_COOKIE_NAME, resp.headers.get("set-cookie", ""))

    def test_auth_db_sqlite_file_persistence_and_rate_limit_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "admin_auth_test.db"
            db_url = f"sqlite:///{db_path.as_posix()}"
            os.environ["SEARCH_ADMIN_AUTH_DB_URL"] = db_url

            auth_db.reset_auth_engine()
            engine_1 = auth_db.init_auth_db(db_url)
            self.assertTrue(auth_db.check_auth_db_ready())
            self.assertIsNotNone(engine_1)

            raw_token, session = admin_auth.create_session(
                "ops.admin",
                client_ip="10.0.0.5",
                user_agent="PersistCheck/1.0",
                ttl_seconds=3600,
            )
            admin_auth.record_login_attempt("10.0.0.9", succeeded=False)
            admin_auth.record_login_attempt("10.0.0.9", succeeded=False)
            admin_auth.record_login_attempt("10.0.0.9", succeeded=False)

            # Simulate backend restart: dispose SQLAlchemy engine and reopen the same SQLite file
            auth_db.reset_auth_engine()
            auth_db.init_auth_db(db_url)
            self.assertTrue(auth_db.check_auth_db_ready())

            reloaded = admin_auth.validate_session_token(raw_token)
            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded.session_id, session.session_id)
            self.assertEqual(reloaded.username, "ops.admin")

            allowed, retry_after = admin_auth.check_login_rate_limit("10.0.0.9")
            self.assertFalse(allowed)
            self.assertGreaterEqual(retry_after, 1)

            # Release SQLite handle cleanly before tempdir cleanup on Windows
            auth_db.reset_auth_engine()


if __name__ == "__main__":
    unittest.main()
