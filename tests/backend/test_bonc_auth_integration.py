"""Comprehensive BONC authentication, JWT validation, authorization, route protection & regression tests.

NOTE: All JWT signing keys, tokens, and verifiers in this module are strictly
test-only fixtures. Passing these tests proves Search_Admin's internal provider,
claims-policy, authorization, route-protection, and fail-closed behavior; it
does NOT prove genuine end-to-end validation against BONC's live/staging
authentication service until BONC's confirmed contract and key/endpoint config
are supplied.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
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

from app.db import auth_db, platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import admin_auth, bonc_auth, embedding_model, platform_search  # noqa: E402


# ---------------------------------------------------------------------------
# Test-only signed JWT & introspection fixtures (NEVER used in production)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_test_hs_jwt(
    payload: dict,
    *,
    secret: str,
    alg: str = "HS256",
    kid: str | None = "test-kid-v1",
    typ: str | None = "JWT",
) -> str:
    header: dict = {"alg": alg}
    if typ is not None:
        header["typ"] = typ
    if kid is not None:
        header["kid"] = kid
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    if alg == "HS256":
        sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    elif alg == "HS512":
        sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha512).digest()
    elif alg == "none":
        sig = b""
    else:
        sig = b"unsupported"
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


class _TestOnlySignedJwtVerifier(bonc_auth.BoncTokenVerifier):
    """Isolated test-only verifier validating HS256 signatures and key rotation."""

    def __init__(
        self,
        keys_by_kid: dict[str, str],
        *,
        allowed_algorithms: frozenset[str] = frozenset({"HS256"}),
        unavailable: bool = False,
    ) -> None:
        self._keys_by_kid = dict(keys_by_kid)
        self._allowed_algorithms = allowed_algorithms
        self._unavailable = unavailable

    def is_configured(self) -> bool:
        return bool(self._keys_by_kid)

    def verify_access_token(self, raw_token: str) -> bonc_auth.VerifiedBoncIdentity:
        if self._unavailable:
            raise bonc_auth.BoncAuthUnavailableError("Test JWKS/auth backend timed out")

        header = bonc_auth.inspect_jwt_structure_and_header(
            raw_token,
            allowed_algorithms=self._allowed_algorithms,
        )
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self._keys_by_kid:
            raise bonc_auth.BoncTokenInvalidError("Unknown signing key ID (kid)")

        segments = raw_token.split(".")
        signing_input = f"{segments[0]}.{segments[1]}".encode("ascii")
        expected_sig = hmac.new(
            self._keys_by_kid[kid].encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        supplied_sig = bonc_auth._b64url_decode(segments[2])
        if not hmac.compare_digest(supplied_sig, expected_sig):
            raise bonc_auth.BoncTokenInvalidError("Invalid JWT signature")

        payload = json.loads(bonc_auth._b64url_decode(segments[1]).decode("utf-8"))
        exp = payload.get("exp")
        nbf = payload.get("nbf")
        iat = payload.get("iat")
        aud_raw = payload.get("aud")
        aud: str | tuple[str, ...] | None
        if isinstance(aud_raw, list):
            aud = tuple(str(x) for x in aud_raw)
        elif isinstance(aud_raw, str):
            aud = aud_raw
        else:
            aud = None
        roles_raw = payload.get("roles", ())
        if isinstance(roles_raw, str):
            roles = (roles_raw,)
        elif isinstance(roles_raw, list):
            roles = tuple(str(r) for r in roles_raw)
        else:
            roles = ()

        return bonc_auth.VerifiedBoncIdentity(
            user_id=str(payload.get("sub") or ""),
            username=payload.get("unique_name"),
            issuer=payload.get("iss"),
            audience=aud,
            expires_at_utc=(
                datetime.fromtimestamp(int(exp), tz=timezone.utc).replace(tzinfo=None)
                if isinstance(exp, (int, float))
                else None
            ),
            not_before_utc=(
                datetime.fromtimestamp(int(nbf), tz=timezone.utc).replace(tzinfo=None)
                if isinstance(nbf, (int, float))
                else None
            ),
            issued_at_utc=(
                datetime.fromtimestamp(int(iat), tz=timezone.utc).replace(tzinfo=None)
                if isinstance(iat, (int, float))
                else None
            ),
            algorithm=str(header.get("alg") or ""),
            key_id=kid,
            token_type=header.get("typ"),
            token_id=payload.get("jti"),
            roles=roles,
        )


class _TestOnlyIntrospectionVerifier(bonc_auth.BoncTokenVerifier):
    """Isolated test-only verifier modeling server-side token introspection."""

    def __init__(self, responses: dict[str, dict], *, raise_timeout: bool = False) -> None:
        self._responses = responses
        self._raise_timeout = raise_timeout

    def is_configured(self) -> bool:
        return True

    def verify_access_token(self, raw_token: str) -> bonc_auth.VerifiedBoncIdentity:
        if self._raise_timeout:
            raise bonc_auth.BoncAuthUnavailableError("Introspection endpoint timeout")
        record = self._responses.get(raw_token)
        if not record or not record.get("active"):
            raise bonc_auth.BoncTokenInvalidError("Token inactive or revoked")
        return bonc_auth.VerifiedBoncIdentity(
            user_id=record["user_id"],
            username=record.get("username"),
            issuer=record["iss"],
            audience=record["aud"],
            expires_at_utc=record["exp"],
            algorithm=None,
            roles=tuple(record.get("roles", ())),
        )


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


class TestBoncAuthIntegrationPreparation(unittest.TestCase):
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
        os.environ.pop("SEARCH_ADMIN_ENABLE_API_DOCS", None)

        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

        self._model_patch = patch(
            "app.services.platform_search.get_model", return_value=_TinyEmbeddingModel()
        )
        self._model_patch.start()

        self.now = datetime.now(timezone.utc)
        self.keys = {
            "test-kid-v1": "test-only-signing-secret-v1-not-for-prod",
            "test-kid-v2": "test-only-signing-secret-v2-not-for-prod",
        }
        self.claims_cfg = bonc_auth.BoncClaimsValidationConfig(
            allowed_algorithms=frozenset({"HS256"}),
            expected_issuer="https://auth.bonc.test",
            expected_audience="bonc-search-admin-test",
            allowed_key_ids=frozenset(self.keys.keys()),
            expected_token_type="JWT",
            clock_skew_seconds=5,
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

    def _build_configured_provider(
        self,
        *,
        keys: dict[str, str] | None = None,
        claims_cfg: bonc_auth.BoncClaimsValidationConfig | None = None,
        role_policy: bonc_auth.BoncRoleAuthorizationPolicy | None = None,
        allow_cli_service_token: bool = False,
        unavailable: bool = False,
    ) -> bonc_auth.BoncJwtAuthProvider:
        verifier = _TestOnlySignedJwtVerifier(
            keys if keys is not None else self.keys,
            unavailable=unavailable,
        )
        return bonc_auth.BoncJwtAuthProvider(
            verifier=verifier,
            claims_config=claims_cfg or self.claims_cfg,
            role_policy=role_policy if role_policy is not None else self.role_policy,
            allow_cli_service_token=allow_cli_service_token,
        )

    def _mint_token(
        self,
        *,
        user_id: str = "bonc-user-uuid-1001",
        username: str = "admin.alice",
        roles: list[str] | None = None,
        iss: str = "https://auth.bonc.test",
        aud: str | list[str] = "bonc-search-admin-test",
        exp_delta: timedelta = timedelta(minutes=30),
        nbf_delta: timedelta | None = timedelta(minutes=-1),
        alg: str = "HS256",
        kid: str | None = "test-kid-v1",
        typ: str | None = "JWT",
        secret: str | None = None,
    ) -> str:
        payload: dict = {
            "iss": iss,
            "aud": aud,
            "exp": int((self.now + exp_delta).timestamp()),
            "iat": int(self.now.timestamp()),
            "jti": "jti-test-001",
        }
        if user_id:
            payload["sub"] = user_id
        if username:
            payload["unique_name"] = username
        if roles is not None:
            payload["roles"] = roles
        if nbf_delta is not None:
            payload["nbf"] = int((self.now + nbf_delta).timestamp())
        signing_secret = secret or self.keys.get(kid or "test-kid-v1", self.keys["test-kid-v1"])
        return _make_test_hs_jwt(payload, secret=signing_secret, alg=alg, kid=kid, typ=typ)

    # ------------------------------------------------------------------
    # 1. Fail-closed mode selection & no automatic fallback to local auth
    # ------------------------------------------------------------------

    def test_non_local_envs_default_to_fail_closed_bonc_and_forbid_local_session(self) -> None:
        # Even if local admin credentials exist in env, staging/production MUST fail closed.
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password("ValidLocalPass!2026")

        for env_name in ("staging", "production"):
            os.environ["APP_ENV"] = env_name
            os.environ.pop("SEARCH_ADMIN_AUTH_MODE", None)
            provider = admin_auth.get_auth_provider()
            self.assertEqual(provider.auth_mode, "bonc_jwt")
            self.assertFalse(provider.supports_local_login())
            self.assertFalse(provider.is_configured())

            app = create_app(warmup_embedding_model=False, connect_platform_database=False)
            with TestClient(app) as client:
                # Admin routes fail closed with 503 + X-Auth-Mode header
                resp = client.get("/api/admin/platform/categories")
                self.assertEqual(resp.status_code, 503)
                self.assertEqual(resp.headers.get("x-auth-mode"), "bonc_jwt")

                # Local login and logout routes are disabled (404)
                login = client.post(
                    "/api/admin/auth/login",
                    json={"username": "ops.admin", "password": "ValidLocalPass!2026"},
                )
                self.assertEqual(login.status_code, 404)
                logout = client.post("/api/admin/auth/logout")
                self.assertEqual(logout.status_code, 404)

                # Readiness reports unconfigured auth provider -> 503 (never silent ready)
                ready = client.get("/health/ready")
                self.assertEqual(ready.status_code, 503)
                self.assertEqual(ready.json()["checks"]["authProvider"], "not_configured")
                self.assertEqual(ready.json()["checks"]["authStore"], "not_used")

                # Swagger/OpenAPI docs disabled by default outside local
                self.assertEqual(client.get("/docs").status_code, 404)
                self.assertEqual(client.get("/openapi.json").status_code, 404)

            # Attempting to force local_session in staging/production is rejected fail-closed (503)
            os.environ["SEARCH_ADMIN_AUTH_MODE"] = "local_session"
            bad_provider = admin_auth.get_auth_provider()
            self.assertEqual(bad_provider.auth_mode, "invalid")
            self.assertFalse(bad_provider.supports_local_login())
            app_bad = create_app(warmup_embedding_model=False, connect_platform_database=False)
            with TestClient(app_bad) as client:
                self.assertEqual(client.get("/api/admin/platform/categories").status_code, 503)
                self.assertEqual(
                    client.post(
                        "/api/admin/auth/login",
                        json={"username": "ops.admin", "password": "ValidLocalPass!2026"},
                    ).status_code,
                    404,
                )

    def test_bonc_mode_ignores_valid_local_session_cookie_with_zero_fallback(self) -> None:
        # Create a valid local SQLite session first, then switch to BONC mode.
        os.environ["SEARCH_ADMIN_AUTH_MODE"] = "local_session"
        os.environ["SEARCH_ADMIN_USERNAME"] = "ops.admin"
        os.environ["SEARCH_ADMIN_PASSWORD_HASH"] = admin_auth.hash_password("ValidLocalPass!2026")
        auth_db.init_auth_db("sqlite:///:memory:")
        raw_cookie, session = admin_auth.create_session("ops.admin", ttl_seconds=3600)

        os.environ["SEARCH_ADMIN_AUTH_MODE"] = "bonc_jwt"
        admin_auth.set_auth_provider(self._build_configured_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            client.cookies.set(admin_auth.SESSION_COOKIE_NAME, raw_cookie)
            resp = client.get(
                "/api/admin/platform/categories",
                headers={"X-CSRF-Token": session.csrf_token},
            )
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.headers.get("www-authenticate"), "Bearer")

    # ------------------------------------------------------------------
    # 2. Token extraction tests
    # ------------------------------------------------------------------

    def test_bearer_token_extraction_cases(self) -> None:
        self.assertEqual(bonc_auth.extract_bearer_token("Bearer abc.def.ghi"), "abc.def.ghi")
        self.assertEqual(bonc_auth.extract_bearer_token("bearer   abc.def.ghi  "), "abc.def.ghi")

        invalid_headers = [
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
        ]
        for header in invalid_headers:
            with self.subTest(header=header):
                with self.assertRaises(bonc_auth.BoncTokenExtractionError):
                    bonc_auth.extract_bearer_token(header)

        admin_auth.set_auth_provider(self._build_configured_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            for bad_header in ("Basic dXNlcjpwYXNz", "Bearer ", "Bearer a b", "RawTokenOnly"):
                resp = client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": bad_header},
                )
                self.assertEqual(resp.status_code, 401)

    # ------------------------------------------------------------------
    # 3. Token verification tests (JWT + key rotation + introspection + failures)
    # ------------------------------------------------------------------

    def test_jwt_verification_valid_invalid_alg_expiry_iss_aud_nbf_kid_rotation_and_unavailable(
        self,
    ) -> None:
        provider = self._build_configured_provider()
        admin_auth.set_auth_provider(provider)
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        with TestClient(app) as client:
            # Valid signature & claims -> 200
            valid_tok = self._mint_token(roles=["Admin"])
            ok = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": f"Bearer {valid_tok}"},
            )
            self.assertEqual(ok.status_code, 200)
            body = ok.json()
            self.assertTrue(body["authenticated"])
            self.assertEqual(body["auth_method"], "bonc_jwt")
            self.assertEqual(body["auth_mode"], "bonc_jwt")
            self.assertEqual(body["user_id"], "bonc-user-uuid-1001")
            self.assertEqual(body["actor"], "bonc-user-uuid-1001")
            self.assertEqual(body["username"], "admin.alice")
            self.assertIsNone(body["csrf_token"])
            self.assertFalse(body["local_login_enabled"])

            # Invalid signature -> 401
            bad_sig = self._mint_token(roles=["Admin"], secret="wrong-signing-key")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {bad_sig}"},
                ).status_code,
                401,
            )

            # alg=none unsigned token -> 401
            alg_none = self._mint_token(roles=["Admin"], alg="none")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {alg_none}"},
                ).status_code,
                401,
            )

            # Unsupported algorithm HS512 -> 401
            bad_alg = self._mint_token(roles=["Admin"], alg="HS512")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {bad_alg}"},
                ).status_code,
                401,
            )

            # Expired token -> 401
            expired = self._mint_token(roles=["Admin"], exp_delta=timedelta(minutes=-5))
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {expired}"},
                ).status_code,
                401,
            )

            # Wrong issuer -> 401
            wrong_iss = self._mint_token(roles=["Admin"], iss="https://evil.example.com")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {wrong_iss}"},
                ).status_code,
                401,
            )

            # Wrong audience -> 401
            wrong_aud = self._mint_token(roles=["Admin"], aud="other-service")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {wrong_aud}"},
                ).status_code,
                401,
            )

            # Invalid nbf (in future) -> 401
            future_nbf = self._mint_token(roles=["Admin"], nbf_delta=timedelta(minutes=10))
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {future_nbf}"},
                ).status_code,
                401,
            )

            # Missing required identity (sub empty) -> 401
            no_sub = self._mint_token(user_id="", roles=["Admin"])
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {no_sub}"},
                ).status_code,
                401,
            )

            # Invalid / unknown kid -> 401
            bad_kid = self._mint_token(roles=["Admin"], kid="unknown-kid")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {bad_kid}"},
                ).status_code,
                401,
            )

            # Key rotation: token signed with test-kid-v2 succeeds while both v1 & v2 trusted
            rotated_tok = self._mint_token(roles=["Admin"], kid="test-kid-v2")
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {rotated_tok}"},
                ).status_code,
                200,
            )

        # After retiring test-kid-v1, old key tokens are rejected while v2 continues working
        retired_v1_keys = {"test-kid-v2": self.keys["test-kid-v2"]}
        retired_cfg = bonc_auth.BoncClaimsValidationConfig(
            allowed_algorithms=frozenset({"HS256"}),
            expected_issuer="https://auth.bonc.test",
            expected_audience="bonc-search-admin-test",
            allowed_key_ids=frozenset({"test-kid-v2"}),
            expected_token_type="JWT",
            clock_skew_seconds=5,
        )
        admin_auth.set_auth_provider(
            self._build_configured_provider(keys=retired_v1_keys, claims_cfg=retired_cfg)
        )
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {valid_tok}"},
                ).status_code,
                401,
            )
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {rotated_tok}"},
                ).status_code,
                200,
            )

        # Unconfigured validator -> 503
        admin_auth.set_auth_provider(bonc_auth.BoncJwtAuthProvider())
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {valid_tok}"},
                ).status_code,
                503,
            )

        # Verifier timeout / unavailable -> 503
        admin_auth.set_auth_provider(self._build_configured_provider(unavailable=True))
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {valid_tok}"},
                ).status_code,
                503,
            )

    def test_introspection_style_verifier_handling_and_timeouts(self) -> None:
        introspection_claims = bonc_auth.BoncClaimsValidationConfig(
            allowed_algorithms=frozenset(),
            expected_issuer="https://auth.bonc.test",
            expected_audience="bonc-search-admin-test",
            require_algorithm=False,
        )
        verifier = _TestOnlyIntrospectionVerifier(
            {
                "opaque-bonc-admin-tok": {
                    "active": True,
                    "user_id": "bonc-user-9001",
                    "username": "ops.bonc",
                    "iss": "https://auth.bonc.test",
                    "aud": "bonc-search-admin-test",
                    "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
                    "roles": ["SuperAdmin"],
                },
                "revoked-tok": {"active": False},
            }
        )
        admin_auth.set_auth_provider(
            bonc_auth.BoncJwtAuthProvider(
                verifier=verifier,
                claims_config=introspection_claims,
                role_policy=self.role_policy,
            )
        )
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            ok = client.get(
                "/api/admin/auth/session",
                headers={"Authorization": "Bearer opaque-bonc-admin-tok"},
            )
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(ok.json()["actor"], "bonc-user-9001")

            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer revoked-tok"},
                ).status_code,
                401,
            )

        # Timeout fails closed with 503
        timeout_verifier = _TestOnlyIntrospectionVerifier({}, raise_timeout=True)
        admin_auth.set_auth_provider(
            bonc_auth.BoncJwtAuthProvider(
                verifier=timeout_verifier,
                claims_config=introspection_claims,
                role_policy=self.role_policy,
            )
        )
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer opaque-bonc-admin-tok"},
                ).status_code,
                503,
            )

    # ------------------------------------------------------------------
    # 4. Authorization, role mapping & spoofed header rejection tests
    # ------------------------------------------------------------------

    def test_authorization_denies_ordinary_users_missing_roles_unconfigured_policy_and_enforces_capabilities(
        self,
    ) -> None:
        admin_auth.set_auth_provider(self._build_configured_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        basic_tok = self._mint_token(user_id="user-basic-1", username="basic.user", roles=["Basic"])
        no_roles_tok = self._mint_token(user_id="user-noroles-2", username="no.roles", roles=[])
        invalid_role_tok = self._mint_token(user_id="user-weird-3", roles=["UnknownRole"])
        auditor_tok = self._mint_token(
            user_id="user-auditor-4",
            username="search.auditor",
            roles=["SearchAuditor"],
        )
        admin_tok = self._mint_token(
            user_id="bonc-admin-uuid-77",
            username="super.admin",
            roles=["SuperAdmin"],
        )

        with TestClient(app) as client:
            # Ordinary BONC user denied Admin access (even with spoofed headers!) -> 403
            resp_basic = client.get(
                "/api/admin/platform/categories",
                headers={
                    "Authorization": f"Bearer {basic_tok}",
                    "X-User-Roles": "SuperAdmin",
                    "X-User-Id": "spoofed-admin",
                },
            )
            self.assertEqual(resp_basic.status_code, 403)

            # Missing role claims denied -> 403
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {no_roles_tok}"},
                ).status_code,
                403,
            )

            # Invalid/unknown role denied -> 403
            self.assertEqual(
                client.get(
                    "/api/admin/platform/search-logs",
                    headers={"Authorization": f"Bearer {invalid_role_tok}"},
                ).status_code,
                403,
            )

            # Fine-grained role: SearchAuditor allowed health & categories read, denied writes & logs
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {auditor_tok}"},
                ).status_code,
                200,
            )
            self.assertEqual(
                client.get(
                    "/api/admin/platform/system-health",
                    headers={"Authorization": f"Bearer {auditor_tok}"},
                ).status_code,
                200,
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories",
                    json=_sample_category("blocked"),
                    headers={"Authorization": f"Bearer {auditor_tok}"},
                ).status_code,
                403,
            )
            self.assertEqual(
                client.get(
                    "/api/admin/platform/search-logs",
                    headers={"Authorization": f"Bearer {auditor_tok}"},
                ).status_code,
                403,
            )

            # Full BONC Admin accepted without requiring cookie CSRF token
            created = client.post(
                "/api/admin/platform/categories",
                json=_sample_category("people", public=False),
                headers={"Authorization": f"Bearer {admin_tok}"},
            )
            self.assertEqual(created.status_code, 201)
            self.assertEqual(created.json()["updated_by"], "bonc-admin-uuid-77")

        # Empty/unconfigured role policy fails closed with 503
        empty_policy = bonc_auth.BoncRoleAuthorizationPolicy()
        admin_auth.set_auth_provider(self._build_configured_provider(role_policy=empty_policy))
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {admin_tok}"},
                ).status_code,
                503,
            )

        # Server-side authorization resolver outage fails closed with 503
        def failing_resolver(_identity: bonc_auth.VerifiedBoncIdentity):
            raise bonc_auth.BoncAuthUnavailableError("BONC userinfo endpoint unavailable")

        resolver_policy = bonc_auth.BoncRoleAuthorizationPolicy(
            allowed_admin_roles=frozenset({"Admin"}),
            authorization_resolver=failing_resolver,
        )
        admin_auth.set_auth_provider(self._build_configured_provider(role_policy=resolver_policy))
        with TestClient(app) as client:
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": f"Bearer {admin_tok}"},
                ).status_code,
                503,
            )

    # ------------------------------------------------------------------
    # 5. Service-token separation in BONC mode
    # ------------------------------------------------------------------

    def test_service_tokens_never_substitute_for_bonc_human_auth(self) -> None:
        os.environ["SEARCH_ADMIN_SERVICE_TOKEN"] = "cli-service-secret-111111"
        os.environ["PRODUCTION_SEARCH_AUTH_TOKEN"] = "prod-obs-secret-222222"
        os.environ["SEARCH_ADMIN_API_TOKEN"] = "legacy-admin-secret-333333"
        os.environ["SEARCH_INTERNAL_API_TOKEN"] = "internal-refresh-444444"

        # Default BONC mode: CLI service token disabled -> ALL service tokens rejected with 401
        admin_auth.set_auth_provider(self._build_configured_provider(allow_cli_service_token=False))
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            for tok in (
                "cli-service-secret-111111",
                "prod-obs-secret-222222",
                "legacy-admin-secret-333333",
                "internal-refresh-444444",
            ):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/categories",
                        headers={"Authorization": f"Bearer {tok}"},
                    ).status_code,
                    401,
                )

        # Explicit CLI opt-in: ONLY SEARCH_ADMIN_SERVICE_TOKEN works on narrow CLI allowlist
        admin_auth.set_auth_provider(self._build_configured_provider(allow_cli_service_token=True))
        with TestClient(app) as client:
            cli_hdr = {"Authorization": "Bearer cli-service-secret-111111"}
            # Allowed read-only CLI routes
            self.assertEqual(
                client.get("/api/admin/platform/categories", headers=cli_hdr).status_code, 200
            )
            # Forbidden on interactive session, logs, health, and category writes -> 403
            self.assertEqual(
                client.get("/api/admin/auth/session", headers=cli_hdr).status_code, 403
            )
            self.assertEqual(
                client.get("/api/admin/platform/search-logs", headers=cli_hdr).status_code, 403
            )
            self.assertEqual(
                client.post(
                    "/api/admin/platform/categories",
                    json=_sample_category("cli_forbidden"),
                    headers=cli_hdr,
                ).status_code,
                403,
            )
            # Unrelated service tokens STILL rejected (401)
            self.assertEqual(
                client.get(
                    "/api/admin/platform/categories",
                    headers={"Authorization": "Bearer prod-obs-secret-222222"},
                ).status_code,
                401,
            )

    # ------------------------------------------------------------------
    # 6. Exhaustive route protection, public rules, HEAD, OPTIONS & OpenAPI
    # ------------------------------------------------------------------

    def test_exhaustive_route_protection_public_rules_options_head_and_openapi(self) -> None:
        os.environ["ALLOWED_ORIGINS"] = "https://app.bonc.test"
        admin_auth.set_auth_provider(self._build_configured_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)

        admin_tok = self._mint_token(user_id="bonc-admin-55", roles=["Admin"])
        basic_tok = self._mint_token(user_id="bonc-basic-99", username="regular.user", roles=["Basic"])
        admin_hdr = {"Authorization": f"Bearer {admin_tok}"}
        basic_hdr = {"Authorization": f"Bearer {basic_tok}"}

        with TestClient(app) as client:
            # 1. Seed one private category ("people") and one public category ("help")
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

            # 2. All protected Admin routes reject unauthenticated GET/POST/PUT/HEAD with 401
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

            # 3. Unauthenticated PATCH/DELETE on admin paths are never allowed (405/404)
            self.assertIn(client.patch("/api/admin/platform/categories/people").status_code, {401, 405})
            self.assertIn(client.delete("/api/admin/platform/categories/people").status_code, {401, 405})

            # 4. Public health & category endpoints preserve public policy (+ HEAD matches GET)
            self.assertEqual(client.get("/health/live").status_code, 200)
            head_live = client.head("/health/live")
            self.assertEqual(head_live.status_code, 200)
            self.assertEqual(head_live.content, b"")
            ready = client.get("/health/ready")
            self.assertEqual(ready.status_code, 200)
            self.assertEqual(ready.json()["checks"]["authProvider"], "ready")

            # HEAD on protected Admin GET follows GET authz policy (403 for basic user, 200 empty for admin)
            self.assertEqual(
                client.head("/api/admin/platform/categories", headers=basic_hdr).status_code,
                403,
            )
            head_admin = client.head("/api/admin/platform/categories", headers=admin_hdr)
            self.assertEqual(head_admin.status_code, 200)
            self.assertEqual(head_admin.content, b"")
            # HEAD on POST-only route still returns 405
            self.assertEqual(client.head("/api/platform/search").status_code, 405)

            pub_cats = client.get("/api/platform/categories")
            self.assertEqual(pub_cats.status_code, 200)
            self.assertEqual([c["category_id"] for c in pub_cats.json()], ["help"])
            self.assertEqual(client.head("/api/platform/categories").status_code, 200)

            # Public category search works anonymously AND attributes verified BONC user if supplied
            pub_anon = client.post("/api/platform/search", json={"category": "help", "query": "BONC"})
            self.assertEqual(pub_anon.status_code, 200)
            self.assertEqual(pub_anon.json()["total_count"], 1)

            pub_bonc_user = client.post(
                "/api/platform/search",
                json={"category": "help", "query": "Getting Started"},
                headers=basic_hdr,
            )
            self.assertEqual(pub_bonc_user.status_code, 200)

            # Private category ("people") remains blocked on /api/platform/search even for authenticated BONC users!
            priv_anon = client.post("/api/platform/search", json={"category": "people", "query": "test"})
            self.assertEqual(priv_anon.status_code, 403)
            priv_bonc_user = client.post(
                "/api/platform/search",
                json={"category": "people", "query": "test"},
                headers=basic_hdr,
            )
            self.assertEqual(priv_bonc_user.status_code, 403)

            # Admin search endpoint allows testing private category with BONC Admin, denies ordinary BONC user
            self.assertEqual(
                client.post(
                    "/api/admin/platform/search",
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

            # Verify SearchLogs captured verified BONC user_id on public search & admin search
            logs = client.get("/api/admin/platform/search-logs", headers=admin_hdr).json()
            logged_users = {item["authenticated_user_id"] for item in logs["items"] if item["authenticated_user_id"]}
            self.assertIn("bonc-basic-99", logged_users)
            self.assertIn("bonc-admin-55", logged_users)

            # 5. CORS OPTIONS preflight works cleanly for trusted origin
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

            # 6. OpenAPI declares BoncBearerAuth on protected routes and keeps public routes open
            spec = client.get("/openapi.json").json()
            self.assertIn("BoncBearerAuth", spec["components"]["securitySchemes"])
            self.assertEqual(
                spec["components"]["securitySchemes"]["BoncBearerAuth"]["type"], "http"
            )
            self.assertEqual(
                spec["components"]["securitySchemes"]["BoncBearerAuth"]["scheme"], "bearer"
            )
            self.assertTrue(spec["paths"]["/api/admin/platform/categories"]["get"].get("security"))
            self.assertTrue(spec["paths"]["/api/admin/platform/search"]["post"].get("security"))
            self.assertTrue(spec["paths"]["/api/admin/auth/session"]["get"].get("security"))
            self.assertNotIn("security", spec["paths"]["/api/platform/categories"]["get"])
            self.assertNotIn("security", spec["paths"]["/api/platform/search"]["post"])
            self.assertNotIn("security", spec["paths"]["/health/live"]["get"])

    # ------------------------------------------------------------------
    # 7. Regression tests under BONC auth (CRUD, rollback, search, logs, KPIs)
    # ------------------------------------------------------------------

    def test_end_to_end_admin_workflow_and_audit_actor_propagation_with_bonc_principal(self) -> None:
        admin_auth.set_auth_provider(self._build_configured_provider())
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        admin_tok = self._mint_token(user_id="3f1a9c20-bonc-admin-id", username="priya@bonc", roles=["Admin"])
        hdr = {"Authorization": f"Bearer {admin_tok}"}

        with TestClient(app) as client:
            # Create -> v1
            c1 = client.post(
                "/api/admin/platform/categories",
                json=_sample_category("jobs", public=False),
                headers=hdr,
            )
            self.assertEqual(c1.status_code, 201)
            self.assertEqual(c1.json()["updated_by"], "3f1a9c20-bonc-admin-id")

            # Update -> v2
            v2_cfg = _sample_category("jobs", public=False)
            v2_cfg["display_name"] = "BONC Jobs v2"
            u2 = client.put(
                "/api/admin/platform/categories/jobs",
                json={"expected_version": 1, "config": v2_cfg, "change_reason": "Rename"},
                headers=hdr,
            )
            self.assertEqual(u2.status_code, 200)
            self.assertEqual(u2.json()["updated_by"], "3f1a9c20-bonc-admin-id")

            # Rollback v2 -> v1 (creates v3)
            rb = client.post(
                "/api/admin/platform/categories/jobs/rollback",
                json={"target_version": 1, "expected_version": 2, "reason": "Restore v1"},
                headers=hdr,
            )
            self.assertEqual(rb.status_code, 200)
            self.assertEqual(rb.json()["config_version"], 3)
            self.assertEqual(rb.json()["updated_by"], "3f1a9c20-bonc-admin-id")

            history = client.get("/api/admin/platform/categories/jobs/history", headers=hdr).json()["items"]
            self.assertEqual([h["changed_by"] for h in history], ["3f1a9c20-bonc-admin-id"] * 3)

            # Ingest + Admin search + KPIs + per-user activity
            ing = client.post(
                "/api/admin/platform/categories/jobs/ingest",
                json={
                    "documents": [
                        {
                            "document_id": "job-1",
                            "title": "Senior Python Engineer",
                            "fields": {"title": "Senior Python Engineer"},
                        }
                    ],
                    "replace_all": True,
                },
                headers=hdr,
            )
            self.assertEqual(ing.status_code, 200)

            sr = client.post(
                "/api/admin/platform/search",
                json={"category": "jobs", "query": "Python Engineer"},
                headers=hdr,
            )
            self.assertEqual(sr.status_code, 200)
            self.assertEqual(sr.json()["data"][0]["id"], "job-1")

            users = client.get("/api/admin/platform/search-logs/users", headers=hdr).json()
            self.assertEqual(users["items"][0]["user_id"], "3f1a9c20-bonc-admin-id")

            kpis = client.get("/api/admin/platform/metrics/kpis", headers=hdr).json()
            self.assertGreaterEqual(kpis["search_kpis"]["total_search_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
