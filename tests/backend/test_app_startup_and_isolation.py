"""Architectural isolation, startup health, CORS fail-closed & removed-endpoint tests."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import resolve_allowed_origins  # noqa: E402
from app.db import platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.schemas.platform import SQLServerSourceConfig, SourceValidationRequest  # noqa: E402
from app.services import admin_auth, bonc_auth  # noqa: E402


class _ReadyTestBoncVerifier(bonc_auth.BoncTokenVerifier):
    def is_configured(self) -> bool:
        return True

    def verify_access_token(self, raw_token: str) -> bonc_auth.VerifiedBoncIdentity:
        return bonc_auth.VerifiedBoncIdentity(
            user_id="test-admin",
            username="test-admin",
            expires_at_utc=None,
            roles=("Admin",),
        )


class TestAppStartupAndIsolation(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        os.environ["APP_ENV"] = "local"
        for key in (
            "BONC_AUTH_VERIFY_URL",
            "BONC_AUTH_ADMIN_ROLES",
            "BONC_AUTH_CACHE_SECONDS",
            "BONC_AUTH_TIMEOUT",
        ):
            os.environ.pop(key, None)
        admin_auth.reset_auth_provider()
        platform_db.reset_platform_engine()

    def tearDown(self) -> None:
        admin_auth.reset_auth_provider()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_zero_legacy_or_brochureiq_imports_in_backend_ast(self) -> None:
        forbidden_prefixes = (
            "app.search_ai",
            "app.shared",
            "app.brochureiq",
            "py_backend",
            "fitz",
            "pytesseract",
            "PIL",
            "rembg",
            "onnxruntime",
            "openpyxl",
            "multipart",
        )
        forbidden_tokens = (
            "SearchAIClient",
            "SEARCH_AI_BASE_URL",
            "SEARCH_AI_ADMIN_API_TOKEN",
            "SearchAISettings",
            "search-settings",
        )
        retired_legacy_relpaths = (
            Path("routes/settings.py"),
            Path("routes/platform.py"),
            Path("routes/observability.py"),
            Path("schemas/settings.py"),
            Path("schemas/auth.py"),
            Path("services/search_ai_client.py"),
            Path("services/auth_db.py"),
            Path("db/auth_db.py"),
        )
        retired_legacy_modules = (
            "app.routes.settings",
            "app.routes.platform",
            "app.routes.observability",
            "app.schemas.settings",
            "app.schemas.auth",
            "app.services.search_ai_client",
            "app.services.auth_db",
            "app.db.auth_db",
        )
        app_dir = BACKEND_DIR / "app"
        for retired_relpath in retired_legacy_relpaths:
            self.assertFalse(
                (app_dir / retired_relpath).exists(),
                f"Retired legacy file must be removed from active app: {retired_relpath}",
            )

        py_files = sorted(app_dir.rglob("*.py"))
        self.assertGreaterEqual(len(py_files), 15)

        for file_path in py_files:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for prefix in forbidden_prefixes:
                            self.assertFalse(
                                alias.name == prefix or alias.name.startswith(prefix + "."),
                                f"Forbidden import '{alias.name}' in {file_path}",
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for prefix in forbidden_prefixes:
                        self.assertFalse(
                            node.module == prefix or node.module.startswith(prefix + "."),
                            f"Forbidden from-import '{node.module}' in {file_path}",
                        )
            for token in forbidden_tokens:
                self.assertNotIn(token, source, f"Forbidden legacy reference '{token}' in {file_path}")

        # In-process check: none of the retired legacy modules are loaded or resolvable
        for legacy_mod in retired_legacy_modules:
            self.assertNotIn(legacy_mod, sys.modules, f"Legacy module '{legacy_mod}' must not be imported")
            self.assertIsNone(
                importlib.util.find_spec(legacy_mod),
                f"Retired legacy module '{legacy_mod}' must not be importable",
            )

        # Clean-interpreter subprocess check: verify app.main + create_app() independently
        # without any possibility of sys.modules pollution from other test modules.
        probe_code = (
            "import json, sys; "
            "import app.main as m; "
            "m.create_app(warmup_embedding_model=False, connect_platform_database=False); "
            "print(json.dumps(sorted(sys.modules.keys())))"
        )
        probe_env = {
            **os.environ,
            "PYTHONPATH": str(BACKEND_DIR),
            "PRODUCTION_OBSERVABILITY_ENABLED": "false",
            "SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL": "false",
        }
        proc = subprocess.run(
            [sys.executable, "-c", probe_code],
            cwd=str(BACKEND_DIR),
            env=probe_env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"Clean subprocess import check failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
        )
        loaded_modules = set(json.loads(proc.stdout.strip().splitlines()[-1]))
        self.assertIn("app.services.bonc_auth_adapter", loaded_modules)
        for legacy_mod in retired_legacy_modules:
            self.assertNotIn(
                legacy_mod,
                loaded_modules,
                f"Fresh interpreter must not load retired legacy module '{legacy_mod}'",
            )
        for prefix in forbidden_prefixes:
            violating = [
                mod for mod in loaded_modules if mod == prefix or mod.startswith(prefix + ".")
            ]
            self.assertEqual(
                violating,
                [],
                f"Fresh interpreter must not load forbidden modules for prefix '{prefix}': {violating}",
            )

    def test_sql_source_schema_field_preserves_json_contract(self) -> None:
        cfg = SQLServerSourceConfig.model_validate(
            {
                "type": "sqlserver",
                "connection_env": "SEARCH_SOURCE_BONC_DEV",
                "schema": "sales",
                "table": "Orders",
                "id_column": "OrderId",
            }
        )
        self.assertEqual(cfg.schema, "sales")
        self.assertEqual(cfg.model_dump()["schema"], "sales")
        self.assertIn('"schema":"sales"', cfg.model_dump_json())

        req = SourceValidationRequest.model_validate(
            {
                "schema": "dbo",
                "table": "Users",
                "id_column": "UserId",
            }
        )
        self.assertEqual(req.schema, "dbo")
        self.assertEqual(req.model_dump()["schema"], "dbo")

        with self.assertRaises(ValidationError):
            SourceValidationRequest.model_validate(
                {
                    "schema_name": "dbo",
                    "table": "Users",
                    "id_column": "UserId",
                }
            )

    def test_platform_repositories_never_query_forbidden_dbo_tables(self) -> None:
        repo_dir = BACKEND_DIR / "app" / "repositories"
        for file_path in repo_dir.rglob("*.py"):
            source = file_path.read_text(encoding="utf-8")
            for legacy_table in platform_db.FORBIDDEN_LEGACY_TABLES:
                self.assertNotIn(
                    f"dbo.{legacy_table}",
                    source,
                    f"Forbidden legacy table dbo.{legacy_table} referenced in {file_path}",
                )

    def test_independent_liveness_and_readiness_without_port_8002(self) -> None:
        engine = platform_db.create_in_memory_sqlite_platform_engine()
        platform_db.set_platform_engine(engine)
        admin_auth.set_auth_provider(
            bonc_auth.BoncJwtAuthProvider(
                verifier=_ReadyTestBoncVerifier(),
                claims_config=bonc_auth.BoncClaimsValidationConfig.delegated_server_verification(),
                role_policy=bonc_auth.BoncRoleAuthorizationPolicy(
                    allowed_admin_roles=frozenset({"Admin", "SuperAdmin"})
                ),
            )
        )

        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            live = client.get("/health/live")
            self.assertEqual(live.status_code, 200)
            self.assertEqual(
                live.json(),
                {"status": "ok", "service": "search-admin-platform"},
            )

            ready = client.get("/health/ready")
            self.assertEqual(ready.status_code, 200)
            body = ready.json()
            self.assertEqual(body["status"], "ready")
            self.assertEqual(body["service"], "search-admin-platform")
            self.assertEqual(body["checks"]["authMode"], "bonc_jwt")
            self.assertEqual(body["checks"]["authProvider"], "ready")
            self.assertNotIn("authStore", body["checks"])
            self.assertEqual(body["checks"]["platformDatabase"], "ready")
            self.assertEqual(body["checks"]["productionObservability"], "disabled")
            self.assertNotIn("upstreamSearchAi", body["checks"])

    def test_readiness_returns_503_when_platform_db_disconnected(self) -> None:
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            ready = client.get("/health/ready")
            self.assertEqual(ready.status_code, 503)
            body = ready.json()
            self.assertEqual(body["status"], "not_ready")
            self.assertEqual(body["checks"]["platformDatabase"], "not_ready")

    def test_removed_and_excluded_endpoints_absent(self) -> None:
        engine = platform_db.create_in_memory_sqlite_platform_engine()
        platform_db.set_platform_engine(engine)

        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            # Decision #1: Legacy Catalog Thresholds completely removed
            self.assertEqual(client.get("/api/admin/search-settings").status_code, 404)
            self.assertEqual(client.put("/api/admin/search-settings", json={}).status_code, 404)
            self.assertEqual(client.get("/api/admin/search-settings/history").status_code, 404)

            # Decision #2: Playground feedback-writing endpoint removed (only GET exists -> 405)
            post_fb = client.post(
                "/api/admin/platform/categories/people/feedback",
                json={"query": "python", "document_id": "1", "is_relevant": True},
            )
            self.assertEqual(post_fb.status_code, 405)

            # Legacy B2B search excluded
            self.assertEqual(
                client.post("/api/search", json={"query": "steel"}).status_code, 404
            )

            # Verify OpenAPI schema exposes Generic Platform Testing & Public search, not retired routes
            openapi_paths = set(client.get("/openapi.json").json()["paths"].keys())
            self.assertIn("/api/admin/platform/search", openapi_paths)
            self.assertIn("/api/platform/search", openapi_paths)
            self.assertIn("/api/admin/production/health", openapi_paths)
            self.assertIn("/api/admin/production/index-status", openapi_paths)
            self.assertNotIn("/api/admin/search-settings", openapi_paths)
            self.assertNotIn("/api/admin/search-settings/history", openapi_paths)
            self.assertNotIn("/api/search", openapi_paths)
            fb_methods = set(
                client.get("/openapi.json")
                .json()["paths"]["/api/admin/platform/categories/{category_id}/feedback"]
                .keys()
            )
            self.assertEqual(fb_methods, {"get"})

    def test_cors_fails_closed_for_wildcards_and_non_local_empty(self) -> None:
        with patch.dict(os.environ, {"APP_ENV": "staging", "ALLOWED_ORIGINS": "*"}, clear=False):
            self.assertEqual(resolve_allowed_origins(), [])
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=False):
            os.environ.pop("ALLOWED_ORIGINS", None)
            self.assertEqual(resolve_allowed_origins(), [])
        with patch.dict(
            os.environ,
            {"APP_ENV": "staging", "ALLOWED_ORIGINS": "https://admin.bonc.in, * , http://bad/path"},
            clear=False,
        ):
            self.assertEqual(resolve_allowed_origins(), ["https://admin.bonc.in"])


if __name__ == "__main__":
    unittest.main()
