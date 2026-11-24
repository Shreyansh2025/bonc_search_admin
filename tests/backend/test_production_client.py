"""Read-only ProductionSearchClient safety, fail-closed auth & BrochureIQ stripping tests."""
from __future__ import annotations

import asyncio
import os
import sys
import unittest
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.clients.production_search_client import (  # noqa: E402
    ProductionSearchClient,
    filter_product_company_indexes,
)
from app.db import auth_db, platform_db  # noqa: E402
from app.main import create_app  # noqa: E402


class TestProductionSearchClient(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["SEARCH_ADMIN_AUTH_DB_URL"] = "sqlite:///:memory:"
        os.environ["SEARCH_ADMIN_SERVICE_TOKEN"] = "prod-route-test-token"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

    def tearDown(self) -> None:
        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_disabled_by_default_makes_zero_http_calls(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json={"status": "ok"})

        client = ProductionSearchClient(
            base_url="https://prod.example.com",
            auth_mode="none",
            transport=httpx.MockTransport(handler),
        )
        health = asyncio.run(client.get_health(request_id="req-1"))
        idx = asyncio.run(client.get_index_status(request_id="req-1"))
        asyncio.run(client.aclose())

        self.assertEqual(calls, [])
        self.assertFalse(health["enabled"])
        self.assertEqual(health["status"], "disabled")
        self.assertTrue(health["read_only"])
        self.assertFalse(idx["enabled"])
        self.assertEqual(idx["status"], "disabled")
        self.assertEqual(idx["indexes"], {})

    def test_fail_closed_when_enabled_without_url_or_auth_token(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json={"status": "ok"})

        # Missing base_url
        c1 = ProductionSearchClient(
            enabled=True, base_url="", auth_mode="none", transport=httpx.MockTransport(handler)
        )
        r1 = asyncio.run(c1.get_health())
        self.assertEqual(r1["status"], "unavailable")
        self.assertEqual(calls, [])

        # Missing bearer token (fail closed — never downgrades to unauthenticated)
        c2 = ProductionSearchClient(
            enabled=True,
            base_url="https://prod.example.com",
            auth_mode="bearer",
            auth_token="",
            transport=httpx.MockTransport(handler),
        )
        r2 = asyncio.run(c2.get_index_status())
        self.assertEqual(r2["status"], "unavailable")
        self.assertIn("PRODUCTION_SEARCH_AUTH_TOKEN", r2["detail"])
        self.assertEqual(calls, [])

        # Missing api_key token
        c3 = ProductionSearchClient(
            enabled=True,
            base_url="https://prod.example.com",
            auth_mode="api_key",
            auth_token="",
            transport=httpx.MockTransport(handler),
        )
        r3 = asyncio.run(c3.get_health())
        self.assertEqual(r3["status"], "unavailable")
        self.assertEqual(calls, [])

    def test_strips_brochureiq_local_products_and_enforces_get_only_allowlist(self) -> None:
        recorded: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded.append(request)
            if request.url.path == "/api/healthz":
                return httpx.Response(200, json={"status": "ok"})
            if request.url.path == "/api/debug/index-status":
                return httpx.Response(
                    200,
                    json={
                        "b2bCompanies": {"count": 120, "index_built": True},
                        "b2bProducts": {"count": 450, "index_built": True},
                        "localProducts": {"count": 999, "index_built": True},
                        "unexpectedExtra": {"count": 50, "index_built": True},
                    },
                )
            return httpx.Response(404)

        client = ProductionSearchClient(
            enabled=True,
            base_url="https://prod.example.com",
            auth_mode="bearer",
            auth_token="prod-ro-token",
            transport=httpx.MockTransport(handler),
        )
        health = asyncio.run(client.get_health(request_id="trace-123"))
        idx = asyncio.run(client.get_index_status(request_id="trace-123"))

        self.assertEqual(health["status"], "healthy")
        self.assertEqual(idx["status"], "healthy")
        self.assertEqual(set(idx["indexes"].keys()), {"b2bCompanies", "b2bProducts"})
        self.assertNotIn("localProducts", idx["indexes"])
        self.assertNotIn("unexpectedExtra", idx["indexes"])
        self.assertEqual(idx["total_count"], 2)
        self.assertEqual(idx["total_records"], 570)
        self.assertEqual(len(recorded), 2)
        for req in recorded:
            self.assertEqual(req.method, "GET")
            self.assertEqual(req.headers.get("authorization"), "Bearer prod-ro-token")
            self.assertEqual(req.headers.get("x-request-id"), "trace-123")

        # Non-allowlisted path strictly blocked
        with self.assertRaises(ValueError):
            asyncio.run(client._get_json("/api/search"))
        asyncio.run(client.aclose())

        # Pure helper also strips localProducts directly
        filtered = filter_product_company_indexes(
            {"localProducts": {"count": 99, "index_built": True}, "b2bCompanies": {"count": 5, "index_built": True}}
        )
        self.assertEqual(list(filtered.keys()), ["b2bCompanies"])

    def test_upstream_auth_failure_and_timeout_handling(self) -> None:
        auth_fail_client = ProductionSearchClient(
            enabled=True,
            base_url="https://prod.example.com",
            auth_mode="api_key",
            auth_token="bad-key",
            auth_header="X-BONC-Key",
            transport=httpx.MockTransport(lambda _req: httpx.Response(403, json={"detail": "Forbidden"})),
        )
        auth_res = asyncio.run(auth_fail_client.get_index_status())
        self.assertEqual(auth_res["status"], "unhealthy")
        self.assertIn("authentication failed", auth_res["detail"].lower())
        self.assertNotIn("bad-key", auth_res["detail"])
        asyncio.run(auth_fail_client.aclose())

        def timeout_handler(_req: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out")

        timeout_client = ProductionSearchClient(
            enabled=True,
            base_url="https://prod.example.com",
            auth_mode="none",
            transport=httpx.MockTransport(timeout_handler),
        )
        to_res = asyncio.run(timeout_client.get_health())
        self.assertEqual(to_res["status"], "unavailable")
        self.assertIn("timed out", to_res["detail"].lower())
        asyncio.run(timeout_client.aclose())

    def test_admin_production_routes_require_auth_and_strip_brochureiq(self) -> None:
        mock_client = ProductionSearchClient(
            enabled=True,
            base_url="https://prod.example.com",
            auth_mode="none",
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    json=(
                        {"status": "ok"}
                        if req.url.path == "/api/healthz"
                        else {
                            "b2bCompanies": {"count": 10, "index_built": True},
                            "b2bProducts": {"count": 20, "index_built": True},
                            "localProducts": {"count": 500, "index_built": True},
                        }
                    ),
                )
            ),
        )
        app = create_app(
            production_search_client=mock_client,
            warmup_embedding_model=False,
            connect_platform_database=False,
        )
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/admin/production/health").status_code, 401)
            self.assertEqual(client.get("/api/admin/production/index-status").status_code, 401)

            headers = {"Authorization": "Bearer prod-route-test-token"}
            h = client.get("/api/admin/production/health", headers=headers)
            self.assertEqual(h.status_code, 200)
            self.assertEqual(h.json()["status"], "healthy")

            idx = client.get("/api/admin/production/index-status", headers=headers)
            self.assertEqual(idx.status_code, 200)
            self.assertEqual(set(idx.json()["indexes"].keys()), {"b2bCompanies", "b2bProducts"})
            self.assertNotIn("localProducts", idx.json()["indexes"])


if __name__ == "__main__":
    unittest.main()
