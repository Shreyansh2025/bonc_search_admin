"""Observability persistence, KPI/failure/relevance metrics, secret redaction & MSSQL dialect tests."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient
from sqlalchemy import insert, select
from sqlalchemy.dialects import mssql

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db import auth_db, platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.repositories import category_store, observability_store  # noqa: E402
from app.services import embedding_model, platform_search  # noqa: E402


class _TinyModel:
    def encode(self, texts: list[str], convert_to_numpy: bool = True, batch_size: int = 64):
        arr = np.zeros((len(texts), embedding_model.EMBEDDING_DIM), dtype="float32")
        arr[:, 0] = 1.0
        return arr


class TestObservabilityAndSqlDialect(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["SEARCH_ADMIN_AUTH_DB_URL"] = "sqlite:///:memory:"
        os.environ["SEARCH_ADMIN_SERVICE_TOKEN"] = "obs-secret-token-xyz987"
        os.environ["SEARCH_ADMIN_SERVICE_ACTOR"] = "admin:obs"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        self.headers = {"Authorization": "Bearer obs-secret-token-xyz987"}

        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        platform_search.clear_all_category_indexes()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

        self._model_patch = patch(
            "app.services.platform_search.get_model", return_value=_TinyModel()
        )
        self._model_patch.start()

    def tearDown(self) -> None:
        self._model_patch.stop()
        platform_search.clear_all_category_indexes()
        auth_db.reset_auth_engine()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_persistent_search_logs_api_logs_kpis_relevance_and_system_health(self) -> None:
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            app.state.embedding_model_ready = True

            # Create public category & ingest 1 document
            client.post(
                "/api/admin/platform/categories",
                json={
                    "category_id": "docs",
                    "display_name": "Docs",
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
                    "public_search_enabled": True,
                },
                headers=self.headers,
            )
            client.post(
                "/api/admin/platform/categories/docs/ingest",
                json={
                    "documents": [
                        {
                            "document_id": "d-1",
                            "title": "FastAPI Architecture",
                            "fields": {"title": "FastAPI Architecture"},
                        }
                    ],
                    "replace_all": True,
                },
                headers=self.headers,
            )

            # 1. Public search with spoofed X-User-Id -> logged as anonymous (never trusts spoofed header)
            pub_hit = client.post(
                "/api/platform/search",
                json={"category": "docs", "query": "FastAPI"},
                headers={"X-User-Id": "spoofed-attacker"},
            )
            self.assertEqual(pub_hit.status_code, 200)

            # 2. Admin zero-result search -> logged as authenticated admin:obs with zero_results outcome
            admin_zero = client.post(
                "/api/admin/platform/search",
                json={"category": "docs", "query": "zzzznonexistentterm"},
                headers=self.headers,
            )
            self.assertEqual(admin_zero.status_code, 200)
            self.assertEqual(admin_zero.json()["total_count"], 0)

            # 3. Seed historical feedback rows directly into searchai.SearchFeedback (read-only in API)
            now = observability_store.utc_now_naive()
            with platform_db.get_platform_engine().begin() as conn:
                conn.execute(
                    insert(observability_store.search_feedback_table).values(
                        [
                            {
                                "CategoryId": "docs",
                                "QueryText": "FastAPI",
                                "DocumentId": "d-1",
                                "IsRelevant": True,
                                "Comment": "Accurate hit",
                                "CreatedAtUtc": now,
                                "CreatedBy": "historical.reviewer",
                                "ResultRank": 1,
                                "ResultScore": 95.0,
                                "ConfigVersion": 1,
                                "IndexVersion": 1,
                            },
                            {
                                "CategoryId": "docs",
                                "QueryText": "FastAPI",
                                "DocumentId": "d-2",
                                "IsRelevant": False,
                                "Comment": "Off topic",
                                "CreatedAtUtc": now,
                                "CreatedBy": "historical.reviewer",
                                "ResultRank": 2,
                                "ResultScore": 42.0,
                                "ConfigVersion": 1,
                                "IndexVersion": 1,
                            },
                        ]
                    )
                )

            # Verify search logs & spoof protection
            logs = client.get("/api/admin/platform/search-logs", headers=self.headers).json()
            self.assertEqual(logs["summary"]["total_attempts"], 2)
            self.assertEqual(logs["summary"]["zero_result_attempts"], 1)
            self.assertEqual(logs["summary"]["authenticated_attempts"], 1)
            self.assertEqual(logs["summary"]["anonymous_attempts"], 1)
            for item in logs["items"]:
                self.assertNotEqual(item["authenticated_user_id"], "spoofed-attacker")

            # Verify per-user breakdown
            users = client.get("/api/admin/platform/search-logs/users", headers=self.headers).json()
            self.assertEqual(users["summary"]["unique_authenticated_users"], 1)
            self.assertEqual(users["items"][0]["user_id"], "admin:obs")

            # Verify KPIs & API failure monitoring
            kpis = client.get("/api/admin/platform/metrics/kpis", headers=self.headers).json()
            self.assertEqual(kpis["search_kpis"]["total_search_attempts"], 2)
            self.assertEqual(kpis["search_kpis"]["zero_result_rate_pct"], 50.0)
            self.assertEqual(kpis["relevance_feedback"]["total_rated_results"], 2)
            self.assertEqual(kpis["relevance_feedback"]["negative_feedback_percentage"], 50.0)
            self.assertGreater(kpis["api_monitoring"]["total_api_requests"], 0)
            self.assertEqual(kpis["api_monitoring"]["server_failure_requests_5xx"], 0)

            api_failures = client.get(
                "/api/admin/platform/metrics/api-failures", headers=self.headers
            ).json()
            self.assertEqual(api_failures["server_failure_requests_5xx"], 0)

            # Verify read-only relevance & category feedback
            rel = client.get("/api/admin/platform/metrics/relevance", headers=self.headers).json()
            self.assertFalse(rel["is_ground_truth"])
            self.assertEqual(len(rel["recent_negative_examples"]), 1)

            cat_fb = client.get(
                "/api/admin/platform/categories/docs/feedback", headers=self.headers
            ).json()
            self.assertEqual(cat_fb["total_count"], 2)
            self.assertEqual(cat_fb["relevant_count"], 1)
            self.assertEqual(cat_fb["not_relevant_count"], 1)

            # Verify system-health stays "healthy" even though production_search is "disabled"
            health = client.get("/api/admin/platform/system-health", headers=self.headers).json()
            self.assertEqual(health["service"], "search-admin-platform")
            self.assertEqual(health["status"], "healthy")
            self.assertEqual(health["components"]["database"]["status"], "healthy")
            self.assertEqual(health["components"]["production_search"]["status"], "disabled")
            self.assertFalse(health["components"]["production_search"]["enabled"])

    def test_secret_redaction_scrubs_tokens_and_connection_strings(self) -> None:
        os.environ["PRODUCTION_SEARCH_AUTH_TOKEN"] = "prod-top-secret-99999"
        raw = (
            "Error with obs-secret-token-xyz987 and prod-top-secret-99999 "
            "Bearer abcdef123456 DRIVER={ODBC Driver 18};SERVER=s;UID=u;PWD=p "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature123456"
        )
        scrubbed = observability_store.redact_sensitive_text(raw)
        self.assertNotIn("obs-secret-token-xyz987", scrubbed)
        self.assertNotIn("prod-top-secret-99999", scrubbed)
        self.assertNotIn("abcdef123456", scrubbed)
        self.assertNotIn("PWD=p", scrubbed)
        self.assertNotIn("signature123456", scrubbed)

    def test_sql_server_mssql_dialect_compilation_and_schema_reference(self) -> None:
        """Compile SQLAlchemy Core queries against the real MSSQL dialect without touching SQL Server."""
        # Test both default MSSQL dialect (ROW_NUMBER pagination) and SQL Server 2019 (OFFSET/FETCH)
        default_dialect = mssql.dialect()
        modern_dialect = mssql.dialect()
        modern_dialect.server_version_info = (15, 0)
        modern_dialect._supports_offset_fetch = True

        # 1. Verify observability_store Core queries compile cleanly to T-SQL referencing searchai.*
        logs_stmt = (
            select(observability_store.search_logs_table)
            .order_by(observability_store.search_logs_table.c.OccurredAtUtc.desc())
            .limit(25)
            .offset(50)
        )
        compiled_default = str(logs_stmt.compile(dialect=default_dialect))
        self.assertIn("searchai.[SearchLogs]", compiled_default)
        self.assertIn("ROW_NUMBER() OVER", compiled_default)

        compiled_modern = str(logs_stmt.compile(dialect=modern_dialect))
        self.assertIn("searchai.[SearchLogs]", compiled_modern)
        self.assertIn("OFFSET", compiled_modern)
        self.assertIn("FETCH FIRST", compiled_modern)

        api_stmt = (
            select(observability_store.api_request_logs_table)
            .order_by(observability_store.api_request_logs_table.c.OccurredAtUtc.desc())
            .limit(10)
        )
        compiled_api = str(api_stmt.compile(dialect=modern_dialect))
        self.assertIn("searchai.[ApiRequestLogs]", compiled_api)
        self.assertIn("TOP", compiled_api)

        fb_stmt = select(observability_store.search_feedback_table)
        compiled_fb = str(fb_stmt.compile(dialect=modern_dialect))
        self.assertIn("searchai.[SearchFeedback]", compiled_fb)

        # 2. Verify category_store MSSQL SQL statements use T-SQL syntax & searchai.* exclusively
        self.assertIn("COUNT_BIG(*)", category_store._GET_CATEGORY_WITH_COUNT_MSSQL.text)
        self.assertIn("COUNT_BIG(*)", category_store._LIST_CATEGORIES_WITH_COUNTS_MSSQL.text)
        self.assertIn("SELECT TOP (:limit)", category_store._LIST_FEEDBACK_MSSQL.text)
        self.assertIn("MERGE searchai.SearchDocuments", category_store._UPSERT_DOCUMENT_MSSQL.text)

        # 3. Verify reference DDL script contains all 6 owned tables and zero legacy dbo/settings tables
        ddl_path = BACKEND_DIR / "sql" / "general_search_platform_schema.sql"
        ddl = ddl_path.read_text(encoding="utf-8")
        for table_name in platform_db.OWNED_PLATFORM_TABLES:
            self.assertIn(f"CREATE TABLE searchai.{table_name}", ddl)
        self.assertIn("RolledBackFromVersion", ddl)
        self.assertNotIn("CREATE TABLE searchai.SearchAISettings", ddl)
        self.assertNotIn("CREATE TABLE dbo.", ddl)


if __name__ == "__main__":
    unittest.main()
