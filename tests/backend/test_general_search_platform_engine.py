"""End-to-end General Search Platform engine, CRUD, rollback, SQL sync & evaluation tests."""
from __future__ import annotations

import hashlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db import platform_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services import (  # noqa: E402
    admin_auth,
    bonc_auth,
    embedding_model,
    platform_search,
    search_evaluation,
    source_sync,
)


class _EngineTestBoncVerifier(bonc_auth.BoncTokenVerifier):
    def __init__(self, expected_token: str, actor: str = "admin:tester") -> None:
        self._expected_token = expected_token
        self._actor = actor

    def is_configured(self) -> bool:
        return True

    def verify_access_token(self, raw_token: str) -> bonc_auth.VerifiedBoncIdentity:
        if raw_token != self._expected_token:
            raise bonc_auth.BoncTokenInvalidError("Invalid test BONC token")
        return bonc_auth.VerifiedBoncIdentity(
            user_id=self._actor,
            username=self._actor,
            expires_at_utc=None,
            roles=("Admin",),
        )


class _DeterministicFakeEmbeddingModel:
    """Offline 384-d bag-of-tokens embedding model for deterministic FAISS tests."""

    def encode(self, texts: list[str], convert_to_numpy: bool = True, batch_size: int = 64):
        out = np.zeros((len(texts), embedding_model.EMBEDDING_DIM), dtype="float32")
        for row_idx, text in enumerate(texts):
            tokens = [tok.strip(".,:;!?()[]{}").lower() for tok in str(text).split()]
            for tok in tokens:
                if not tok:
                    continue
                digest = hashlib.sha256(tok.encode("utf-8")).digest()
                bucket = int.from_bytes(digest[:2], "big") % embedding_model.EMBEDDING_DIM
                out[row_idx, bucket] += 1.0
            norm = float(np.linalg.norm(out[row_idx]))
            if norm > 0:
                out[row_idx] /= norm
            else:
                out[row_idx, 0] = 1.0
        return out


def _category_config(
    *,
    category_id: str = "engineers",
    display_name: str = "Engineers",
    public_search_enabled: bool = False,
    source: dict | None = None,
) -> dict:
    return {
        "category_id": category_id,
        "display_name": display_name,
        "description": "Technical talent directory",
        "source": source or {"type": "push"},
        "fields": [
            {
                "key": "full_name",
                "source_column": "FullName",
                "label": "Full Name",
                "role": "title",
                "weight": 4.0,
                "searchable": True,
                "semantic": True,
                "aliases": ["name", "person"],
                "filterable": False,
                "data_type": "text",
                "query_filter_mode": "none",
                "query_match": "all",
            },
            {
                "key": "skills",
                "source_column": "Skills",
                "label": "Skills",
                "role": "skill",
                "weight": 5.0,
                "searchable": True,
                "semantic": True,
                "aliases": ["skill", "tech"],
                "filterable": True,
                "data_type": "keyword",
                "query_filter_mode": "preferred",
                "query_match": "any",
            },
            {
                "key": "city",
                "source_column": "City",
                "label": "City",
                "role": "location",
                "weight": 2.0,
                "searchable": True,
                "semantic": False,
                "aliases": ["city", "location"],
                "filterable": True,
                "data_type": "keyword",
                "query_filter_mode": "preferred",
                "query_match": "any",
            },
            {
                "key": "years_exp",
                "source_column": "YearsExp",
                "label": "Experience Years",
                "role": "general",
                "weight": 0.5,
                "searchable": False,
                "semantic": False,
                "aliases": [],
                "filterable": True,
                "data_type": "integer",
                "query_filter_mode": "none",
                "query_match": "all",
            },
            {
                "key": "verified",
                "source_column": "IsVerified",
                "label": "Verified",
                "role": "general",
                "weight": 0.0,
                "searchable": False,
                "semantic": False,
                "aliases": [],
                "filterable": True,
                "data_type": "boolean",
                "query_filter_mode": "none",
                "query_match": "all",
            },
        ],
        "synonyms": [{"terms": ["k8s", "kubernetes"]}],
        "rules": {
            "lexical_enabled": True,
            "semantic_enabled": True,
            "semantic_min_score": 15.0,
            "semantic_high_confidence_score": 75.0,
            "semantic_candidate_limit": 20,
            "lexical_weight": 0.65,
            "semantic_weight": 0.35,
        },
        "active": True,
        "public_search_enabled": public_search_enabled,
    }


class TestGeneralSearchPlatformEngine(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ["APP_ENV"] = "local"
        os.environ["PRODUCTION_OBSERVABILITY_ENABLED"] = "false"
        os.environ["SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL"] = "false"
        self.headers = {"Authorization": "Bearer engine-test-bonc-token"}

        admin_auth.reset_auth_provider()
        admin_auth.set_auth_provider(
            bonc_auth.BoncJwtAuthProvider(
                verifier=_EngineTestBoncVerifier("engine-test-bonc-token", "admin:tester"),
                claims_config=bonc_auth.BoncClaimsValidationConfig.delegated_server_verification(),
                role_policy=bonc_auth.BoncRoleAuthorizationPolicy(
                    allowed_admin_roles=frozenset({"Admin", "SuperAdmin"})
                ),
            )
        )
        platform_db.reset_platform_engine()
        platform_search.clear_all_category_indexes()
        platform_db.set_platform_engine(platform_db.create_in_memory_sqlite_platform_engine())

        self._model_patch = patch(
            "app.services.platform_search.get_model",
            return_value=_DeterministicFakeEmbeddingModel(),
        )
        self._model_patch.start()

    def tearDown(self) -> None:
        self._model_patch.stop()
        admin_auth.reset_auth_provider()
        platform_search.clear_all_category_indexes()
        platform_db.reset_platform_engine()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_category_crud_optimistic_concurrency_atomic_rollback_and_cache_invalidation(self) -> None:
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            cfg = _category_config(category_id="engineers", display_name="Engineers v1")
            r1 = client.post("/api/admin/platform/categories", json=cfg, headers=self.headers)
            self.assertEqual(r1.status_code, 201)
            self.assertEqual(r1.json()["config_version"], 1)

            # Duplicate ID -> 409
            dup = client.post("/api/admin/platform/categories", json=cfg, headers=self.headers)
            self.assertEqual(dup.status_code, 409)

            # Update v1 -> v2
            cfg_v2 = _category_config(category_id="engineers", display_name="Engineers v2")
            r2 = client.put(
                "/api/admin/platform/categories/engineers",
                json={
                    "expected_version": 1,
                    "config": cfg_v2,
                    "change_reason": "Rename display name",
                },
                headers=self.headers,
            )
            self.assertEqual(r2.status_code, 200)
            self.assertEqual(r2.json()["config_version"], 2)
            self.assertEqual(r2.json()["index_version"], 1)

            # Stale expected_version -> 409
            conflict = client.put(
                "/api/admin/platform/categories/engineers",
                json={"expected_version": 1, "config": cfg_v2},
                headers=self.headers,
            )
            self.assertEqual(conflict.status_code, 409)

            # Ingest & run search so cache warms at v2
            ingest_resp = client.post(
                "/api/admin/platform/categories/engineers/ingest",
                json={
                    "documents": [
                        {
                            "document_id": "eng-1",
                            "title": "Asha Rao",
                            "fields": {
                                "full_name": "Asha Rao",
                                "skills": "C++, Python",
                                "city": "Indore",
                                "years_exp": 6,
                                "verified": True,
                            },
                        }
                    ],
                    "replace_all": True,
                },
                headers=self.headers,
            )
            self.assertEqual(ingest_resp.status_code, 200)
            search_before = client.post(
                "/api/admin/platform/search",
                json={"category": "engineers", "query": "C++"},
                headers=self.headers,
            )
            self.assertEqual(search_before.status_code, 200)
            self.assertIn("engineers", platform_search.get_category_index_statuses())

            # Atomic rollback v2 -> v1 creates v3 with RolledBackFromVersion=1 and invalidates cache
            rb = client.post(
                "/api/admin/platform/categories/engineers/rollback",
                json={
                    "target_version": 1,
                    "expected_version": 2,
                    "reason": "Revert display name",
                },
                headers=self.headers,
            )
            self.assertEqual(rb.status_code, 200)
            rb_body = rb.json()
            self.assertEqual(rb_body["config_version"], 3)
            self.assertEqual(rb_body["rolled_back_from_version"], 1)
            self.assertEqual(rb_body["config"]["display_name"], "Engineers v1")
            self.assertNotIn("engineers", platform_search.get_category_index_statuses())

            history = client.get(
                "/api/admin/platform/categories/engineers/history", headers=self.headers
            ).json()["items"]
            self.assertEqual([h["config_version"] for h in history], [3, 2, 1])
            self.assertEqual(history[0]["rolled_back_from_version"], 1)

    def test_hybrid_bm25f_faiss_rrf_tech_tokens_synonyms_filters_and_privacy(self) -> None:
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            # Create private category first
            client.post(
                "/api/admin/platform/categories",
                json=_category_config(category_id="engineers", public_search_enabled=False),
                headers=self.headers,
            )
            docs = [
                {
                    "document_id": "doc-cpp",
                    "title": "Vikram C++ Architect",
                    "fields": {
                        "full_name": "Vikram Sharma",
                        "skills": "C++, Kubernetes, Linux",
                        "city": "Indore",
                        "years_exp": 8,
                        "verified": True,
                    },
                },
                {
                    "document_id": "doc-csharp",
                    "title": "Meera C# Developer",
                    "fields": {
                        "full_name": "Meera Patel",
                        "skills": "C#, .NET, SQL",
                        "city": "Pune",
                        "years_exp": 4,
                        "verified": True,
                    },
                },
                {
                    "document_id": "doc-c",
                    "title": "Rohan Embedded C Engineer",
                    "fields": {
                        "full_name": "Rohan Verma",
                        "skills": "C, RTOS",
                        "city": "Indore",
                        "years_exp": 2,
                        "verified": False,
                    },
                },
            ]
            ing = client.post(
                "/api/admin/platform/categories/engineers/ingest",
                json={"documents": docs, "replace_all": True},
                headers=self.headers,
            )
            self.assertEqual(ing.status_code, 200)
            self.assertEqual(ing.json()["documents_ingested"], 3)

            # Reject unknown fields on ingest
            bad_ing = client.post(
                "/api/admin/platform/categories/engineers/ingest",
                json={
                    "documents": [
                        {
                            "document_id": "bad-1",
                            "title": "Bad",
                            "fields": {"nonexistent_field": "x"},
                        }
                    ]
                },
                headers=self.headers,
            )
            self.assertEqual(bad_ing.status_code, 422)

            # Private category blocked on public endpoints, allowed on admin search
            self.assertEqual(client.get("/api/platform/categories").json(), [])
            pub_blocked = client.post(
                "/api/platform/search",
                json={"category": "engineers", "query": "C++"},
            )
            self.assertEqual(pub_blocked.status_code, 403)

            # Technical token distinction: C++ vs C# vs C
            cpp_res = client.post(
                "/api/admin/platform/search",
                json={"category": "engineers", "query": "C++"},
                headers=self.headers,
            )
            self.assertEqual(cpp_res.status_code, 200)
            cpp_body = cpp_res.json()
            self.assertEqual(cpp_body["data"][0]["id"], "doc-cpp")
            self.assertEqual(cpp_body["data"][0]["ranking_signals"]["engine"], "bm25f_rrf_v2")
            self.assertEqual(cpp_body["query_plan"]["ranking_engine"], "bm25f_rrf_v2")

            csharp_res = client.post(
                "/api/admin/platform/search",
                json={"category": "engineers", "query": "C#"},
                headers=self.headers,
            ).json()
            self.assertEqual(csharp_res["data"][0]["id"], "doc-csharp")

            # Synonym expansion: k8s -> kubernetes
            syn_res = client.post(
                "/api/admin/platform/search",
                json={"category": "engineers", "query": "k8s"},
                headers=self.headers,
            ).json()
            self.assertEqual(syn_res["data"][0]["id"], "doc-cpp")
            self.assertTrue(len(syn_res["query_plan"]["synonym_expansions"]) >= 1)

            # Typed filters: integer between + boolean eq
            filtered = client.post(
                "/api/admin/platform/search",
                json={
                    "category": "engineers",
                    "query": "Indore",
                    "filters": [
                        {"field": "years_exp", "operator": "between", "values": [5, 10]},
                        {"field": "verified", "operator": "eq", "value": True},
                    ],
                },
                headers=self.headers,
            ).json()
            self.assertEqual([d["id"] for d in filtered["data"]], ["doc-cpp"])
            self.assertTrue(filtered["query_plan"]["filters_applied"])

            # Invalid filter on non-filterable field -> 400
            bad_filter = client.post(
                "/api/admin/platform/search",
                json={
                    "category": "engineers",
                    "query": "Vikram",
                    "filters": [{"field": "full_name", "operator": "eq", "value": "Vikram"}],
                },
                headers=self.headers,
            )
            self.assertEqual(bad_filter.status_code, 400)

            # Exact document ID lookup
            exact = client.post(
                "/api/admin/platform/search",
                json={"category": "engineers", "query": "doc-csharp"},
                headers=self.headers,
            ).json()
            self.assertEqual(exact["data"][0]["id"], "doc-csharp")
            self.assertTrue(exact["data"][0]["exact_identifier_match"])
            self.assertEqual(exact["data"][0]["score"], 100.0)

            # Enable public search -> visible in /api/platform/categories and searchable publicly
            pub_cfg = _category_config(category_id="engineers", public_search_enabled=True)
            client.put(
                "/api/admin/platform/categories/engineers",
                json={"expected_version": 1, "config": pub_cfg},
                headers=self.headers,
            )
            pub_cats = client.get("/api/platform/categories").json()
            self.assertEqual([c["category_id"] for c in pub_cats], ["engineers"])
            pub_search = client.post(
                "/api/platform/search",
                json={"category": "engineers", "query": "C++"},
            )
            self.assertEqual(pub_search.status_code, 200)
            self.assertEqual(pub_search.json()["data"][0]["id"], "doc-cpp")

    def test_sql_source_discovery_suggestions_join_preview_preflight_and_sync(self) -> None:
        os.environ["SEARCH_SOURCE_BONC_MOCK"] = "DRIVER={ODBC};SERVER=mock;DATABASE=MockDB;UID=ro;PWD=secret"
        mock_catalog = {
            "profile_id": "BONC_MOCK",
            "database": "MockDB",
            "schemas": ["dbo"],
            "tables": [
                {
                    "schema": "dbo",
                    "name": "Profiles",
                    "type": "BASE TABLE",
                    "primary_key_columns": ["ProfileId"],
                    "columns": [
                        {"name": "ProfileId", "data_type": "int", "nullable": False, "is_primary_key": True, "is_foreign_key": False},
                        {"name": "FullName", "data_type": "nvarchar", "nullable": False, "is_primary_key": False, "is_foreign_key": False},
                        {"name": "Skills", "data_type": "nvarchar", "nullable": True, "is_primary_key": False, "is_foreign_key": False},
                        {"name": "Email", "data_type": "nvarchar", "nullable": True, "is_primary_key": False, "is_foreign_key": False},
                        {"name": "PasswordHash", "data_type": "nvarchar", "nullable": True, "is_primary_key": False, "is_foreign_key": False},
                        {"name": "CityId", "data_type": "int", "nullable": True, "is_primary_key": False, "is_foreign_key": True},
                    ],
                },
                {
                    "schema": "dbo",
                    "name": "Cities",
                    "type": "BASE TABLE",
                    "primary_key_columns": ["CityId"],
                    "columns": [
                        {"name": "CityId", "data_type": "int", "nullable": False, "is_primary_key": True, "is_foreign_key": False},
                        {"name": "City", "data_type": "nvarchar", "nullable": False, "is_primary_key": False, "is_foreign_key": False},
                    ],
                },
            ],
            "relationships": [
                {
                    "constraint_name": "FK_Profiles_Cities",
                    "from_schema": "dbo",
                    "from_table": "Profiles",
                    "to_schema": "dbo",
                    "to_table": "Cities",
                    "columns": [{"from_column": "CityId", "to_column": "CityId", "ordinal_position": 1}],
                }
            ],
        }

        # 1. Mapping suggestions exclude sensitive PII columns (Email, PasswordHash)
        suggestions = source_sync.build_source_mapping_suggestions(
            mock_catalog, schema="dbo", table="Profiles"
        )
        self.assertEqual(suggestions["id_column_suggestion"]["column"], "ProfileId")
        suggested_cols = {f["source_column"] for f in suggestions["fields"]}
        self.assertIn("FullName", suggested_cols)
        self.assertIn("Skills", suggested_cols)
        self.assertNotIn("Email", suggested_cols)
        self.assertNotIn("PasswordHash", suggested_cols)

        # 2. Join view preview generates SQL without executing DDL
        with patch.object(source_sync, "discover_source_schema", return_value=mock_catalog):
            preview = source_sync.generate_join_view_preview(
                "BONC_MOCK",
                base_schema="dbo",
                base_table="Profiles",
                base_id_column="ProfileId",
                view_schema="searchai",
                view_name="vw_Search_Profiles",
                selected_relationships=[
                    {
                        "constraint_name": "FK_Profiles_Cities",
                        "from_schema": "dbo",
                        "from_table": "Profiles",
                        "to_schema": "dbo",
                        "to_table": "Cities",
                    }
                ],
            )
            self.assertFalse(preview["execution_performed"])
            self.assertIn("CREATE OR ALTER VIEW [searchai].[vw_Search_Profiles]", preview["view_sql"])
            self.assertNotIn("[Email]", preview["view_sql"])

        # 3. API route for listing source profiles hides connection strings
        app = create_app(warmup_embedding_model=False, connect_platform_database=False)
        with TestClient(app) as client:
            profiles_resp = client.get("/api/admin/platform/sources", headers=self.headers)
            self.assertEqual(profiles_resp.status_code, 200)
            body = profiles_resp.json()
            self.assertEqual(
                body["items"],
                [{"profile_id": "BONC_MOCK", "connection_env": "SEARCH_SOURCE_BONC_MOCK"}],
            )
            self.assertNotIn("PWD=secret", profiles_resp.text)

            # 4. Sync endpoint enforces preflight & ingests rows
            sql_cfg = _category_config(
                category_id="sql_people",
                source={
                    "type": "sqlserver",
                    "connection_env": "SEARCH_SOURCE_BONC_MOCK",
                    "schema": "dbo",
                    "table": "Profiles",
                    "id_column": "ProfileId",
                    "filters": [],
                    "max_records": 1000,
                },
            )
            sql_cfg["fields"] = [sql_cfg["fields"][0], sql_cfg["fields"][1]]
            client.post("/api/admin/platform/categories", json=sql_cfg, headers=self.headers)

            # Route-level validation regressions preserved from legacy suite:
            # 1. Invalid profile_id on /sources/{profile_id}/schema -> 422
            self.assertEqual(
                client.get("/api/admin/platform/sources/invalid-id!/schema", headers=self.headers).status_code,
                422,
            )
            # 2. HTTP routes for schema, mapping-suggestions, join-view-preview, validate
            with patch.object(source_sync, "discover_source_schema", return_value=mock_catalog):
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/sources/BONC_MOCK/schema?schema=dbo",
                        headers=self.headers,
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    client.get(
                        "/api/admin/platform/sources/BONC_MOCK/mapping-suggestions?schema=dbo&table=Profiles",
                        headers=self.headers,
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    client.post(
                        "/api/admin/platform/sources/BONC_MOCK/join-view-preview",
                        headers=self.headers,
                        json={
                            "base_schema": "dbo",
                            "base_table": "Profiles",
                            "base_id_column": "ProfileId",
                            "view_schema": "searchai",
                            "view_name": "vw_Search_Profiles",
                            "selected_relationships": [
                                {
                                    "constraint_name": "FK_Profiles_Cities",
                                    "from_schema": "dbo",
                                    "from_table": "Profiles",
                                    "to_schema": "dbo",
                                    "to_table": "Cities",
                                }
                            ],
                        },
                    ).status_code,
                    200,
                )
            with patch.object(
                source_sync,
                "validate_sqlserver_source",
                return_value={
                    "profile_id": "BONC_MOCK",
                    "database": "MockDB",
                    "schema": "dbo",
                    "table": "Profiles",
                    "id_column": "ProfileId",
                    "total_rows": 2,
                    "non_null_ids": 2,
                    "distinct_ids": 2,
                    "null_id_count": 0,
                    "blank_id_count": 0,
                    "duplicate_id_count": 0,
                    "max_records": 1000,
                    "is_valid": True,
                    "warnings": [],
                },
            ):
                self.assertEqual(
                    client.post(
                        "/api/admin/platform/sources/BONC_MOCK/validate",
                        headers=self.headers,
                        json={
                            "schema": "dbo",
                            "table": "Profiles",
                            "id_column": "ProfileId",
                            "filters": [],
                            "max_records": 1000,
                        },
                    ).status_code,
                    200,
                )

            # 3. Mismatched category_id in PUT URL vs payload -> 422
            mismatch = client.put(
                "/api/admin/platform/categories/different_id",
                headers=self.headers,
                json={"expected_version": 1, "config": sql_cfg},
            )
            self.assertEqual(mismatch.status_code, 422)

            # 4. Blank rollback reason -> 422
            blank_rb = client.post(
                "/api/admin/platform/categories/sql_people/rollback",
                headers=self.headers,
                json={"target_version": 1, "expected_version": 1, "reason": "   "},
            )
            self.assertEqual(blank_rb.status_code, 422)

            # 5. Sync endpoint enforces preflight & ingests rows
            fake_engine = MagicMock()
            fake_conn = fake_engine.connect.return_value.__enter__.return_value
            fake_conn.execute.return_value.mappings.return_value.all.return_value = [
                {"_document_id": 101, "full_name": "Neha Joshi", "skills": "Python, FastAPI"},
                {"_document_id": 102, "full_name": "Arjun Nair", "skills": "SQL Server"},
            ]
            with (
                patch.object(
                    source_sync,
                    "validate_sqlserver_source",
                    return_value={"is_valid": True, "warnings": []},
                ),
                patch.object(source_sync, "_source_engine", return_value=fake_engine),
            ):
                sync_resp = client.post(
                    "/api/admin/platform/categories/sql_people/sync",
                    headers=self.headers,
                )
                self.assertEqual(sync_resp.status_code, 200)
                self.assertEqual(sync_resp.json()["documents_synced"], 2)

    def test_offline_search_evaluation_metrics(self) -> None:
        m1 = search_evaluation.evaluate_ranking(
            ["doc-1", "doc-2", "doc-3", "doc-4"],
            relevant_ids={"doc-1", "doc-3"},
            k=1,
        )
        self.assertEqual(m1["precision_at_k"], 1.0)
        self.assertAlmostEqual(m1["recall_at_k"], 0.5)
        self.assertEqual(m1["mrr_at_k"], 1.0)
        self.assertEqual(m1["relevant_found_at_k"], 1)

        m3 = search_evaluation.evaluate_ranking(
            ["doc-1", "doc-2", "doc-3", "doc-4"],
            relevant_ids={"doc-1", "doc-3"},
            k=3,
        )
        self.assertAlmostEqual(m3["precision_at_k"], 2.0 / 3.0, places=3)
        self.assertEqual(m3["recall_at_k"], 1.0)
        self.assertEqual(m3["mrr_at_k"], 1.0)
        self.assertGreater(m3["ndcg_at_k"], 0.9)
        self.assertEqual(m3["returned_at_k"], 3)


if __name__ == "__main__":
    unittest.main()
