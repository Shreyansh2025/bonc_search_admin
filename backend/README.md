# BONC General Search Platform & Search Admin Backend

Independent FastAPI backend (`backend/`) running on loopback port `8004`.

## Package Layout

```text
app/
├── main.py                              # Standalone FastAPI entrypoint & request telemetry middleware
├── config.py                            # Environment config (platform DB, local auth DB, CORS, prod observability)
├── logger.py                            # Stdout logger (search-admin-platform)
├── db/
│   ├── auth_db.py                       # Isolated SQLite admin_sessions & admin_login_attempts
│   └── platform_db.py                   # Independent SQL Server pool strictly for searchai.* tables
├── clients/
│   └── production_search_client.py      # Optional read-only GET client (disabled by default; strips localProducts)
├── schemas/
│   ├── auth.py                          # Admin login schema
│   └── platform.py                      # Strict Pydantic v2 General Search Platform models
├── repositories/
│   ├── category_store.py                # Category CRUD, version history, atomic rollback, docs & read-only feedback
│   └── observability_store.py           # Persistent SearchLogs, ApiRequestLogs, KPIs, failure & relevance analytics
├── services/
│   ├── admin_auth.py                    # Pluggable AdminAuthProvider, LocalSessionAuthProvider, CSRF & rate limiting
│   ├── bonc_auth.py                     # BoncTokenVerifier, VerifiedBoncIdentity, BoncClaimsValidationConfig, RBAC & BoncJwtAuthProvider
│   ├── bonc_auth_adapter.py             # Unactivated BoncTokenVerifier adapter importing the reusable bonc-auth package
│   ├── embedding_model.py               # Singleton SentenceTransformer (all-MiniLM-L6-v2, 384-d)
│   ├── platform_common.py               # HTML stripping, C/C++/C# tokenization, inverted index & spellcheck
│   ├── query_understanding.py           # Deterministic alias/value/constraint extraction & synonym expansion
│   ├── ranking_v2.py                    # Shared BM25F scoring & weighted Reciprocal Rank Fusion (RRF)
│   ├── platform_search.py               # Per-category FAISS + BM25F hybrid search pipeline & cache
│   ├── source_sync.py                   # SQL Server metadata discovery, mapping suggestions, join-view preview & sync
│   └── search_evaluation.py             # Offline IR metrics (Precision@k, Recall@k, MRR@k, NDCG@k)
└── routes/
    ├── health.py                        # GET /health/live, GET /health/ready
    ├── auth.py                          # POST /api/admin/auth/login, GET /session, POST /logout
    ├── engines/public.py                # GET /api/platform/categories, POST /api/platform/search
    └── admin/
        ├── platform.py                  # /api/admin/platform/* (categories, sources, sync, ingest, rollback, search)
        ├── observability.py             # /api/admin/platform/{system-health,search-logs*,metrics/*}
        └── production.py                # /api/admin/production/{health,index-status} (GET-only, disabled by default)
```

## Authentication & Authorization

- Centralized `AdminAuthProvider` abstraction in `app/services/admin_auth.py` and BONC provider/policy abstractions in `app/services/bonc_auth.py`.
- Reusable `bonc-auth` package dependency is pinned by exact commit SHA in `requirements.txt` (local development may use an editable install `pip install -e "<path-to-bonc-auth>[fastapi]"`). `BoncAuthPackageVerifierAdapter` in `app/services/bonc_auth_adapter.py` connects `bonc_auth.BoncAuth` to `BoncTokenVerifier` without duplicating package code, but BONC authentication remains **unactivated and fail-closed (HTTP `503`)** in `build_default_auth_provider()` until the `.NET` team confirms the verification mechanism (local JWT verification via JWKS/public key/shared secret preferred) and trusted claims contract.
- Default local-development `LocalSessionAuthProvider` uses salted `scrypt`/`pbkdf2_sha256`, `HttpOnly` cookie (`bonc_search_admin_platform_session`), in-memory `X-CSRF-Token` validation on state-changing requests, IP-hashed login rate limiting, and an optional backend-only CLI `SEARCH_ADMIN_SERVICE_TOKEN` for automated evaluation tools.
- Every Admin write records the authenticated `principal.actor` directly in `searchai.SearchCategories.UpdatedBy` and `searchai.SearchCategoryHistory.ChangedBy`.

## Running Locally

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8004
```

For fast local checks without eager SentenceTransformer warmup:
```powershell
$env:SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL="false"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8004
```
