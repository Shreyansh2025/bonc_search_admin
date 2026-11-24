# BONC General Search Platform & Search Admin Backend

Independent FastAPI backend (`backend/`) running on loopback port `8004`.

## Package Layout

```text
app/
├── main.py                              # Standalone FastAPI entrypoint & request telemetry middleware
├── config.py                            # Environment config (APP_ENV, BONC getUserDetail auth, platform DB, CORS, prod observability)
├── logger.py                            # Stdout logger (search-admin-platform)
├── db/
│   └── platform_db.py                   # Independent SQL Server pool strictly for searchai.* tables
├── clients/
│   └── production_search_client.py      # Optional read-only GET client (disabled by default; strips localProducts)
├── schemas/
│   └── platform.py                      # Strict Pydantic v2 General Search Platform models
├── repositories/
│   ├── category_store.py                # Category CRUD, version history, atomic rollback, docs & read-only feedback
│   └── observability_store.py           # Persistent SearchLogs, ApiRequestLogs, KPIs, failure & relevance analytics
├── services/
│   ├── admin_auth.py                    # Centralized BONC Admin auth lifecycle & FastAPI dependencies
│   ├── bonc_auth.py                     # BoncTokenVerifier, VerifiedBoncIdentity, RBAC & BoncJwtAuthProvider
│   ├── bonc_auth_adapter.py             # BONC .NET getUserDetail verifier & SHA-256 success-only TTL cache
│   ├── embedding_model.py               # Singleton SentenceTransformer (all-MiniLM-L6-v2, 384-d)
│   ├── platform_common.py               # HTML stripping, C/C++/C# tokenization, inverted index & spellcheck
│   ├── query_understanding.py           # Deterministic alias/value/constraint extraction & synonym expansion
│   ├── ranking_v2.py                    # Shared BM25F scoring & weighted Reciprocal Rank Fusion (RRF)
│   ├── platform_search.py               # Per-category FAISS + BM25F hybrid search pipeline & cache
│   ├── source_sync.py                   # SQL Server metadata discovery, mapping suggestions, join-view preview & sync
│   └── search_evaluation.py             # Offline IR metrics (Precision@k, Recall@k, MRR@k, NDCG@k)
└── routes/
    ├── health.py                        # GET /health/live, GET /health/ready
    ├── auth.py                          # GET /api/admin/auth/session
    ├── engines/public.py                # GET /api/platform/categories, POST /api/platform/search
    └── admin/
        ├── platform.py                  # /api/admin/platform/* (categories, sources, sync, ingest, rollback, search)
        ├── observability.py             # /api/admin/platform/{system-health,search-logs*,metrics/*}
        └── production.py                # /api/admin/production/{health,index-status} (GET-only, disabled by default)
```

## Authentication & Authorization

- BONC JWT verification via BONC's existing `.NET` `GET /api/userService/getUserDetail` endpoint (`BONC_AUTH_VERIFY_URL`) is the **only** supported Search Admin user authentication system.
- There is no local username/password login, no local SQLite auth store, no session cookies, no CSRF flow, no alternative verification mode, and no authentication-disable switch.
- Incoming requests must supply `Authorization: Bearer <AuthToken>`. Search Admin decodes `UserRowId` from the JWT payload strictly as an untrusted lookup parameter, forwards the original unchanged Bearer token to `BONC_AUTH_VERIFY_URL?userRowId=<UserRowId>`, verifies matching `UserRowId`, `IsActive`, and an allowed role in `BONC_AUTH_ADMIN_ROLES` (default `Admin,SuperAdmin`), and maps verified admin roles into Search Admin's explicit route permissions.
- When `BONC_AUTH_VERIFY_URL` is unset, `BoncJwtAuthProvider` fails closed with HTTP `503`.
- Every Admin write records the verified BONC `UserRowId` (`principal.actor`) directly in `searchai.SearchCategories.UpdatedBy` and `searchai.SearchCategoryHistory.ChangedBy`.

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
