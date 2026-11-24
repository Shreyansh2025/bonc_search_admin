# BONC General Search Platform & Search Admin (`bonc_search_admin`)

Independent, self-contained application owning the **General Search Platform** engine, its management APIs, observability/analytics, and the **Search Admin Console** frontend.

## Architecture Overview

| Layer | Location | Default Port | Ownership |
|---|---|---|---|
| **Backend (FastAPI)** | `backend/` | `127.0.0.1:8004` | General Search Engine (hybrid BM25F + FAISS + `all-MiniLM-L6-v2` + query understanding + synonyms + typed filters), SQL source discovery/sync, push ingestion, versioned category config & atomic rollback, search logs/KPIs/evaluation metrics, centralized Admin Auth, and disabled-by-default read-only `ProductionSearchClient`. |
| **Frontend (React + Vite)** | `frontend/` | `127.0.0.1:5175` | System Health & Analytics, Search Logs & Per-User Activity, Data Sources & Configuration, Generic Search Engine Testing, and Read-Only Feedback Log. |
| **Platform SQL Database** | `backend/app/db/platform_db.py` | Configured via `SEARCH_PLATFORM_SQL_ODBC_CONNECT_<ENV>` | Exclusively owns the six `searchai.*` tables (`SearchCategories`, `SearchCategoryHistory`, `SearchDocuments`, `SearchFeedback`, `SearchLogs`, `ApiRequestLogs`). |
| **Admin Auth Store** | `backend/app/db/auth_db.py` | Local SQLite (`./data/admin_auth.db`) | Isolated local-dev session and IP-hashed login rate-limit tables (`admin_sessions`, `admin_login_attempts`). Pluggable `AdminAuthProvider` ready for BONC JWT integration. |

### Strict Project Boundaries

- **Zero runtime dependency on the legacy split Search AI microservice (port `8002`)** — this repository runs completely independently.
- **Original Production Application (Product & Company Search + BrochureIQ)** remains separate and untouched. An optional, strictly GET-only `ProductionSearchClient` is built in but **disabled by default** (`PRODUCTION_OBSERVABILITY_ENABLED=false`) and unconditionally strips BrochureIQ (`localProducts`).
- **Zero BrochureIQ contamination**: Zero BrochureIQ code or dependencies (`PyMuPDF`, `pytesseract`, `pillow`, `rembg`, `onnxruntime`, `openpyxl`, `python-multipart`).
- **Removed per Stage 2 Decisions**:
  - Legacy Catalog Thresholds (`GET/PUT /api/admin/search-settings`, `GET /api/admin/search-settings/history`, `Catalog Thresholds` UI tab) are retired.
  - Inline playground feedback writing (`POST /api/admin/platform/categories/{id}/feedback`, `Mark Relevant` / `Not Relevant` buttons) and the old B2B Catalog Playground (`POST /api/search`) are excluded.
  - Generic Search Engine Testing (`POST /api/admin/platform/search` + `Engine Testing` UI tab) and read-only feedback retrieval (`GET .../feedback`, `GET .../metrics/relevance`) are preserved.

## Prerequisites

- **Python 3.11+** and `git` (required by `pip` to install the pinned `bonc-auth` package dependency from GitHub).
- **Node.js 22.6+** (tested with Node 24; required for `--experimental-strip-types` in frontend unit/contract tests) and `npm`.
- **ODBC Driver 18 for SQL Server** (required at runtime when connecting to SQL Server via `pyodbc`).
- **SQL Server database** provisioned with the six `searchai.*` tables defined in [backend/sql/general_search_platform_schema.sql](backend/sql/general_search_platform_schema.sql).
- **Internet / HuggingFace cache access** on first startup if `SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL=true` so `sentence-transformers` can download `all-MiniLM-L6-v2` (384-d).

## Clean-Machine Installation & Local Setup

### 1. Backend Setup (`backend/`)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

*(On Linux/macOS, replace `.\.venv\Scripts\python.exe` with `./.venv/bin/python`.)*

Copy `config/local.env.example` to `backend/.env` and configure your local SQL Server connection string (`SEARCH_PLATFORM_SQL_ODBC_CONNECT_LOCAL`) and local admin credentials. Generate a salted `scrypt` password hash offline:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.services.admin_auth
```

Paste the generated `SEARCH_ADMIN_PASSWORD_HASH=...` into `backend/.env` along with `SEARCH_ADMIN_USERNAME`. Never commit `.env` files.

### 2. Frontend Setup (`frontend/`)

```powershell
cd frontend
npm ci
```

Optionally copy `frontend/.env.example` to `frontend/.env.local` if you need custom ports or proxy targets (defaults: dev port `5175`, preview port `4175`, proxy `/admin-api` -> `http://127.0.0.1:8004`).

## Environment Configuration

See [.env.example](.env.example) for the complete reference, plus environment-specific templates:

- `config/local.env.example` — Local development backend template (`APP_ENV=local`, `SEARCH_ADMIN_AUTH_MODE=local_session`).
- `config/staging.env.example` — Staging backend template (`APP_ENV=staging`, `SEARCH_ADMIN_AUTH_MODE=bonc_jwt`, fail-closed until BONC contract is wired).
- `frontend/.env.example` — Frontend Vite configuration (`VITE_ADMIN_API_BASE_URL`, `VITE_BASE_PATH`, `VITE_AUTH_MODE`, `VITE_PORT`, `VITE_PREVIEW_PORT`, server-only `ADMIN_BACKEND_TARGET`).

### Key Backend Variables

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `local` | Environment name (`local`, `staging`, `production`). Non-local environments enforce `bonc_jwt` and disable Swagger docs by default. |
| `PORT` | `8004` | Backend HTTP port (loopback `127.0.0.1`). |
| `ALLOWED_ORIGINS` | Local ports `5175`/`4175` in `local`; empty elsewhere | Comma-separated browser CORS origins (never `*`). |
| `SEARCH_PLATFORM_SQL_ODBC_CONNECT_<ENV>` | *(required for DB)* | SQL Server ODBC connection string for `searchai.*` tables (alternative: `SEARCH_PLATFORM_SQL_CONNECTION_STRING_<ENV>`). |
| `SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL` | `true` | Preload `all-MiniLM-L6-v2` in background on startup. Set `false` for lightweight checks. |
| `SEARCH_SOURCE_<PROFILE>` | *(optional)* | Read-only SQL Server connection strings for external source schema discovery and sync. |
| `SEARCH_ADMIN_AUTH_MODE` | `local_session` in `local`; `bonc_jwt` elsewhere | Centralized auth mode. `local_session` is prohibited outside `APP_ENV=local`. |
| `SEARCH_ADMIN_USERNAME` / `SEARCH_ADMIN_PASSWORD_HASH` | *(required for `local_session`)* | Backend-only local dev credentials. |
| `SEARCH_ADMIN_AUTH_DB_PATH` | `./data/admin_auth.db` | Local SQLite store for `local_session` mode (override with `SEARCH_ADMIN_AUTH_DB_URL`). |
| `PRODUCTION_OBSERVABILITY_ENABLED` | `false` | Optional read-only GET client for original production search health/index status. |
| `WEB_CONCURRENCY` / `GUNICORN_TIMEOUT` | `1` / `120` | Keep `WEB_CONCURRENCY=1` so in-memory FAISS category indexes stay consistent. |

## Startup & Shutdown

### Local Development

**Start Backend (port `8004`):**
```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8004
```
For fast startup without eager embedding model download/warmup:
```powershell
$env:SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL="false"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8004
```

**Start Frontend (port `5175`):**
```powershell
cd frontend
npm run dev
```

**Stop Local Services:** Press `Ctrl+C` in each terminal. FastAPI's lifespan handler cancels any active embedding warmup task and closes the optional HTTP client cleanly.

### Production / Hosted (Linux systemd + Gunicorn + Nginx)

```bash
# Start backend directly via Gunicorn from backend/
cd /opt/bonc-search-admin/backend
.venv/bin/gunicorn -c gunicorn.conf.py app.main:app

# Or via systemd (after approved deployment setup)
sudo systemctl start bonc-search-admin-backend
sudo systemctl status bonc-search-admin-backend
sudo systemctl stop bonc-search-admin-backend
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and `deployment/` for full systemd and Nginx templates.

## Health Checks

| Endpoint | Auth | Expected Healthy Response | Notes |
|---|---|---|---|
| `GET /health/live` | Unauthenticated | `200 OK` — `{"status": "ok", "service": "search-admin-platform"}` | Process liveness probe. |
| `GET /health/ready` | Unauthenticated | `200 OK` (`status: "ready"`) or `503 Service Unavailable` (`status: "not_ready"`) | Checks `authProvider`, `authStore` (in `local_session` mode), `platformDatabase` (`SELECT 1`), and `embeddingModel`. Reports `productionObservability` (`disabled`/`enabled`) without blocking readiness. |
| `GET /api/admin/platform/system-health` | Admin Auth | `200 OK` | Full Admin console health snapshot (DB latency, embedding status, FAISS category index cache, 24h HTTP 5xx summary, optional production observability). |

## Automated Verification

Run from the repository root:

```powershell
# Backend tests (isolated in-memory SQLite + mocked embeddings/SQL sources + SQL Server dialect checks)
.\backend\.venv\Scripts\python.exe -m unittest discover -s tests/backend -p "test_*.py" -v

# Frontend typecheck, unit/contract tests, and production bundle build
cd frontend
npm run typecheck
npm run test
npm run build
```

## Documentation

- [Backend Guide](backend/README.md)
- [Frontend Guide](frontend/README.md)
- [Architecture Audit](docs/ARCHITECTURE_AUDIT.md)
- [API Integration Contract](docs/API_INTEGRATION_CONTRACT.md)
- [BONC Auth Integration Contract](docs/BONC_AUTH_INTEGRATION_CONTRACT.md)
- [Database Ownership & Cutover Guide](docs/DATABASE_OWNERSHIP.md)
- [Deployment & Operations Reference](docs/DEPLOYMENT.md)
