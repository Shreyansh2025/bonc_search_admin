# Deployment & Operations Reference (`bonc_search_admin`)

> **Important:** Do not deploy or apply DDL/service changes to staging or production without reviewed cutover and infrastructure sign-off.

## 1. Topology

- **Backend**: `gunicorn -c gunicorn.conf.py app.main:app` bound privately to `127.0.0.1:8004` (`WEB_CONCURRENCY=1` so in-memory FAISS category caches stay consistent on updates/rollbacks/syncs).
- **Frontend**: Static bundle from `frontend/dist/` served via Nginx under `/search-admin/` (built with `VITE_BASE_PATH=/search-admin/` and `VITE_ADMIN_API_BASE_URL=/search-admin-api`), or Vite dev server on `127.0.0.1:5175` locally.
- **No port-`8002` dependency**: Do not add `After=` or `Wants=` dependencies on legacy `bonc-search-ai-staging.service`. Stop any legacy port-`8002` writer before pointing `bonc_search_admin` at staging `searchai.*` tables (see [DATABASE_OWNERSHIP.md](DATABASE_OWNERSHIP.md)).

## 2. Reference Templates

- Backend systemd unit: `deployment/bonc-search-admin-backend.service.example`
- Nginx reverse proxy: `deployment/nginx-search-admin.conf.example`
- Environment templates: `.env.example`, `config/local.env.example`, `config/staging.env.example`, `frontend/.env.example`
- SQL Server reference DDL: `backend/sql/general_search_platform_schema.sql`

## 3. Clean-Server Deployment Steps

1. **Provision Database Schema (DBA-reviewed)**:
   Ensure the target SQL Server database contains the six `searchai.*` tables from `backend/sql/general_search_platform_schema.sql` and install **ODBC Driver 18 for SQL Server** on the backend host.
2. **Install Backend**:
   ```bash
   cd /opt/bonc-search-admin/backend
   python3.11 -m venv .venv
   .venv/bin/pip install --upgrade pip
   .venv/bin/pip install -r requirements.txt
   ```
3. **Configure Environment**:
   Create `/etc/bonc-search-admin/backend.env` (mode `0600`, owned by service user `bonc-admin`) based on `config/staging.env.example`.
4. **Build Frontend Static Bundle**:
   ```bash
   cd /opt/bonc-search-admin/frontend
   npm ci
   VITE_BASE_PATH=/search-admin/ VITE_ADMIN_API_BASE_URL=/search-admin-api VITE_AUTH_MODE=bonc npm run build
   ```
5. **Start / Restart / Stop Service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now bonc-search-admin-backend
   sudo systemctl restart bonc-search-admin-backend
   sudo systemctl stop bonc-search-admin-backend
   ```

## 4. Health Verification

```bash
# Process liveness (always 200 when process is up)
curl -fsS http://127.0.0.1:8004/health/live

# Readiness (200 when auth provider + platform SQL DB are ready; 503 otherwise)
curl -i http://127.0.0.1:8004/health/ready
```

Note: In `staging`/`production` (`APP_ENV != local`), `SEARCH_ADMIN_AUTH_MODE` defaults to `bonc_jwt`, which intentionally reports `authProvider: "not_configured"` (HTTP `503`) on `/health/ready` until the BONC `.NET` verification contract and role mapping are wired in.

## 5. Production Integration Gate (Stage 3)

Keep `PRODUCTION_OBSERVABILITY_ENABLED=false` until all Stage 3 prerequisites are verified:
1. Identify the live VPS deployment commit, service unit, and route protection on the original Product & Company Search service.
2. Confirm whether `/api/healthz` and `/api/debug/index-status` require reverse-proxy or token auth (`PRODUCTION_SEARCH_AUTH_MODE=bearer|api_key|none`).
3. Confirm BrochureIQ `localProducts` stripping remains enforced via automated tests before enabling.
4. Keep all production interactions strictly read-only (`GET` only).
