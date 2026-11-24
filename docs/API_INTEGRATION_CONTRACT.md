# BONC General Search Platform & Search Admin — API Integration Contract

Base URL (local default): `http://127.0.0.1:8004` (proxied from frontend via `/admin-api`).

## 1. Health Probes (Unauthenticated)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health/live` | Process liveness (`{"status": "ok", "service": "search-admin-platform"}`) |
| `GET` | `/health/ready` | Checks local `authStore`, `platformDatabase` (`SELECT 1`), `embeddingModel` state, and reports optional `productionObservability` (`disabled`/`enabled`; never blocks readiness) |

## 2. Admin Authentication (`/api/admin/auth/*`)

| Method | Path | Auth / CSRF | Purpose |
|---|---|---|---|
| `POST` | `/api/admin/auth/login` | Credentials + rate limit | Creates persistent SQLite session, sets `HttpOnly` `bonc_search_admin_platform_session` cookie, returns `csrf_token`, `actor`, `roles` |
| `GET` | `/api/admin/auth/session` | Session cookie or service Bearer | Validates active principal; clears invalid cookie on 401 |
| `POST` | `/api/admin/auth/logout` | Session + `X-CSRF-Token` | Revokes session and clears cookie |

## 3. Public General Search Platform Routes (`/api/platform/*`)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/platform/categories` | Public | Lists active categories with `public_search_enabled=true` |
| `POST` | `/api/platform/search` | Public | Executes hybrid BM25F + FAISS search on active public categories (403 on private categories); persists `searchai.SearchLogs` (`surface="public"`) |

## 4. Admin General Search Platform Routes (`/api/admin/platform/*`)

All endpoints require Admin authentication via `AdminAuthProvider` (browser `HttpOnly` cookie + `X-CSRF-Token` on non-GET writes, OR backend-only `Authorization: Bearer <SEARCH_ADMIN_SERVICE_TOKEN>`).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/admin/platform/search` | Admin-authenticated Generic Search Engine Testing & offline evaluation (supports private categories; persists `surface="admin"` in `SearchLogs`) |
| `GET` | `/api/admin/platform/sources` | Lists configured `SEARCH_SOURCE_*` profile IDs (zero secrets returned) |
| `GET` | `/api/admin/platform/sources/{profile_id}/schema` | Discovers SQL Server schemas, tables, views, PKs, and FKs |
| `GET` | `/api/admin/platform/sources/{profile_id}/mapping-suggestions` | Suggests field/ID mappings while excluding sensitive/PII columns |
| `POST` | `/api/admin/platform/sources/{profile_id}/join-view-preview` | Generates reviewable many-to-one SQL view script (`execution_performed: false`) |
| `POST` | `/api/admin/platform/sources/{profile_id}/validate` | Checks row counts, NULL/blank/duplicate document IDs, and `max_records` |
| `GET` | `/api/admin/platform/categories` | Lists all categories with document counts & version metadata |
| `POST` | `/api/admin/platform/categories` | Creates category and v1 history row (HTTP 201; 409 on duplicate) |
| `PUT` | `/api/admin/platform/categories/{category_id}` | Updates category with optimistic `expected_version` check and invalidates cache |
| `POST` | `/api/admin/platform/categories/{category_id}/rollback` | Atomically restores historical version as a new version with `RolledBackFromVersion` provenance and invalidates cache |
| `GET` | `/api/admin/platform/categories/{category_id}/history` | Lists immutable configuration version history |
| `POST` | `/api/admin/platform/categories/{category_id}/ingest` | Push-ingests validated documents (upsert or `replace_all`) and invalidates cache |
| `POST` | `/api/admin/platform/categories/{category_id}/sync` | Runs server-side ID preflight, syncs SQL Server source, and invalidates cache |
| `GET` | `/api/admin/platform/categories/{category_id}/feedback` | Read-only historical relevance judgments for one category |

## 5. Admin Observability & Analytics Routes (`/api/admin/platform/*`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/admin/platform/system-health` | Live API, platform DB, embedding model, category index cache, 24h 5xx telemetry, and optional read-only production snapshot |
| `GET` | `/api/admin/platform/search-logs` | Filtered, paginated persistent `SearchLogs` + summary aggregates |
| `GET` | `/api/admin/platform/search-logs/users` | Per-authenticated-user search attempt breakdown |
| `GET` | `/api/admin/platform/metrics/kpis` | Search KPIs, API 4xx/5xx failure monitoring, and feedback summary |
| `GET` | `/api/admin/platform/metrics/api-failures` | API request volume, 4xx vs 5xx separation, failure-prone endpoints |
| `GET` | `/api/admin/platform/metrics/relevance` | Read-only feedback-derived relevance & negative-feedback metrics |

## 6. Optional Read-Only Production Observability (`/api/admin/production/*`)

Disabled by default (`PRODUCTION_OBSERVABILITY_ENABLED=false`). Strictly GET-only; never executes writes; unconditionally strips BrochureIQ `localProducts`.

| Method | Path | Upstream Target (`origin/main`) |
|---|---|---|
| `GET` | `/api/admin/production/health` | `GET /api/healthz` |
| `GET` | `/api/admin/production/index-status` | `GET /api/debug/index-status` (filtered to `b2bCompanies`, `b2bProducts`) |

## 7. Explicitly Removed / Excluded Endpoints

- `GET /api/admin/search-settings`, `PUT /api/admin/search-settings`, `GET /api/admin/search-settings/history` — Retired (Decision #1).
- `POST /api/admin/platform/categories/{category_id}/feedback` — Removed (Decision #2).
- `POST /api/search` — Legacy B2B Product & Company Search remains owned by original production (`origin/main`).
