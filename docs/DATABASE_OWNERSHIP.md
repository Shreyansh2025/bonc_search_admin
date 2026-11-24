# General Search Platform Database Ownership & Cutover Guide

## 1. Strict Schema Ownership

`backend/app/db/platform_db.py` independently owns access to the six General Search Platform tables in the `searchai` schema:

| Owned Table | Purpose | Read / Write Ownership |
|---|---|---|
| `searchai.SearchCategories` | Engine definitions, active/public flags, `ConfigVersion`, `IndexVersion` | Read/Write (`Search_Admin`) |
| `searchai.SearchCategoryHistory` | Immutable configuration history & `RolledBackFromVersion` provenance | Append/Read (`Search_Admin`) |
| `searchai.SearchDocuments` | Normalized searchable documents for SQL-synced and push categories | Read/Write (`Search_Admin`) |
| `searchai.SearchFeedback` | Historical relevance judgments & ranking snapshots | Read-Only (`Search_Admin` — inline write removed per Decision #2) |
| `searchai.SearchLogs` | Persistent public & admin search execution telemetry | Append/Read (`Search_Admin`) |
| `searchai.ApiRequestLogs` | Persistent API latency and HTTP 4xx/5xx telemetry | Append/Read (`Search_Admin`) |

### Reference SQL Server Schema

See [general_search_platform_schema.sql](../backend/sql/general_search_platform_schema.sql) for the complete idempotent SQL Server DDL covering all six `searchai.*` tables, check constraints, foreign keys, and analytics indexes. **Do not execute DDL against production without DBA approval.**

## 2. Strictly Excluded Tables (Never Accessed by `Search_Admin`)

- Legacy Product & Company Search tables: `dbo.Company`, `dbo.Products`, `dbo.ProductsAndServices`, `dbo.B2BCompanies`, `dbo.B2BProducts`.
- BrochureIQ tables: `dbo.Brochures`.
- Retired legacy Catalog Thresholds tables: `searchai.SearchAISettings`, `searchai.SearchAISettingsHistory` (retired per Decision #1; left intact in staging SQL Server and never dropped or queried by `Search_Admin`).

## 3. Isolated Admin Authentication Store

`backend/app/db/auth_db.py` stores `admin_sessions` and `admin_login_attempts` in a dedicated local SQLite file (`SEARCH_ADMIN_AUTH_DB_PATH`, default `./data/admin_auth.db`). It is completely separate from the SQL Server platform database and uses the dedicated cookie name `bonc_search_admin_platform_session` so no loopback cookie collisions can occur with legacy `py-backend`.

## 4. Database Cutover Rules (Preventing Dual Writers)

Because the legacy split Search AI microservice (`py-backend/app/search_main.py`, port `8002`) previously wrote to staging `searchai.*` tables, operators **MUST NOT** run both `py-backend` (port `8002`) and `Search_Admin` (port `8004`) simultaneously against the same `searchai.*` SQL Server database:

1. **Before cutover**: Test `Search_Admin` exclusively with isolated SQLite tests or a dedicated local/dev SQL Server database.
2. **During cutover to staging**:
   - Stop and disable the legacy port-`8002` `search_main.py` service so it can no longer mutate `searchai.*` rows or hold stale in-memory FAISS caches.
   - Verify all 6 `searchai.*` tables exist and match `general_search_platform_schema.sql` (including `SearchCategoryHistory.RolledBackFromVersion`).
   - Configure `SEARCH_PLATFORM_SQL_ODBC_CONNECT_STAGING` and any `SEARCH_SOURCE_*` read-only profiles in `/etc/bonc-search-admin/backend.env`.
   - Start `bonc-search-admin-backend.service` (`WEB_CONCURRENCY=1`) and verify `/health/live`, `/health/ready`, and `/api/admin/platform/system-health`.
3. **Production**: Keep `PRODUCTION_OBSERVABILITY_ENABLED=false` until Stage 3 VPS deployment verification, network path review, and upstream authentication sign-off are complete.
