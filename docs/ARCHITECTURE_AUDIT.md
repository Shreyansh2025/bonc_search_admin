# Search_Admin — Independent General Search Platform Architecture

## 1. Architectural Ownership

`bonc_search_admin` is a completely independent application that directly owns:

1. **General Search Platform Engine** (`backend/app/services/`):
   - Hybrid BM25F + FAISS (`IndexFlatIP`) semantic retrieval with `sentence-transformers/all-MiniLM-L6-v2` (384-d).
   - Weighted Reciprocal Rank Fusion (RRF) (`ranking_v2.py`).
   - Deterministic query understanding, discrete field value extraction, hard vs ranking-hint constraints, and synonym expansion (`query_understanding.py`).
   - Technical token preservation (`C`, `C++`, `C#`), HTML stripping, inverted index, and spellcheck (`platform_common.py`).
   - Per-category versioned index caching and invalidation (`platform_search.py`).
   - SQL Server metadata discovery, sensitive-column filtering, mapping suggestions, non-executing join-view SQL preview, ID uniqueness preflight validation, and synchronization (`source_sync.py`).
   - Dependency-free offline IR evaluation metrics (`search_evaluation.py`).
2. **Independent Platform Database Layer** (`app/db/platform_db.py`, `app/repositories/`):
   - Dedicated SQLAlchemy connection pool (`SEARCH_PLATFORM_SQL_ODBC_CONNECT_<ENV>`) strictly owning the six `searchai.*` tables (`SearchCategories`, `SearchCategoryHistory`, `SearchDocuments`, `SearchFeedback`, `SearchLogs`, `ApiRequestLogs`).
   - Zero imports from `py-backend/app/shared/db.py` and zero access to legacy `dbo.*` Product/Company/BrochureIQ tables.
3. **Centralized BONC Authentication & Authorization** (`app/services/admin_auth.py`, `app/services/bonc_auth.py`, `app/services/bonc_auth_adapter.py`):
   - Single mandatory BONC JWT authentication flow via BONC's `.NET` `GET /api/userService/getUserDetail` endpoint (`BONC_AUTH_VERIFY_URL`).
   - Stateless `Authorization: Bearer <AuthToken>` validation with untrusted `UserRowId` extraction, authoritative `.NET` signature/expiry/revocation validation, matching `UserRowId`, `IsActive`, and `BONC_AUTH_ADMIN_ROLES` enforcement (`Admin`, `SuperAdmin`), plus SHA-256-keyed success-only caching (`BONC_AUTH_CACHE_SECONDS`).
   - Verified BONC `UserRowId` (`principal.actor`) persisted directly into `UpdatedBy` / `ChangedBy` / `SearchLogs` / `ApiRequestLogs`.
   - Zero local username/password accounts, cookies, CSRF tokens, local auth SQLite DB, or auth-disable flags.
4. **Optional Read-Only Production Observability Client** (`app/clients/production_search_client.py`):
   - Disabled by default (`PRODUCTION_OBSERVABILITY_ENABLED=false`).
   - Strictly GET-only for original production (`origin/main`) `/api/healthz` and `/api/debug/index-status` with its own independent `PRODUCTION_SEARCH_*` credentials.
   - Unconditionally strips BrochureIQ `localProducts` so only `b2bCompanies` and `b2bProducts` can ever be displayed when enabled in Stage 3.
5. **Independent React Admin Console** (`frontend/`):
   - BONC-only in-memory Bearer token auth gate, System Health & Analytics, Search Logs & Per-User Activity, Data Sources & Configuration, Generic Search Engine Testing, and Read-Only Feedback Log.

## 2. Eliminated Legacy Dependencies & Retired Features

- **Zero runtime dependency on legacy `py-backend/app/search_main.py` (port `8002`)** — removed `SearchAIClient` proxy layer completely.
- **Retired Legacy Local Username/Password Auth**: Removed local password login, SQLite auth store (`app/db/auth_db.py`), session cookies, CSRF tokens, login rate limiting, `/api/admin/auth/login`, `/api/admin/auth/logout`, and alternative `verify-admin` mode.
- **Retired Legacy Catalog Thresholds (Decision #1)**: Removed `/api/admin/search-settings`, `/api/admin/search-settings/history`, `schemas/settings.py`, `routes/settings.py`, and the `Catalog Thresholds` UI tab.
- **Excluded Inline Feedback Writing & Legacy B2B Playground (Decision #2)**: Removed `POST /api/admin/platform/categories/{id}/feedback` and inline relevance-labeling controls while preserving `POST /api/admin/platform/search`, the Generic Search Engine Testing UI, and read-only feedback/relevance endpoints.
- **Zero BrochureIQ / Monolith Contamination**: Zero imports or packages for OCR/PDF/images (`PyMuPDF`, `pytesseract`, `pillow`, `rembg`, `onnxruntime`, `openpyxl`, `python-multipart`).
