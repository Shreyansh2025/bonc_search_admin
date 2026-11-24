# BONC Search Admin Frontend

Independent React 19 + TypeScript + Vite console (`frontend/`) serving the General Search Platform Admin UI on port `5175`.

## Sections & Capabilities

1. **System Health & Analytics** (`src/components/system-health-panel.tsx`):
   - Live status for the General Search Platform API, SQL Server connectivity (`SELECT 1`), embedding model (`all-MiniLM-L6-v2`), category indexes & worker cache, and 24-hour HTTP 5xx server failures.
   - Optional read-only **Production Search Observability** panel (shows `Disabled` cleanly until Stage 3; displays only `b2bCompanies` and `b2bProducts` when enabled — zero BrochureIQ `localProducts`).
   - Backend-calculated Search KPIs, API 4xx vs 5xx breakdown, and feedback-derived relevance metrics.
2. **Search Logs & User Activity** (`src/components/search-logs-panel.tsx`):
   - Persistent search history filtering (date range, query, category, authenticated user, identity type, outcome, HTTP status/class, surface) with pagination and per-user breakdown.
3. **Data Sources & Configuration** (`src/components/platform-panel.tsx`):
   - **Engines & Data Sources**: Create/edit configurable search engines, SQL profile discovery, mapping suggestions, non-executing join-view SQL preview, ID uniqueness preflight validation, SQL sync, field weights/roles/typed filters/synonyms, version history, and atomic rollback.
   - **Engine Testing** (`Generic Search Engine Testing`): Select any configured search engine, push JSON documents (for push sources), run generic queries with dynamic typed result filters, inspect tested engine metadata (`config_version`, `index_version`), Query Understanding & Execution Plan, and per-result BM25F + FAISS + RRF signals. Intentionally excludes inline relevance feedback writing and the legacy B2B Catalog Playground.
   - **Feedback Log**: Read-only audit trail of historical `searchai.SearchFeedback` judgments across configured engines.

## Security & Boundary Guarantees

- Browser communicates exclusively with Search Admin Backend (`/admin-api` proxied to `127.0.0.1:8004`).
- Uses BONC Bearer tokens (`Authorization: Bearer <AuthToken>`) held strictly in JavaScript memory with `credentials: "omit"` — never writes tokens to `localStorage`, `sessionStorage`, or cookies, and offers no local username/password login form.
- Zero backend tokens, SQL drivers, BrochureIQ imports, or legacy Catalog Thresholds UI.

## Scripts

```powershell
cd frontend
npm ci
npm run dev        # Vite dev server on http://127.0.0.1:5175
npm run typecheck  # tsc --noEmit
npm run test       # Node test runner contract & separation tests
npm run build      # Production Vite bundle in dist/
```
