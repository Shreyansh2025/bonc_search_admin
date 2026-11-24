# BONC Authentication Integration — Discovery Report, Contract & Preparation

## 1. Discovery Summary

Inspection of the workspace (`BONC_Search_AI_Platform/`) and sibling project directories confirmed that **the main BONC application's backend authentication source, frontend authentication source, and Swagger/OpenAPI specification are not available in this workspace**.

- Existing code in `BONC_Search_AI_Platform/` covers only `Search_Admin/`, legacy `py-backend/` (BrochureIQ + legacy Search AI), `react-frontend/`, `search-ai-admin/`, and `lib/` (BrochureIQ API spec/client).
- Sibling directory `bonc-short-content/` is a separate service whose own security readiness doc likewise marks the BONC production JWT contract as unresolved.
- Indirect SQL Server schema evidence from `docs/people_search_configuration_audit.md` and `py-backend/sql/staging/02_create_vw_search_people_v2.sql` confirms the BONC database contains `dbo.BoncUser.UserRowId` (36-char UUID) and `dbo.UserRoles` / `dbo.Roles` (`Basic`, `Admin`, `SuperAdmin`, plus other staff roles). Database tables alone do **not** define BONC's JWT signing mechanism, claims, endpoints, or frontend token handoff.

Per Phase 3 safety rules, **no BONC signing keys, algorithms, issuers, audiences, endpoints, claim names, role mappings, or browser globals were invented**. Only safe, contract-independent, fail-closed preparation was implemented inside `Search_Admin/`.

## 2. BONC Authentication Contract Status

| Item | Status | Evidence / Required Confirmation |
|---|---|---|
| Login endpoint | **UNCONFIRMED** | Main BONC backend source / Swagger not in workspace |
| Login request | **UNCONFIRMED** | Exact fields and casing not in workspace |
| Login response | **UNCONFIRMED** | Expected fields (`AuthToken`, `RefreshToken`, `TokenExpireDate`, `RefreshTokenExpireDate`, user/roles) must be verified against BONC API |
| Access token | **UNCONFIRMED** | Expected `Authorization: Bearer <AuthToken>`; exact JWT vs opaque format unverified |
| Refresh token | **UNCONFIRMED** | Owned by BONC; exact refresh endpoint & rotation rules not in workspace |
| Expiration | **UNCONFIRMED** | Exact `exp` / `nbf` / `TokenExpireDate` semantics not in workspace |
| Signing algorithm | **UNCONFIRMED** | Asymmetric (`RS256`/`ES256`) vs symmetric (`HS256`) not in workspace |
| Verification mechanism | **UNCONFIRMED** | Public key / JWKS / shared key / introspection / approved library not in workspace |
| Issuer (`iss`) | **UNCONFIRMED** | Not in workspace |
| Audience (`aud`) | **UNCONFIRMED** | Not in workspace |
| Identity | **PARTIAL (DB only)** | `dbo.BoncUser.UserRowId` (UUID) observed in DB audit; exact JWT claim (`sub` / `nameid` / `UserRowId`) unconfirmed |
| Roles | **PARTIAL (DB only)** | `dbo.Roles.RoleName` (`Basic`, `Admin`, `SuperAdmin`, etc.) observed in DB audit; exact JWT claim or userinfo API unconfirmed |
| Permissions | **UNCONFIRMED** | Exact Admin role IDs/names/scopes authorized for Search_Admin unconfirmed |
| Refresh | **UNCONFIRMED** | Owned by BONC host; exact host refresh callback contract unconfirmed |
| Logout | **UNCONFIRMED** | Owned by BONC; exact server revocation & host logout hook unconfirmed |
| Frontend handoff | **UNCONFIRMED** | Main BONC frontend source not in workspace; hosting model (embedded shell vs strict-origin iframe) unconfirmed |

## 3. Implemented Fail-Closed Preparation in `Search_Admin/`

1. **Auth Mode Selection (`app/config.py`)**:
   - `APP_ENV != "local"` (`staging`, `production`) defaults to `SEARCH_ADMIN_AUTH_MODE=bonc_jwt` and strictly disallows `local_session` (fails closed with HTTP `503`).
   - `APP_ENV == "local"` supports explicit `local_session` (transition dev mode) or `bonc_jwt` (fail-closed, zero fallback to local session).
   - Interactive OpenAPI/Swagger (`/docs`, `/redoc`, `/openapi.json`) is enabled in `local` and disabled by default outside `local`.
2. **BONC Provider & Authorization Layer (`app/services/bonc_auth.py`, `app/services/bonc_auth_adapter.py`, `app/services/admin_auth.py`)**:
   - `BoncJwtAuthProvider` implements `AdminAuthProvider` with strict Bearer token extraction (`401`), defense-in-depth verified claims checks (`alg` allowlist, `alg != none`, `iss`, `aud`, `exp`, `nbf`, optional `kid` & `typ`, required `user_id`), and separate `BoncRoleAuthorizationPolicy` capability mapping (`403` for ordinary BONC users or insufficient permissions).
   - `BoncAuthPackageVerifierAdapter` (`backend/app/services/bonc_auth_adapter.py`) integrates the external reusable `bonc-auth` Python package (`bonc-auth[fastapi]` pinned by commit SHA `1a314e3e6db9959bc9a1f47db7a15d8bded155e7` in `backend/requirements.txt`) behind `BoncTokenVerifier` without duplicating package code or bypassing `BoncJwtAuthProvider` via `FastAPIAdminGuard`.
   - **Architectural preference & unactivated status:** Local cryptographic JWT verification (JWKS, public key, or verified shared secret) behind `BoncTokenVerifier` remains the preferred mechanism if the `.NET` team supplies signing keys. `BoncAuthPackageVerifierAdapter` is prepared as an **unactivated** candidate adapter for HTTP verification; `build_default_auth_provider()` intentionally keeps `BoncJwtAuthProvider` unconfigured (`verifier=None`, `claims_config=None`, `role_policy=None`) and failing closed with HTTP `503` until BONC's real verification mechanism and trusted claims contract are confirmed.
   - **Contract gap enforced fail-closed (HTTP `503`):** `bonc-auth` v0.2.0's documented example response (`{"adminId", "role", "sessionId"}`) omits `issuer` (`iss`), `audience` (`aud`), and `expires_at_utc` (`exp`), which `validate_verified_bonc_identity()` requires. `BoncAuthPackageVerifierAdapter` never fabricates missing claims and raises `BoncAuthUnavailableError` (HTTP `503`, never `401`) if an HTTP `200` verification response omits required trusted claims or returns malformed/conflicting field types. Additionally, an admin-only `/api/auth/verify-admin` endpoint returning `403` for ordinary BONC users cannot attribute non-admin users on public `/api/platform/search` requests (`try_authenticate_public_request` safely falls back to anonymous/session logging).
   - Local login (`POST /api/admin/auth/login`) and local logout (`POST /api/admin/auth/logout`) return HTTP `404` when BONC mode is active.
   - `AdminPrincipal` propagates the verified stable BONC `user_id` into `UpdatedBy`, `ChangedBy`, `SearchLogs.AuthenticatedUserId`, and `ApiRequestLogs.AuthenticatedUserId` (and preserves optional verified `session_id`).
3. **CLI / Service Token Isolation**:
   - `SEARCH_ADMIN_SERVICE_TOKEN` is disabled in BONC mode by default (`SEARCH_ADMIN_ALLOW_CLI_SERVICE_TOKEN=false`).
   - Even when explicitly opted in for offline evaluation scripts, it is restricted strictly to `admin:search:execute` and `admin:categories:read`, marked `is_service_account=True`, and rejected on `/api/admin/auth/session` and all write/log/analytics routes.
4. **Frontend In-Memory Host Adapter (`frontend/src/lib/bonc-auth.ts`, `search-api.ts`, `App.tsx`)**:
   - Exposes `registerBoncAuthProvider(provider)` for approved host-managed in-memory token access, one-shot refresh delegation on `401`, and host logout delegation/subscription.
   - Never writes tokens to `localStorage`, `sessionStorage`, cookies, URLs, logs, or Vite env vars.
   - Production Vite builds default to `bonc` mode and never render an independent Search_Admin login form.

## 4. Safe Local-Auth Retirement Plan (Future, Non-Destructive)

- **No database tables or SQLite files are dropped or modified in Phase 3.**
- Historical SQL Server tables `searchai.AdminSessions` and `searchai.AdminLoginAttempts` (from legacy `py-backend` Migration 007) and `searchai.SearchCategoryHistory` (which also stores rollback provenance `RolledBackFromVersion`) remain untouched.
- Local SQLite file `backend/data/admin_auth.db` is untouched and is not opened during lifespan startup when `SEARCH_ADMIN_AUTH_MODE=bonc_jwt`.
- Once BONC end-to-end authentication is verified in staging and production, `LocalSessionAuthProvider`, `app/db/auth_db.py`, and local login/logout routes can be retired in a dedicated cleanup PR, followed by a DBA-approved archival/drop of legacy `searchai.AdminSessions` and `searchai.AdminLoginAttempts` only (preserving `searchai.SearchCategoryHistory`).
