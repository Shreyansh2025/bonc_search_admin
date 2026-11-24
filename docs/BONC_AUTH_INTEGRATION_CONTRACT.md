# BONC Authentication Architecture (`getUserDetail`)

## 1. Consolidated Authentication Decision

**BONC JWT verification through BONC's existing `.NET` `getUserDetail` endpoint is the ONLY supported Search Admin user authentication system.**

All legacy local username/password authentication, local SQLite session/rate-limit storage, session cookies, CSRF tokens, alternative `verify-admin` mode, CLI static admin tokens, and auth-disable toggles have been permanently removed.

## 2. End-to-End Authentication Flow

1. An Admin signs in on BONC and obtains a BONC-issued JWT `AuthToken`.
2. The Search Admin frontend holds the token strictly in JavaScript memory (via host-registered `registerBoncAuthProvider` or the standalone in-memory BONC AuthToken input — never in `localStorage`, `sessionStorage`, or cookies) and sends it on Admin API calls as:
   ```http
   Authorization: Bearer <AuthToken>
   ```
3. Search Admin's backend (`backend/app/services/bonc_auth_adapter.py`) decodes the JWT payload **only** to extract the untrusted `UserRowId` claim. It performs **no** local signature verification and requires **no** HS256 signing secret.
4. Search Admin calls BONC's `.NET` endpoint (`BONC_AUTH_VERIFY_URL`, e.g. `https://api.boncnetwork.com/api/userService/getUserDetail`):
   ```http
   GET /api/userService/getUserDetail?userRowId=<UserRowId>
   Authorization: Bearer <original AuthToken>
   ```
   with `follow_redirects=False` and configurable `BONC_AUTH_TIMEOUT` (default `5s`).
5. BONC `.NET` authoritatively validates the token signature, expiry, and session/logout revocation status.
6. Search Admin grants access **only** when ALL of the following hold:
   - HTTP status is `200` and JSON payload is a valid object with `Success` not `false`.
   - Returned `Data.UserRowId` (or bare DTO `UserRowId`) matches the token's `UserRowId` (case-insensitively); mismatch fails closed with `503`.
   - `IsActive` is not `false` (inactive accounts fail closed with `401`).
   - At least one role parsed from `UserRoles`, `RoleNames`, or `RoleName` (supporting `,`, `;`, `|` delimiters and lists, matched case-insensitively) is in `BONC_AUTH_ADMIN_ROLES` (default `Admin,SuperAdmin`). Authenticated non-admin users (e.g., `Basic`) receive `403 Forbidden`.
7. Verified BONC admin identities are mapped via `BoncRoleAuthorizationPolicy` into `AdminPrincipal`, propagating `UserRowId` into `UpdatedBy`, `ChangedBy`, `SearchLogs.AuthenticatedUserId`, and `ApiRequestLogs.AuthenticatedUserId`.

## 3. Error Handling & Fail-Closed Contract

| Condition | HTTP Response |
|---|---|
| Valid `Admin` / `SuperAdmin` token | `200` (authenticated) |
| Authenticated non-admin (`Basic`) token | `403 Forbidden` |
| Missing/malformed header, non-JWT, missing `UserRowId`, invalid/expired/revoked token, inactive user | `401 Unauthorized` (`WWW-Authenticate: Bearer`) |
| `BONC_AUTH_VERIFY_URL` unset | `503 Service Unavailable` (fail-closed) |
| Mismatched `UserRowId`, `Success: false`, malformed JSON, timeout, network error, unexpected HTTP status | `503 Service Unavailable` (fail-closed) |

## 4. Token Caching (`BONC_AUTH_CACHE_SECONDS`)

- `CachedBoncTokenVerifier` caches **only successful** verifications, keyed by `SHA-256(raw_token)` (raw tokens are never stored as cache keys).
- Rejections (`401`/`403`) and upstream failures (`503`) are **never** cached.
- **`BONC_AUTH_CACHE_SECONDS=0`** (recommended for local testing): verifies every request against BONC `.NET`, reflecting BONC logout/revocation immediately.
- **`BONC_AUTH_CACHE_SECONDS=60`** (typical staging/production trade-off): reduces round trips to `.NET` on multi-call dashboard pages, with up to 60 seconds of delay before a BONC sign-out takes effect in Search Admin.

## 5. Configuration & Security Boundaries

- Required backend variable: `BONC_AUTH_VERIFY_URL` (must be HTTPS for any non-localhost host).
- Configurable role & cache variables: `BONC_AUTH_ADMIN_ROLES` (default `Admin,SuperAdmin`), `BONC_AUTH_CACHE_SECONDS` (default `60`), `BONC_AUTH_TIMEOUT` (default `5`).
- `APP_ENV` (`local` | `staging` | `production`) controls Swagger visibility and default local CORS origins only — BONC JWT authentication is mandatory in every environment.
- **Separate Production Observability Boundary:** `PRODUCTION_SEARCH_*` settings (`PRODUCTION_OBSERVABILITY_ENABLED`, `PRODUCTION_SEARCH_BASE_URL`, `PRODUCTION_SEARCH_AUTH_MODE`, `PRODUCTION_SEARCH_AUTH_TOKEN`) are strictly for read-only backend-to-backend observability calls and are explicitly rejected if ever sent as a user Bearer token.
