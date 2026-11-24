"""Centralized Search Admin authentication, pluggable AdminAuthProvider, sessions, CSRF & rate limiting.

Architecture:
- Search_Admin is the single authentication entry point for Admin users and
  in-process General Search Platform management operations.
- All Admin routes depend on ``AdminAuthProvider`` via ``require_admin_principal``
  / ``require_admin_actor`` so BONC JWT authentication can be plugged in later
  by replacing the active provider without rewriting any Admin route.
- For this phase, ``LocalSessionAuthProvider`` preserves the hardened local
  username/password + salted scrypt/PBKDF2 + HttpOnly cookie + in-memory
  X-CSRF-Token + IP-hashed rate limiting implementation backed by Search Admin's
  isolated SQLite store (``app.db.auth_db``).
- Uses a dedicated cookie name (``bonc_search_admin_platform_session``) so
  running legacy ``py-backend`` on loopback never causes cookie collisions.
- Supports an optional, separately configured CLI automation token
  (``SEARCH_ADMIN_SERVICE_TOKEN``) strictly for headless evaluation/smoke tools.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import ipaddress
import math
import os
import secrets
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal

from fastapi import Depends, Header, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import and_, delete, insert, select, update

from app.config import (
    get_admin_auth_mode,
    get_app_env,
    is_cli_service_token_enabled_in_bonc_mode,
)
from app.db.auth_db import (
    admin_login_attempts_table,
    admin_sessions_table,
    get_auth_engine,
)
from app.logger import logger
from app.services.bonc_auth import (
    ADMIN_PERMISSION_ANALYTICS_READ,
    ADMIN_PERMISSION_CATEGORIES_READ,
    ADMIN_PERMISSION_CATEGORIES_WRITE,
    ADMIN_PERMISSION_HEALTH_READ,
    ADMIN_PERMISSION_INGESTION_WRITE,
    ADMIN_PERMISSION_LOGS_READ,
    ADMIN_PERMISSION_PRODUCTION_READ,
    ADMIN_PERMISSION_SEARCH_EXECUTE,
    ADMIN_PERMISSION_SOURCES_READ,
    ALL_ADMIN_PERMISSIONS,
    CLI_AUTOMATION_ALLOWED_PERMISSIONS,
    AdminAuthProvider,
    AdminPrincipal,
    BoncAuthorizationDeniedError,
    BoncAuthNotConfiguredError,
    BoncAuthUnavailableError,
    BoncClaimsValidationConfig,
    BoncJwtAuthProvider,
    BoncRoleAuthorizationPolicy,
    BoncTokenExtractionError,
    BoncTokenInvalidError,
    BoncTokenVerifier,
    MisconfiguredAuthModeProvider,
    VerifiedBoncIdentity,
    attach_request_principal,
)
from app.services.bonc_auth_adapter import BoncAuthPackageVerifierAdapter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Dedicated cookie name distinct from legacy py-backend ("bonc_search_admin_session")
# to eliminate loopback port-sharing cookie collisions during transition.
SESSION_COOKIE_NAME = (
    os.getenv("SEARCH_ADMIN_SESSION_COOKIE_NAME", "bonc_search_admin_platform_session").strip()
    or "bonc_search_admin_platform_session"
)
CSRF_HEADER_NAME = "X-CSRF-Token"

DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60  # 8 hours
MIN_SESSION_TTL_SECONDS = 300  # 5 minutes
MAX_SESSION_TTL_SECONDS = 24 * 60 * 60  # 24 hours

DEFAULT_RATE_LIMIT_MAX_ATTEMPTS = 5
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 15 * 60  # 15 minutes
_LAST_SEEN_TOUCH_INTERVAL_SECONDS = 60

_SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Minimum safe KDF parameters for SEARCH_ADMIN_PASSWORD_HASH
_MIN_SCRYPT_N = 16384
_MAX_SCRYPT_N = 131072
_MIN_SCRYPT_R = 8
_MAX_SCRYPT_R = 16
_MIN_SCRYPT_P = 1
_MAX_SCRYPT_P = 4
_SCRYPT_MAXMEM = 128 * 1024 * 1024  # 128 MiB cap
_MIN_PBKDF2_ITERATIONS = 200_000
_MAX_PBKDF2_ITERATIONS = 5_000_000
_MIN_SALT_BYTES = 16
_MIN_DIGEST_BYTES = 32


# ---------------------------------------------------------------------------
# Data structures & errors
# ---------------------------------------------------------------------------


class AdminAuthNotConfiguredError(RuntimeError):
    """Raised when required backend admin credentials are missing or invalid."""


class AdminAuthStorageError(RuntimeError):
    """Raised when persistent session or rate-limit storage cannot be reached."""


@dataclass(frozen=True)
class ParsedPasswordHash:
    scheme: Literal["scrypt", "pbkdf2_sha256"]
    salt: bytes
    digest: bytes
    n: int | None = None
    r: int | None = None
    p: int | None = None
    iterations: int | None = None


@dataclass(frozen=True)
class AdminSession:
    session_id: str
    username: str
    csrf_token: str
    created_at_utc: datetime
    last_seen_at_utc: datetime
    expires_at_utc: datetime


# ---------------------------------------------------------------------------
# Time & environment configuration helpers
# ---------------------------------------------------------------------------


def utc_now_naive() -> datetime:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def format_utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    dt = value
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def session_ttl_seconds() -> int:
    return _int_env(
        "SEARCH_ADMIN_SESSION_TTL_SECONDS",
        DEFAULT_SESSION_TTL_SECONDS,
        minimum=MIN_SESSION_TTL_SECONDS,
        maximum=MAX_SESSION_TTL_SECONDS,
    )


def rate_limit_max_attempts() -> int:
    return _int_env(
        "SEARCH_ADMIN_LOGIN_RATE_LIMIT_MAX_ATTEMPTS",
        DEFAULT_RATE_LIMIT_MAX_ATTEMPTS,
        minimum=1,
        maximum=100,
    )


def rate_limit_window_seconds() -> int:
    return _int_env(
        "SEARCH_ADMIN_LOGIN_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        minimum=10,
        maximum=86400,
    )


def cookie_secure(request: Request | None = None) -> bool:
    app_env = os.getenv("APP_ENV", "local").strip().lower() or "local"
    if app_env == "production":
        return True

    override = os.getenv("SEARCH_ADMIN_COOKIE_SECURE", "").strip().lower()
    if override in {"1", "true", "yes"}:
        return True
    if override in {"0", "false", "no"}:
        return False

    if app_env != "local":
        return True

    if request is not None:
        scheme = (getattr(getattr(request, "url", None), "scheme", "") or "").lower()
        if scheme == "https":
            return True
    return False


def cookie_samesite() -> Literal["lax", "strict"]:
    raw = os.getenv("SEARCH_ADMIN_COOKIE_SAMESITE", "lax").strip().lower()
    if raw == "strict":
        return "strict"
    return "lax"


def set_session_cookie(
    response: Response,
    raw_token: str,
    *,
    max_age: int,
    request: Request | None = None,
) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=max(1, int(max_age)),
        path="/",
        httponly=True,
        secure=cookie_secure(request),
        samesite=cookie_samesite(),
    )


def clear_session_cookie(
    response: Response,
    *,
    request: Request | None = None,
) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=cookie_secure(request),
        samesite=cookie_samesite(),
    )


# ---------------------------------------------------------------------------
# Password hashing & constant-time verification
# ---------------------------------------------------------------------------


def hash_password(password: str, *, scheme: Literal["scrypt", "pbkdf2_sha256"] = "scrypt") -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    salt = secrets.token_bytes(16)
    if scheme == "scrypt":
        n, r, p = _MIN_SCRYPT_N, _MIN_SCRYPT_R, _MIN_SCRYPT_P
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=_SCRYPT_MAXMEM,
            dklen=32,
        )
        return f"scrypt${n}${r}${p}${salt.hex()}${derived.hex()}"
    if scheme == "pbkdf2_sha256":
        iterations = 600_000
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )
        return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"
    raise ValueError(f"Unsupported password hash scheme: {scheme}")


def parse_password_hash(encoded: str | None) -> ParsedPasswordHash | None:
    if not encoded or not isinstance(encoded, str):
        return None
    parts = encoded.strip().split("$")
    if len(parts) == 6 and parts[0] == "scrypt":
        try:
            n = int(parts[1])
            r = int(parts[2])
            p = int(parts[3])
            salt = bytes.fromhex(parts[4])
            digest = bytes.fromhex(parts[5])
        except ValueError:
            return None
        if n < _MIN_SCRYPT_N or n > _MAX_SCRYPT_N or (n & (n - 1)) != 0:
            return None
        if not (_MIN_SCRYPT_R <= r <= _MAX_SCRYPT_R):
            return None
        if not (_MIN_SCRYPT_P <= p <= _MAX_SCRYPT_P):
            return None
        if len(salt) < _MIN_SALT_BYTES or len(digest) < _MIN_DIGEST_BYTES:
            return None
        return ParsedPasswordHash(
            scheme="scrypt",
            salt=salt,
            digest=digest,
            n=n,
            r=r,
            p=p,
        )

    if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
        try:
            iterations = int(parts[1])
            salt = bytes.fromhex(parts[2])
            digest = bytes.fromhex(parts[3])
        except ValueError:
            return None
        if not (_MIN_PBKDF2_ITERATIONS <= iterations <= _MAX_PBKDF2_ITERATIONS):
            return None
        if len(salt) < _MIN_SALT_BYTES or len(digest) < _MIN_DIGEST_BYTES:
            return None
        return ParsedPasswordHash(
            scheme="pbkdf2_sha256",
            salt=salt,
            digest=digest,
            iterations=iterations,
        )

    return None


def verify_password(password: str, encoded_hash: str) -> bool:
    parsed = parse_password_hash(encoded_hash)
    if parsed is None or not isinstance(password, str):
        return False
    password_bytes = password.encode("utf-8")
    if parsed.scheme == "scrypt":
        derived = hashlib.scrypt(
            password_bytes,
            salt=parsed.salt,
            n=int(parsed.n),
            r=int(parsed.r),
            p=int(parsed.p),
            maxmem=_SCRYPT_MAXMEM,
            dklen=len(parsed.digest),
        )
    else:
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            parsed.salt,
            int(parsed.iterations),
            dklen=len(parsed.digest),
        )
    return hmac.compare_digest(derived, parsed.digest)


def is_admin_login_configured() -> bool:
    username = os.getenv("SEARCH_ADMIN_USERNAME", "").strip()
    password_hash = os.getenv("SEARCH_ADMIN_PASSWORD_HASH", "").strip()
    return bool(username) and parse_password_hash(password_hash) is not None


def is_admin_service_bearer_configured() -> bool:
    """Optional incoming CLI/automation Bearer token (never exposed to browsers)."""
    return bool(os.getenv("SEARCH_ADMIN_SERVICE_TOKEN", "").strip())


def verify_admin_credentials(username: str, password: str) -> str | None:
    expected_username = os.getenv("SEARCH_ADMIN_USERNAME", "").strip()
    encoded_hash = os.getenv("SEARCH_ADMIN_PASSWORD_HASH", "").strip()
    if not expected_username or parse_password_hash(encoded_hash) is None:
        raise AdminAuthNotConfiguredError("Admin login credentials are not configured")

    supplied_username = (username or "").strip()
    username_ok = hmac.compare_digest(
        supplied_username.encode("utf-8"),
        expected_username.encode("utf-8"),
    )
    password_ok = verify_password(password or "", encoded_hash)
    if bool(username_ok & password_ok):
        return expected_username
    return None


# ---------------------------------------------------------------------------
# Client IP & persistent login rate limiting
# ---------------------------------------------------------------------------


def extract_client_ip(request: Request | None) -> str:
    direct_host = ""
    if request is not None and request.client and request.client.host:
        direct_host = str(request.client.host).strip()

    trust_proxy = os.getenv("SEARCH_ADMIN_TRUST_PROXY_HEADERS", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if trust_proxy and direct_host and request is not None:
        try:
            is_loopback = ipaddress.ip_address(direct_host).is_loopback
        except ValueError:
            is_loopback = False
        if is_loopback:
            xff = (request.headers.get("x-forwarded-for") or "").strip()
            if xff:
                candidate = xff.split(",")[0].strip()
                if candidate:
                    return candidate[:64]
            x_real_ip = (request.headers.get("x-real-ip") or "").strip()
            if x_real_ip:
                return x_real_ip[:64]

    return (direct_host or "unknown")[:64]


def hash_client_key(client_ip: str, *, scope: str = "login_ip") -> str:
    material = f"search-admin-platform-auth-v2:{scope}:{client_ip.strip().lower()}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def check_login_rate_limit(
    client_ip: str,
    *,
    now_utc: datetime | None = None,
) -> tuple[bool, int]:
    now = now_utc or utc_now_naive()
    window = rate_limit_window_seconds()
    max_attempts = rate_limit_max_attempts()
    window_start = now - timedelta(seconds=window)
    client_key = hash_client_key(client_ip)
    t = admin_login_attempts_table

    try:
        with get_auth_engine().connect() as conn:
            rows = conn.execute(
                select(t.c.AttemptedAtUtc)
                .where(
                    and_(
                        t.c.ClientKeyHash == client_key,
                        t.c.Succeeded == False,  # noqa: E712
                        t.c.AttemptedAtUtc >= window_start,
                    )
                )
                .order_by(t.c.AttemptedAtUtc.asc())
            ).scalars().all()
    except Exception as exc:
        logger.error("Admin login rate-limit check failed (exception_type=%s)", type(exc).__name__)
        raise AdminAuthStorageError("Admin authentication storage is unavailable") from exc

    if len(rows) >= max_attempts:
        oldest_in_window = rows[-max_attempts]
        unlock_at = oldest_in_window + timedelta(seconds=window)
        retry_after = max(1, int(math.ceil((unlock_at - now).total_seconds())))
        return False, retry_after
    return True, 0


def record_login_attempt(
    client_ip: str,
    *,
    succeeded: bool,
    now_utc: datetime | None = None,
) -> None:
    now = now_utc or utc_now_naive()
    client_key = hash_client_key(client_ip)
    prune_before = now - timedelta(hours=24)
    t = admin_login_attempts_table

    try:
        with get_auth_engine().begin() as conn:
            conn.execute(delete(t).where(t.c.AttemptedAtUtc < prune_before))
            if succeeded:
                conn.execute(
                    delete(t).where(
                        and_(
                            t.c.ClientKeyHash == client_key,
                            t.c.Succeeded == False,  # noqa: E712
                        )
                    )
                )
            else:
                conn.execute(
                    insert(t).values(
                        ClientKeyHash=client_key,
                        AttemptedAtUtc=now,
                        Succeeded=False,
                    )
                )
    except Exception as exc:
        logger.error("Admin login attempt persistence failed (exception_type=%s)", type(exc).__name__)
        raise AdminAuthStorageError("Admin authentication storage is unavailable") from exc


# ---------------------------------------------------------------------------
# Persistent session management (Admin-local SQLite)
# ---------------------------------------------------------------------------


def hash_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _sanitize_user_agent(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = "".join(ch for ch in str(raw) if 32 <= ord(ch) < 127).strip()
    return cleaned[:256] or None


def create_session(
    username: str,
    *,
    client_ip: str | None = None,
    user_agent: str | None = None,
    ttl_seconds: int | None = None,
    now_utc: datetime | None = None,
) -> tuple[str, AdminSession]:
    now = now_utc or utc_now_naive()
    effective_ttl = (
        int(ttl_seconds)
        if ttl_seconds is not None and int(ttl_seconds) > 0
        else session_ttl_seconds()
    )
    expires_at = now + timedelta(seconds=effective_ttl)
    session_id = uuid.uuid4().hex
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(raw_token)
    csrf_token = secrets.token_urlsafe(32)
    ip_hash = hash_client_key(client_ip, scope="session_ip") if client_ip else None
    safe_ua = _sanitize_user_agent(user_agent)

    t = admin_sessions_table
    try:
        with get_auth_engine().begin() as conn:
            conn.execute(
                insert(t).values(
                    SessionId=session_id,
                    SessionTokenHash=token_hash,
                    CsrfToken=csrf_token,
                    AdminUsername=username[:128],
                    CreatedAtUtc=now,
                    LastSeenAtUtc=now,
                    ExpiresAtUtc=expires_at,
                    RevokedAtUtc=None,
                    RevokedReason=None,
                    ClientIpHash=ip_hash,
                    UserAgent=safe_ua,
                )
            )
    except Exception as exc:
        logger.error("Admin session creation failed (exception_type=%s)", type(exc).__name__)
        raise AdminAuthStorageError("Admin session storage is unavailable") from exc

    return raw_token, AdminSession(
        session_id=session_id,
        username=username[:128],
        csrf_token=csrf_token,
        created_at_utc=now,
        last_seen_at_utc=now,
        expires_at_utc=expires_at,
    )


def validate_session_token(
    raw_token: str | None,
    *,
    now_utc: datetime | None = None,
    touch: bool = True,
) -> AdminSession | None:
    if not raw_token or not isinstance(raw_token, str):
        return None
    candidate = raw_token.strip()
    if len(candidate) < 16 or len(candidate) > 256:
        return None

    now = now_utc or utc_now_naive()
    token_hash = hash_session_token(candidate)
    t = admin_sessions_table

    try:
        with get_auth_engine().connect() as conn:
            row = conn.execute(
                select(
                    t.c.SessionId,
                    t.c.CsrfToken,
                    t.c.AdminUsername,
                    t.c.CreatedAtUtc,
                    t.c.LastSeenAtUtc,
                    t.c.ExpiresAtUtc,
                    t.c.RevokedAtUtc,
                ).where(t.c.SessionTokenHash == token_hash)
            ).mappings().first()
    except Exception as exc:
        logger.error("Admin session lookup failed (exception_type=%s)", type(exc).__name__)
        raise AdminAuthStorageError("Admin session storage is unavailable") from exc

    if row is None or row["RevokedAtUtc"] is not None:
        return None

    expires_at = row["ExpiresAtUtc"]
    if isinstance(expires_at, datetime) and expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    if expires_at <= now:
        return None

    last_seen = row["LastSeenAtUtc"]
    if isinstance(last_seen, datetime) and last_seen.tzinfo is not None:
        last_seen = last_seen.astimezone(timezone.utc).replace(tzinfo=None)

    if touch and (now - last_seen) >= timedelta(seconds=_LAST_SEEN_TOUCH_INTERVAL_SECONDS):
        try:
            with get_auth_engine().begin() as conn:
                conn.execute(
                    update(t)
                    .where(and_(t.c.SessionId == row["SessionId"], t.c.RevokedAtUtc.is_(None)))
                    .values(LastSeenAtUtc=now)
                )
            last_seen = now
        except Exception as exc:
            logger.warning(
                "Admin session LastSeenAtUtc update skipped (exception_type=%s)",
                type(exc).__name__,
            )

    created_at = row["CreatedAtUtc"]
    if isinstance(created_at, datetime) and created_at.tzinfo is not None:
        created_at = created_at.astimezone(timezone.utc).replace(tzinfo=None)

    return AdminSession(
        session_id=str(row["SessionId"]),
        username=str(row["AdminUsername"]),
        csrf_token=str(row["CsrfToken"]),
        created_at_utc=created_at,
        last_seen_at_utc=last_seen,
        expires_at_utc=expires_at,
    )


def revoke_session_by_id(
    session_id: str,
    *,
    reason: str = "logout",
    now_utc: datetime | None = None,
) -> bool:
    now = now_utc or utc_now_naive()
    t = admin_sessions_table
    try:
        with get_auth_engine().begin() as conn:
            result = conn.execute(
                update(t)
                .where(and_(t.c.SessionId == session_id, t.c.RevokedAtUtc.is_(None)))
                .values(RevokedAtUtc=now, RevokedReason=(reason or "revoked")[:128])
            )
            return int(result.rowcount or 0) > 0
    except Exception as exc:
        logger.error("Admin session revocation failed (exception_type=%s)", type(exc).__name__)
        raise AdminAuthStorageError("Admin session storage is unavailable") from exc


def revoke_session_by_token(
    raw_token: str | None,
    *,
    reason: str = "logout",
    now_utc: datetime | None = None,
) -> bool:
    if not raw_token or not isinstance(raw_token, str) or not raw_token.strip():
        return False
    now = now_utc or utc_now_naive()
    token_hash = hash_session_token(raw_token.strip())
    t = admin_sessions_table
    try:
        with get_auth_engine().begin() as conn:
            result = conn.execute(
                update(t)
                .where(and_(t.c.SessionTokenHash == token_hash, t.c.RevokedAtUtc.is_(None)))
                .values(RevokedAtUtc=now, RevokedReason=(reason or "revoked")[:128])
            )
            return int(result.rowcount or 0) > 0
    except Exception as exc:
        logger.error("Admin session token revocation failed (exception_type=%s)", type(exc).__name__)
        raise AdminAuthStorageError("Admin session storage is unavailable") from exc


# ---------------------------------------------------------------------------
# Pluggable AdminAuthProvider Abstraction & OpenAPI Bearer Security Scheme
# ---------------------------------------------------------------------------

# OpenAPI security scheme declaration (Authorization: Bearer <AuthToken>).
# auto_error=False ensures backend providers inspect the raw Authorization header
# directly so malformed/non-Bearer headers are rejected with HTTP 401 and local
# development cookie sessions continue functioning when explicitly enabled.
bearer_security_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BoncBearerAuth",
    bearerFormat="JWT",
    description=(
        "BONC-issued Bearer access token (`Authorization: Bearer <AuthToken>`). "
        "OpenAPI scheme convention subject to confirmation against BONC's Swagger definition."
    ),
)

_attach_request_principal = attach_request_principal


class LocalSessionAuthProvider(AdminAuthProvider):
    """Local-development-only HttpOnly session + CSRF provider with optional CLI service Bearer auth.

    MUST NEVER be selected in staging or production and MUST NEVER act as an
    automatic fallback when BONC authentication fails or is unconfigured.
    """

    @property
    def auth_mode(self) -> str:
        return "local_session"

    def supports_local_login(self) -> bool:
        return get_app_env() == "local"

    def is_configured(self) -> bool:
        return is_admin_login_configured() or is_admin_service_bearer_configured()

    def authorize_request(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
        require_csrf: bool = True,
    ) -> AdminPrincipal:
        if get_app_env() != "local":
            raise HTTPException(
                status_code=503,
                detail="Local Search Admin session authentication is prohibited outside local development",
                headers={"X-Auth-Mode": "bonc_jwt"},
            )

        bearer_configured = is_admin_service_bearer_configured()
        login_configured = is_admin_login_configured()
        if not bearer_configured and not login_configured:
            raise HTTPException(
                status_code=503,
                detail="Search Admin authentication is not configured",
                headers={"X-Auth-Mode": self.auth_mode},
            )

        auth_header = authorization
        if auth_header is None and request is not None:
            auth_header = request.headers.get("authorization")

        if isinstance(auth_header, str) and auth_header.strip():
            parts = auth_header.strip().split(None, 1)
            if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required",
                    headers={"WWW-Authenticate": "Bearer", "X-Auth-Mode": self.auth_mode},
                )
            if not bearer_configured:
                raise HTTPException(
                    status_code=403,
                    detail="Invalid admin token",
                    headers={"X-Auth-Mode": self.auth_mode},
                )

            expected_token = os.getenv("SEARCH_ADMIN_SERVICE_TOKEN", "").strip()
            supplied_token = parts[1].strip()
            if not hmac.compare_digest(
                supplied_token.encode("utf-8"),
                expected_token.encode("utf-8"),
            ):
                raise HTTPException(
                    status_code=403,
                    detail="Invalid admin token",
                    headers={"X-Auth-Mode": self.auth_mode},
                )

            actor = (
                os.getenv("SEARCH_ADMIN_SERVICE_ACTOR", "admin:service").strip()
                or "admin:service"
            )[:256]
            principal = AdminPrincipal(
                actor=actor,
                username=actor,
                auth_method="bearer",
                roles=("admin", "automation"),
                permissions=tuple(sorted(ALL_ADMIN_PERMISSIONS)),
                is_service_account=True,
            )
            _attach_request_principal(request, principal)
            return principal

        if request is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"X-Auth-Mode": self.auth_mode},
            )

        raw_cookie = (request.cookies.get(SESSION_COOKIE_NAME) or "").strip()
        if not raw_cookie or not login_configured:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"X-Auth-Mode": self.auth_mode},
            )

        try:
            session = validate_session_token(raw_cookie)
        except AdminAuthStorageError as exc:
            raise HTTPException(
                status_code=503,
                detail="Admin authentication service is unavailable",
                headers={"X-Auth-Mode": self.auth_mode},
            ) from exc

        if session is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"X-Auth-Mode": self.auth_mode},
            )

        method = (getattr(request, "method", "GET") or "GET").upper()
        if require_csrf and method not in _SAFE_HTTP_METHODS:
            supplied_csrf = (request.headers.get(CSRF_HEADER_NAME) or "").strip()
            if not supplied_csrf or not hmac.compare_digest(
                supplied_csrf.encode("utf-8"),
                session.csrf_token.encode("utf-8"),
            ):
                raise HTTPException(
                    status_code=403,
                    detail="CSRF validation failed",
                    headers={"X-Auth-Mode": self.auth_mode},
                )

        principal = AdminPrincipal(
            actor=session.username,
            username=session.username,
            auth_method="session",
            roles=("admin",),
            permissions=tuple(sorted(ALL_ADMIN_PERMISSIONS)),
            session_id=session.session_id,
            expires_at_utc=session.expires_at_utc,
            csrf_token=session.csrf_token,
            is_service_account=False,
        )
        _attach_request_principal(request, principal)
        return principal

    def try_authenticate_public_request(
        self,
        request: Request | None = None,
        *,
        authorization: str | None = None,
    ) -> str | None:
        if get_app_env() != "local":
            return None
        expected = os.getenv("SEARCH_ADMIN_SERVICE_TOKEN", "").strip()
        auth_header = authorization
        if auth_header is None and request is not None:
            auth_header = request.headers.get("authorization")
        if not expected or not isinstance(auth_header, str) or not auth_header.strip():
            return None
        parts = auth_header.strip().split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            return None
        if not hmac.compare_digest(parts[1].strip().encode("utf-8"), expected.encode("utf-8")):
            return None
        return (
            os.getenv("SEARCH_ADMIN_SERVICE_ACTOR", "admin:service").strip() or "admin:service"
        )[:256]


_custom_provider: AdminAuthProvider | None = None
_default_local_provider = LocalSessionAuthProvider()


def build_default_auth_provider() -> AdminAuthProvider:
    """Resolve the active default provider strictly from ``APP_ENV`` and ``SEARCH_ADMIN_AUTH_MODE``.

    - Non-local environments (``staging``, ``production``) always default to
      fail-closed ``BoncJwtAuthProvider`` and refuse ``local_session``.
    - Local development supports explicit ``local_session`` (transition default)
      or ``bonc_jwt`` (fail-closed, zero local fallback).
    """
    mode = get_admin_auth_mode()
    if mode == "local_session":
        return _default_local_provider
    if mode == "bonc_jwt":
        return BoncJwtAuthProvider(
            verifier=None,
            claims_config=None,
            role_policy=None,
            allow_cli_service_token=is_cli_service_token_enabled_in_bonc_mode(),
        )
    return MisconfiguredAuthModeProvider(
        "Disallowed or invalid SEARCH_ADMIN_AUTH_MODE configuration; failing closed."
    )


def get_auth_provider() -> AdminAuthProvider:
    if _custom_provider is not None:
        return _custom_provider
    return build_default_auth_provider()


def set_auth_provider(provider: AdminAuthProvider) -> None:
    """Inject an explicit authentication provider (verified BONC provider or test fixture)."""
    global _custom_provider
    _custom_provider = provider


def reset_auth_provider() -> None:
    """Clear any injected provider and return to environment-driven provider selection."""
    global _custom_provider
    _custom_provider = None


def authorize_admin_request(
    request: Request | None = None,
    *,
    authorization: str | None = None,
    require_csrf: bool = True,
    required_permission: str | None = None,
    allow_service_token: bool = True,
) -> AdminPrincipal:
    return get_auth_provider().authorize_permission(
        request,
        authorization=authorization,
        require_csrf=require_csrf,
        required_permission=required_permission,
        allow_service_token=allow_service_token,
    )


def try_resolve_public_authenticated_user(
    request: Request | None = None,
    *,
    authorization: str | None = None,
) -> str | None:
    """Optionally resolve a verified user identifier on public routes (never trusts spoofed headers)."""
    return get_auth_provider().try_authenticate_public_request(
        request,
        authorization=authorization,
    )


def require_admin_principal(
    request: Request,
    _bearer: HTTPAuthorizationCredentials | None = Depends(bearer_security_scheme),
) -> AdminPrincipal:
    """Central FastAPI dependency enforcing Admin auth (+ CSRF for local cookies) on Admin routes."""
    return authorize_admin_request(
        request,
        authorization=request.headers.get("authorization"),
        require_csrf=True,
    )


def require_admin_permission(permission: str) -> Callable[..., AdminPrincipal]:
    """Dependency factory enforcing both authentication and an explicit Search_Admin capability."""

    def _dependency(
        request: Request,
        _bearer: HTTPAuthorizationCredentials | None = Depends(bearer_security_scheme),
    ) -> AdminPrincipal:
        return authorize_admin_request(
            request,
            authorization=request.headers.get("authorization"),
            require_csrf=True,
            required_permission=permission,
        )

    return _dependency


def require_admin_actor(
    request: Request | None = None,
    *,
    authorization: str | None = None,
    require_csrf: bool = True,
    required_permission: str | None = None,
) -> str:
    return authorize_admin_request(
        request,
        authorization=authorization,
        require_csrf=require_csrf,
        required_permission=required_permission,
    ).actor


def _cli_main() -> int:
    print("Generate a salted scrypt SEARCH_ADMIN_PASSWORD_HASH for backend/.env")
    password = getpass.getpass("Admin password (minimum 12 characters): ")
    if len(password) < 12:
        print("Error: password must be at least 12 characters.", file=sys.stderr)
        return 1
    confirm = getpass.getpass("Confirm admin password: ")
    if not hmac.compare_digest(password.encode("utf-8"), confirm.encode("utf-8")):
        print("Error: passwords do not match.", file=sys.stderr)
        return 1
    encoded = hash_password(password)
    print("\nAdd to backend/.env (keep backend-only, never commit):")
    print(f"SEARCH_ADMIN_PASSWORD_HASH={encoded}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
