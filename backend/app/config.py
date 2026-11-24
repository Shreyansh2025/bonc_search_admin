"""Independent runtime configuration for the BONC Search Admin & General Search Platform."""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from dotenv import load_dotenv

from app.logger import logger

BACKEND_ROOT = Path(__file__).resolve().parents[1]

# Load Search_Admin's own .env file only (never py-backend/.env).
# Process environment variables always take precedence (override=False).
load_dotenv(BACKEND_ROOT / ".env", override=False)

_LOCAL_DEFAULT_ALLOWED_ORIGINS = (
    "http://127.0.0.1:5175",
    "http://localhost:5175",
    "http://127.0.0.1:4175",
    "http://localhost:4175",
)

SUPPORTED_APP_ENVS: tuple[str, ...] = ("local", "staging", "production")


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        parsed = float(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _validate_http_base_url(raw: str) -> str | None:
    trimmed = raw.strip()
    if not trimmed:
        return None
    parsed = urlsplit(trimmed)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    try:
        _ = parsed.port
    except ValueError:
        return None
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def get_app_env() -> str:
    """Return active runtime environment (``local``, ``staging``, or ``production``)."""
    return os.getenv("APP_ENV", "local").strip().lower() or "local"


def is_api_docs_enabled() -> bool:
    """Expose interactive Swagger/OpenAPI docs in local dev; fail closed outside local."""
    default_enabled = get_app_env() == "local"
    return _bool_env("SEARCH_ADMIN_ENABLE_API_DOCS", default_enabled)


def get_port() -> int:
    raw_port = os.getenv("PORT", "8004").strip()
    try:
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise RuntimeError(
            f'Invalid PORT value: "{raw_port}". Set PORT to an integer between 1 and 65535.'
        ) from exc
    return port


def normalize_cors_origin(raw_origin: str) -> str | None:
    """Validate and normalize one explicit HTTP(S) origin; reject wildcards/invalid URLs."""
    candidate = raw_origin.strip()
    if not candidate or candidate == "*":
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    try:
        _ = parsed.port
    except ValueError:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def resolve_allowed_origins() -> list[str]:
    """Resolve CORS origins safely without ever silently broadening to '*'."""
    raw = os.getenv("ALLOWED_ORIGINS")
    app_env = get_app_env()

    if raw is None:
        if app_env == "local":
            return list(_LOCAL_DEFAULT_ALLOWED_ORIGINS)
        logger.warning(
            "ALLOWED_ORIGINS is not configured for APP_ENV=%s; CORS cross-origin access is disabled.",
            app_env,
        )
        return []

    valid_origins: list[str] = []
    invalid_entries: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        trimmed = part.strip()
        if not trimmed:
            continue
        normalized = normalize_cors_origin(trimmed)
        if normalized is None:
            invalid_entries.append(trimmed)
            continue
        if normalized not in seen:
            seen.add(normalized)
            valid_origins.append(normalized)

    if invalid_entries:
        logger.warning(
            "Ignored %s invalid or wildcard ALLOWED_ORIGINS entry(ies); wildcard '*' is disallowed.",
            len(invalid_entries),
        )
    if not valid_origins:
        logger.warning(
            "ALLOWED_ORIGINS yielded no valid origins; CORS cross-origin access is disabled (fail-closed)."
        )
    return valid_origins


# ---------------------------------------------------------------------------
# BONC .NET Admin Authentication Configuration (getUserDetail — Mandatory)
# ---------------------------------------------------------------------------

DEFAULT_BONC_AUTH_ADMIN_ROLES: tuple[str, ...] = ("Admin", "SuperAdmin")
DEFAULT_BONC_AUTH_TIMEOUT_SECONDS = 5.0
DEFAULT_BONC_AUTH_CACHE_SECONDS = 60.0


def get_bonc_auth_verify_url() -> str | None:
    """Return configured BONC .NET ``getUserDetail`` endpoint URL, or None if unset."""
    raw = (os.getenv("BONC_AUTH_VERIFY_URL") or "").strip()
    return raw or None


def get_bonc_auth_admin_roles() -> tuple[str, ...]:
    """Parse comma-separated ``BONC_AUTH_ADMIN_ROLES``.

    Defaults to ``("Admin", "SuperAdmin")`` when unset. If explicitly set to
    blank/whitespace, returns ``()`` so startup validation fails closed.
    """
    raw = os.getenv("BONC_AUTH_ADMIN_ROLES")
    if raw is None:
        return DEFAULT_BONC_AUTH_ADMIN_ROLES
    roles: list[str] = []
    seen_lower: set[str] = set()
    for part in raw.split(","):
        cleaned = part.strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            roles.append(cleaned)
    return tuple(roles)


def get_bonc_auth_cache_seconds() -> float:
    """Return TTL in seconds for caching accepted BONC tokens (``0`` disables cache)."""
    raw = (os.getenv("BONC_AUTH_CACHE_SECONDS") or "").strip()
    if not raw:
        return DEFAULT_BONC_AUTH_CACHE_SECONDS
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"BONC_AUTH_CACHE_SECONDS must be a non-negative number, not {raw!r}"
        ) from exc
    if not math.isfinite(value) or value < 0:
        raise ValueError(
            f"BONC_AUTH_CACHE_SECONDS must be greater than or equal to zero, not {raw!r}"
        )
    return value


def get_bonc_auth_timeout_seconds() -> float:
    """Return HTTP timeout in seconds for calls to BONC's ``getUserDetail`` endpoint."""
    raw = (os.getenv("BONC_AUTH_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_BONC_AUTH_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"BONC_AUTH_TIMEOUT must be a positive number, not {raw!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"BONC_AUTH_TIMEOUT must be greater than zero, not {raw!r}")
    return value


# ---------------------------------------------------------------------------
# General Search Platform SQL Server Configuration (searchai.* ONLY)
# ---------------------------------------------------------------------------


def get_platform_sql_odbc_connect() -> str:
    env_suffix = get_app_env().upper()
    return (
        os.getenv(f"SEARCH_PLATFORM_SQL_ODBC_CONNECT_{env_suffix}", "").strip()
        or os.getenv("SEARCH_PLATFORM_SQL_ODBC_CONNECT", "").strip()
    )


def get_platform_sql_connection_string() -> str:
    env_suffix = get_app_env().upper()
    return (
        os.getenv(f"SEARCH_PLATFORM_SQL_CONNECTION_STRING_{env_suffix}", "").strip()
        or os.getenv("SEARCH_PLATFORM_SQL_CONNECTION_STRING", "").strip()
    )


def get_platform_sql_pool_size() -> int:
    return _int_env("SEARCH_PLATFORM_SQL_POOL_SIZE", 5, minimum=1, maximum=50)


def get_platform_sql_max_overflow() -> int:
    return _int_env("SEARCH_PLATFORM_SQL_MAX_OVERFLOW", 10, minimum=0, maximum=100)


def get_platform_sql_pool_timeout() -> int:
    return _int_env("SEARCH_PLATFORM_SQL_POOL_TIMEOUT", 30, minimum=5, maximum=120)


def get_platform_sql_pool_recycle() -> int:
    return _int_env("SEARCH_PLATFORM_SQL_POOL_RECYCLE", 1800, minimum=60, maximum=7200)


def should_warmup_embedding_model_on_startup() -> bool:
    """Whether to warm up SentenceTransformer during FastAPI lifespan startup."""
    return _bool_env("SEARCH_PLATFORM_WARMUP_EMBEDDING_MODEL", True)


# ---------------------------------------------------------------------------
# Optional Read-Only Production Observability Client (DISABLED BY DEFAULT)
# Separate security boundary from Search Admin user authentication.
# ---------------------------------------------------------------------------


def is_production_observability_enabled() -> bool:
    """Production read-only observability stays disabled until Stage 3 verification."""
    return _bool_env("PRODUCTION_OBSERVABILITY_ENABLED", False)


def get_production_search_base_url() -> str | None:
    return _validate_http_base_url(os.getenv("PRODUCTION_SEARCH_BASE_URL", ""))


def get_production_search_auth_mode() -> Literal["bearer", "api_key", "none"]:
    """Independent upstream auth mode; defaults to fail-closed 'bearer'."""
    raw = os.getenv("PRODUCTION_SEARCH_AUTH_MODE", "bearer").strip().lower()
    if raw in {"bearer", "api_key", "none"}:
        return raw  # type: ignore[return-value]
    return "bearer"


def get_production_search_auth_token() -> str:
    return os.getenv("PRODUCTION_SEARCH_AUTH_TOKEN", "").strip()


def get_production_search_auth_header() -> str:
    header = os.getenv("PRODUCTION_SEARCH_AUTH_HEADER", "X-API-Key").strip()
    return header or "X-API-Key"


def get_production_search_timeout_seconds() -> float:
    return _float_env("PRODUCTION_SEARCH_TIMEOUT_SECONDS", 10.0, minimum=1.0, maximum=60.0)
