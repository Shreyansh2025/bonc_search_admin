"""Persistent SQL storage and analytics for General Search Platform logs, KPIs, API failures & relevance.

All SQL statements are built via SQLAlchemy Core strictly against the owned
``searchai.*`` schema (via ``app.db.platform_db.get_platform_engine()``), so they
parameterize safely on SQL Server (production/staging/local) and execute
end-to-end against an isolated in-memory SQLite ``searchai`` schema in tests.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Table,
    and_,
    case,
    desc,
    func,
    insert,
    select,
    text,
)

from app.db.platform_db import check_platform_db_ready, get_platform_engine
from app.logger import logger

# ---------------------------------------------------------------------------
# SQLAlchemy Core schema definitions (searchai.*)
# ---------------------------------------------------------------------------

observability_metadata = MetaData(schema="searchai")
_BIGINT_PK_TYPE = BigInteger().with_variant(Integer, "sqlite")

search_categories_table = Table(
    "SearchCategories",
    observability_metadata,
    Column("CategoryId", String(64), primary_key=True),
    Column("DisplayName", String(120), nullable=False),
)

search_feedback_table = Table(
    "SearchFeedback",
    observability_metadata,
    Column("FeedbackId", _BIGINT_PK_TYPE, primary_key=True, autoincrement=True),
    Column("CategoryId", String(64), nullable=False),
    Column("QueryText", String(500), nullable=False),
    Column("DocumentId", String(200), nullable=False),
    Column("IsRelevant", Boolean, nullable=False),
    Column("Comment", String(1000), nullable=True),
    Column("CreatedAtUtc", DateTime, nullable=False),
    Column("CreatedBy", String(256), nullable=False),
    Column("ResultRank", Integer, nullable=True),
    Column("ResultScore", Float, nullable=True),
    Column("ConfigVersion", Integer, nullable=True),
    Column("IndexVersion", Integer, nullable=True),
)

search_logs_table = Table(
    "SearchLogs",
    observability_metadata,
    Column("SearchLogId", _BIGINT_PK_TYPE, primary_key=True, autoincrement=True),
    Column("OccurredAtUtc", DateTime, nullable=False),
    Column("RequestId", String(64), nullable=False),
    Column("EndpointPath", String(128), nullable=False),
    Column("SearchSurface", String(16), nullable=False),
    Column("CategoryId", String(64), nullable=False),
    Column("ResolvedCategoryId", String(64), nullable=True),
    Column("QueryText", String(500), nullable=False),
    Column("NormalizedQuery", String(500), nullable=False),
    Column("AuthenticatedUserId", String(256), nullable=True),
    Column("IdentityType", String(32), nullable=False),
    Column("SessionIdHash", String(64), nullable=True),
    Column("HttpStatus", SmallInteger, nullable=False),
    Column("Outcome", String(32), nullable=False),
    Column("ResultCount", Integer, nullable=True),
    Column("PageNo", Integer, nullable=False),
    Column("PageSize", Integer, nullable=False),
    Column("FilterCount", Integer, nullable=False),
    Column("DurationMs", Float, nullable=False),
    Column("ConfigVersion", Integer, nullable=True),
    Column("IndexVersion", Integer, nullable=True),
    Column("ErrorCode", String(64), nullable=True),
    Column("ErrorCategory", String(32), nullable=True),
)

api_request_logs_table = Table(
    "ApiRequestLogs",
    observability_metadata,
    Column("RequestLogId", _BIGINT_PK_TYPE, primary_key=True, autoincrement=True),
    Column("OccurredAtUtc", DateTime, nullable=False),
    Column("RequestId", String(64), nullable=False),
    Column("HttpMethod", String(16), nullable=False),
    Column("EndpointTemplate", String(200), nullable=False),
    Column("HttpStatus", SmallInteger, nullable=False),
    Column("StatusClass", String(8), nullable=False),
    Column("IsServerFailure", Boolean, nullable=False),
    Column("IsClientError", Boolean, nullable=False),
    Column("DurationMs", Float, nullable=False),
    Column("AuthenticatedUserId", String(256), nullable=True),
    Column("IdentityType", String(32), nullable=False),
    Column("ErrorCode", String(64), nullable=True),
    Column("ErrorSummary", String(256), nullable=True),
)


# ---------------------------------------------------------------------------
# Constants, validation patterns, and redaction rules
# ---------------------------------------------------------------------------

MAX_LOGGED_QUERY_LENGTH = 500
MAX_USER_ID_LENGTH = 256
MAX_CATEGORY_LENGTH = 64
MAX_ENDPOINT_LENGTH = 200
MAX_REQUEST_ID_LENGTH = 64
MAX_ERROR_CODE_LENGTH = 64
MAX_ERROR_SUMMARY_LENGTH = 256

_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_SAFE_ERROR_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s+")

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}")
_BASIC_AUTH_RE = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{6,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
_URL_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_ODBC_CONN_RE = re.compile(r"(?i)\bDRIVER\s*=\s*\{[^}]+\}[^;\r\n]*(?:;\s*[^;\r\n]+)+")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(pwd|password|passwd|secret|client_secret|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|token|"
    r"accountkey|sharedaccesskey|uid|user\s+id)\s*([:=])\s*([^;\s&,\"']+)"
)

_SECRET_ENV_KEYS = (
    "SEARCH_ADMIN_SERVICE_TOKEN",
    "SEARCH_ADMIN_PASSWORD_HASH",
    "PRODUCTION_SEARCH_AUTH_TOKEN",
    "SEARCH_PLATFORM_SQL_ODBC_CONNECT",
    "SEARCH_PLATFORM_SQL_ODBC_CONNECT_LOCAL",
    "SEARCH_PLATFORM_SQL_ODBC_CONNECT_STAGING",
    "SEARCH_PLATFORM_SQL_ODBC_CONNECT_PRODUCTION",
    "SEARCH_PLATFORM_SQL_CONNECTION_STRING",
    "SEARCH_PLATFORM_SQL_CONNECTION_STRING_LOCAL",
    "SEARCH_PLATFORM_SQL_CONNECTION_STRING_STAGING",
    "SEARCH_PLATFORM_SQL_CONNECTION_STRING_PRODUCTION",
    "SEARCH_ADMIN_API_TOKEN",
    "SEARCH_INTERNAL_API_TOKEN",
)

_ALLOWED_ERROR_CATEGORIES = {
    "validation",
    "auth",
    "not_found",
    "forbidden",
    "server_error",
    "dependency_error",
}

_ANONYMOUS_SESSION_COOKIES = ("search_session_id", "bonc_search_session")

_HTTP_STATUS_ERROR_INFO: dict[int, tuple[str, str]] = {
    400: ("http_400_bad_request", "Bad request"),
    401: ("http_401_unauthorized", "Authentication required"),
    403: ("http_403_forbidden", "Access denied"),
    404: ("http_404_not_found", "Resource not found"),
    405: ("http_405_method_not_allowed", "Method not allowed"),
    409: ("http_409_conflict", "Resource conflict"),
    422: ("http_422_validation_error", "Request validation error"),
    429: ("http_429_rate_limited", "Rate limit exceeded"),
    500: ("http_500_internal_error", "Internal server error"),
    502: ("http_502_bad_gateway", "Upstream dependency failure"),
    503: ("http_503_service_unavailable", "Service unavailable"),
    504: ("http_504_gateway_timeout", "Upstream dependency timeout"),
}

_SEARCH_ERROR_SUMMARIES: dict[str, str] = {
    "category_not_found": "Search category not found",
    "category_not_public": "Search category is not publicly available",
    "invalid_search_parameters": "Invalid search parameters",
    "authentication_required": "Authentication required",
    "forbidden": "Access denied",
    "admin_auth_unconfigured": "Admin authentication is not configured",
    "search_execution_error": "Search execution failed",
    "unhandled_exception": "Internal server error",
}

_ZERO_RESULT_RATE_DEFINITION = (
    "Percentage of successful (HTTP 2xx) search attempts that returned 0 results "
    "(zero_result_searches / successful_searches * 100). Kept separate from API 5xx "
    "failure rate and feedback-derived negative relevance rate."
)
_SERVER_FAILURE_RATE_DEFINITION = (
    "Percentage of monitored API requests returning HTTP 5xx "
    "(server_failure_requests_5xx / total_api_requests * 100). Expected 4xx client, "
    "validation, and authorization responses are tracked separately and excluded from "
    "server failures."
)
_NEGATIVE_FEEDBACK_DEFINITION = (
    "Percentage of rated search results marked not relevant "
    "(not_relevant_judgments / total_rated_results * 100). This is feedback-derived "
    "relevance data, not an objective false-positive rate against ground truth; kept "
    "separate from API 5xx failure rate and zero-result rate."
)
_RELEVANCE_DISCLAIMER = (
    "Calculated from recorded relevance feedback judgments in searchai.SearchFeedback. "
    "Negative-feedback percentage represents feedback-derived relevance rejection signals "
    "rather than an objective false-positive rate against an independent ground-truth dataset."
)


# ---------------------------------------------------------------------------
# Sanitization, formatting, and identity helpers
# ---------------------------------------------------------------------------


def utc_now_naive() -> datetime:
    """Return current UTC timestamp as naive datetime matching SQL Server DATETIME2(3)."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def format_utc_iso(value: Any) -> str | None:
    """Serialize a UTC datetime or ISO string with explicit UTC 'Z' suffix."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.isoformat(timespec="milliseconds") + "Z"
    return str(value)


def parse_utc_boundary(
    raw_value: str | None,
    *,
    is_end: bool = False,
) -> tuple[datetime | None, bool]:
    """Parse an ISO-8601 date or UTC datetime filter boundary."""
    if raw_value is None:
        return None, False
    cleaned = raw_value.strip()
    if not cleaned:
        return None, False

    if _DATE_ONLY_RE.fullmatch(cleaned):
        try:
            day = datetime.strptime(cleaned, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError(f"Invalid UTC date value: {raw_value!r}") from exc
        if is_end:
            return day + timedelta(days=1), True
        return day, False

    normalized = cleaned[:-1] + "+00:00" if cleaned.endswith(("Z", "z")) else cleaned
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 UTC timestamp: {raw_value!r}") from exc

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed, False


def validate_utc_window(
    start_utc: str | None,
    end_utc: str | None,
) -> tuple[datetime | None, datetime | None, bool]:
    """Parse and validate a UTC date range, raising ValueError if start > end."""
    start_dt, _ = parse_utc_boundary(start_utc, is_end=False)
    end_dt, end_is_exclusive = parse_utc_boundary(end_utc, is_end=True)
    if start_dt is not None and end_dt is not None:
        if end_is_exclusive:
            if not (start_dt < end_dt):
                raise ValueError("start_utc must be earlier than or equal to end_utc")
        elif start_dt > end_dt:
            raise ValueError("start_utc must be earlier than or equal to end_utc")
    return start_dt, end_dt, end_is_exclusive


def _runtime_secret_values() -> list[str]:
    """Collect active runtime secret strings so they are scrubbed if ever echoed in input."""
    secrets_list: list[str] = []
    for key in _SECRET_ENV_KEYS:
        val = os.getenv(key, "").strip()
        if len(val) >= 6:
            secrets_list.append(val)
    for env_name, env_val in os.environ.items():
        if env_name.startswith("SEARCH_SOURCE_"):
            trimmed = env_val.strip()
            if len(trimmed) >= 6:
                secrets_list.append(trimmed)
    return secrets_list


def redact_sensitive_text(value: str) -> str:
    """Scrub tokens, headers, passwords, JWTs, and connection strings from text."""
    cleaned = _CONTROL_CHARS_RE.sub("", value)
    cleaned = cleaned.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    for secret in _runtime_secret_values():
        if secret in cleaned:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = _ODBC_CONN_RE.sub("[REDACTED_CONNECTION_STRING]", cleaned)
    cleaned = _URL_CRED_RE.sub(r"\1[REDACTED]@", cleaned)
    cleaned = _BEARER_RE.sub("Bearer [REDACTED]", cleaned)
    cleaned = _BASIC_AUTH_RE.sub("Basic [REDACTED]", cleaned)
    cleaned = _JWT_RE.sub("[REDACTED_TOKEN]", cleaned)
    cleaned = _KV_SECRET_RE.sub(r"\1\2[REDACTED]", cleaned)
    return cleaned


def sanitize_query_for_log(raw_query: str | None) -> tuple[str, str]:
    """Return ``(sanitized_query, normalized_query)`` bounded and scrubbed of secrets."""
    cleaned = redact_sensitive_text(str(raw_query or "")).strip()
    sanitized = cleaned[:MAX_LOGGED_QUERY_LENGTH]
    normalized = _WHITESPACE_RE.sub(" ", sanitized).strip().lower()[:MAX_LOGGED_QUERY_LENGTH]
    return sanitized, normalized


def sanitize_category_id(raw_category: str | None) -> str:
    cleaned = redact_sensitive_text(str(raw_category or "")).strip().lower()
    return (cleaned or "unknown")[:MAX_CATEGORY_LENGTH]


def sanitize_request_id(raw_request_id: str | None) -> str:
    """Use a valid caller correlation ID or generate a fresh UUID4 hex ID."""
    candidate = str(raw_request_id or "").strip()
    if candidate and _SAFE_REQUEST_ID_RE.fullmatch(candidate):
        if all(secret not in candidate for secret in _runtime_secret_values()):
            return candidate[:MAX_REQUEST_ID_LENGTH]
    return uuid.uuid4().hex


def get_or_create_request_id(request: Any | None) -> str:
    """Retrieve or lazily attach a correlation ID on ``request.state``."""
    if request is None:
        return uuid.uuid4().hex
    existing = getattr(request.state, "request_id", None)
    if isinstance(existing, str) and existing:
        return existing
    incoming = None
    headers = getattr(request, "headers", None)
    if headers is not None:
        incoming = headers.get("x-request-id") or headers.get("x-correlation-id")
    request_id = sanitize_request_id(incoming)
    request.state.request_id = request_id
    return request_id


def hash_session_id(raw_session_id: str) -> str:
    """Hash an anonymous session identifier with SHA-256 so raw cookie values are never persisted."""
    salt = os.getenv("SEARCH_LOG_SESSION_SALT", "").strip()
    material = f"searchai-session-v1:{salt}:{raw_session_id.strip()}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _clean_user_id(raw_user_id: str | None) -> str | None:
    if raw_user_id is None:
        return None
    cleaned = redact_sensitive_text(str(raw_user_id)).strip()
    if not cleaned:
        return None
    return cleaned[:MAX_USER_ID_LENGTH]


def _verify_optional_admin_bearer(authorization: Any) -> str | None:
    """Validate optional CLI service Bearer token in constant time without raising."""
    expected = os.getenv("SEARCH_ADMIN_SERVICE_TOKEN", "").strip()
    if not expected or not isinstance(authorization, str) or not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    if not hmac.compare_digest(parts[1].strip().encode("utf-8"), expected.encode("utf-8")):
        return None
    return os.getenv("SEARCH_ADMIN_SERVICE_ACTOR", "admin:service").strip() or "admin:service"


def resolve_trusted_identity(
    request: Any | None,
    *,
    authorization: Any = None,
    verified_admin_actor: str | None = None,
) -> tuple[str, str | None, str | None]:
    """Resolve ``(identity_type, authenticated_user_id, session_id_hash)`` safely.

    NEVER trusts client-supplied user-ID headers or request-body identity fields.
    """
    actor = _clean_user_id(verified_admin_actor)
    if actor:
        return "authenticated", actor, None

    if request is not None:
        state_user = _clean_user_id(getattr(request.state, "authenticated_user_id", None))
        if state_user:
            return "authenticated", state_user, None

    auth_header = authorization if isinstance(authorization, str) else None
    if auth_header is None and request is not None:
        headers = getattr(request, "headers", None)
        if headers is not None:
            auth_header = headers.get("authorization")

    if auth_header:
        try:
            from app.services import admin_auth

            provider_user = _clean_user_id(
                admin_auth.try_resolve_public_authenticated_user(
                    request,
                    authorization=auth_header,
                )
            )
            if provider_user:
                return "authenticated", provider_user, None
        except Exception:
            pass

    raw_session: str | None = None
    if request is not None:
        state_session = getattr(request.state, "session_id", None)
        if isinstance(state_session, str) and len(state_session.strip()) >= 4:
            raw_session = state_session.strip()
        else:
            cookies = getattr(request, "cookies", None) or {}
            for cookie_name in _ANONYMOUS_SESSION_COOKIES:
                cookie_val = cookies.get(cookie_name)
                if isinstance(cookie_val, str) and len(cookie_val.strip()) >= 4:
                    raw_session = cookie_val.strip()
                    break

    if raw_session:
        return "session", None, hash_session_id(raw_session)

    return "anonymous", None, None


def status_class_for(http_status: int) -> str:
    if 100 <= http_status < 200:
        return "1xx"
    if 200 <= http_status < 300:
        return "2xx"
    if 300 <= http_status < 400:
        return "3xx"
    if 400 <= http_status < 500:
        return "4xx"
    return "5xx"


def classify_search_outcome(http_status: int, result_count: int | None) -> str:
    if 200 <= http_status < 300:
        return "zero_results" if (result_count is not None and result_count == 0) else "success"
    if 400 <= http_status < 500:
        return "client_error"
    return "server_error"


def sanitize_error_code(error_code: str | None, *, http_status: int) -> str | None:
    if http_status < 400:
        return None
    if error_code:
        candidate = error_code.strip().lower()
        if _SAFE_ERROR_CODE_RE.fullmatch(candidate):
            return candidate[:MAX_ERROR_CODE_LENGTH]
    default_pair = _HTTP_STATUS_ERROR_INFO.get(http_status)
    if default_pair:
        return default_pair[0]
    if 400 <= http_status < 500:
        return f"http_{http_status}_client_error"
    return f"http_{http_status}_server_error"


def sanitize_error_summary(http_status: int, error_code: str | None = None) -> str | None:
    if http_status < 400:
        return None
    if error_code and error_code in _SEARCH_ERROR_SUMMARIES:
        return _SEARCH_ERROR_SUMMARIES[error_code]
    default_pair = _HTTP_STATUS_ERROR_INFO.get(http_status)
    if default_pair:
        return default_pair[1]
    if 400 <= http_status < 500:
        return "Client request error"
    return "Internal server error"


def sanitize_error_category(error_category: str | None, *, http_status: int) -> str | None:
    if http_status < 400:
        return None
    if error_category and error_category in _ALLOWED_ERROR_CATEGORIES:
        return error_category
    if http_status == 401:
        return "auth"
    if http_status == 403:
        return "forbidden"
    if http_status == 404:
        return "not_found"
    if 400 <= http_status < 500:
        return "validation"
    if http_status in {502, 503, 504}:
        return "dependency_error"
    return "server_error"


def resolve_endpoint_template(request: Any) -> str:
    route = request.scope.get("route") if hasattr(request, "scope") else None
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str) and route_path.strip():
        return route_path.strip()[:MAX_ENDPOINT_LENGTH]

    raw_path = str(getattr(getattr(request, "url", None), "path", "") or "")
    if raw_path.startswith("/api/"):
        return "/api/<unmatched>"
    return "/<unmatched>"


def _pct(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 2)


# ---------------------------------------------------------------------------
# Persistent write helpers
# ---------------------------------------------------------------------------


def record_search_log(
    *,
    request_id: str,
    endpoint_path: str,
    search_surface: str,
    category_id: str,
    query: str,
    http_status: int,
    duration_ms: float,
    identity_type: str = "anonymous",
    authenticated_user_id: str | None = None,
    session_id_hash: str | None = None,
    resolved_category_id: str | None = None,
    result_count: int | None = None,
    page_no: int = 1,
    page_size: int = 10,
    filter_count: int = 0,
    config_version: int | None = None,
    index_version: int | None = None,
    error_code: str | None = None,
    error_category: str | None = None,
    occurred_at_utc: datetime | None = None,
) -> None:
    """Insert one sanitized persistent SearchLogs record."""
    bounded_status = max(100, min(599, int(http_status)))
    sanitized_query, normalized_query = sanitize_query_for_log(query)
    safe_category = sanitize_category_id(category_id)
    safe_resolved = (
        sanitize_category_id(resolved_category_id) if resolved_category_id else None
    )
    safe_user_id = _clean_user_id(authenticated_user_id)
    safe_identity_type = (
        identity_type
        if identity_type in {"authenticated", "anonymous", "session"}
        else "anonymous"
    )
    if safe_identity_type == "authenticated" and not safe_user_id:
        safe_identity_type = "anonymous"
    elif safe_identity_type != "authenticated":
        safe_user_id = None

    safe_result_count = (
        max(0, int(result_count))
        if (200 <= bounded_status < 300 and result_count is not None)
        else None
    )
    outcome = classify_search_outcome(bounded_status, safe_result_count)
    safe_error_code = sanitize_error_code(error_code, http_status=bounded_status)
    safe_error_category = sanitize_error_category(error_category, http_status=bounded_status)
    safe_surface = "admin" if search_surface == "admin" else "public"
    safe_endpoint = redact_sensitive_text(endpoint_path).strip()[:128] or "/api/platform/search"
    safe_duration = max(0.0, round(float(duration_ms), 2))
    safe_page_no = max(1, int(page_no))
    safe_page_size = max(1, min(100, int(page_size)))
    safe_filter_count = max(0, int(filter_count))
    safe_config_version = (
        int(config_version) if (config_version is not None and int(config_version) >= 1) else None
    )
    safe_index_version = (
        int(index_version) if (index_version is not None and int(index_version) >= 0) else None
    )
    safe_session_hash = (
        session_id_hash[:64]
        if (safe_identity_type == "session" and isinstance(session_id_hash, str) and session_id_hash)
        else None
    )
    timestamp = occurred_at_utc if occurred_at_utc is not None else utc_now_naive()
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    values = {
        "OccurredAtUtc": timestamp,
        "RequestId": sanitize_request_id(request_id),
        "EndpointPath": safe_endpoint,
        "SearchSurface": safe_surface,
        "CategoryId": safe_category,
        "ResolvedCategoryId": safe_resolved,
        "QueryText": sanitized_query,
        "NormalizedQuery": normalized_query,
        "AuthenticatedUserId": safe_user_id,
        "IdentityType": safe_identity_type,
        "SessionIdHash": safe_session_hash,
        "HttpStatus": bounded_status,
        "Outcome": outcome,
        "ResultCount": safe_result_count,
        "PageNo": safe_page_no,
        "PageSize": safe_page_size,
        "FilterCount": safe_filter_count,
        "DurationMs": safe_duration,
        "ConfigVersion": safe_config_version,
        "IndexVersion": safe_index_version,
        "ErrorCode": safe_error_code,
        "ErrorCategory": safe_error_category,
    }

    with get_platform_engine().begin() as connection:
        connection.execute(insert(search_logs_table).values(**values))


def safe_record_search_log(**kwargs: Any) -> bool:
    """Persist a search log without ever allowing logging failures to break search."""
    try:
        record_search_log(**kwargs)
        return True
    except Exception as exc:
        logger.warning(
            "Failed to persist SearchLogs entry (exception_type=%s)",
            type(exc).__name__,
        )
        return False


def record_api_request_log(
    *,
    request_id: str,
    http_method: str,
    endpoint_template: str,
    http_status: int,
    duration_ms: float,
    identity_type: str = "anonymous",
    authenticated_user_id: str | None = None,
    error_code: str | None = None,
    error_summary: str | None = None,
    occurred_at_utc: datetime | None = None,
) -> None:
    """Insert one sanitized persistent ApiRequestLogs record."""
    bounded_status = max(100, min(599, int(http_status)))
    status_cls = status_class_for(bounded_status)
    is_server_failure = bounded_status >= 500
    is_client_error = 400 <= bounded_status < 500

    safe_user_id = _clean_user_id(authenticated_user_id)
    safe_identity_type = (
        identity_type
        if identity_type in {"authenticated", "anonymous", "session"}
        else "anonymous"
    )
    if safe_identity_type == "authenticated" and not safe_user_id:
        safe_identity_type = "anonymous"
    elif safe_identity_type != "authenticated":
        safe_user_id = None

    safe_error_code = sanitize_error_code(error_code, http_status=bounded_status)
    if bounded_status < 400:
        safe_error_summary = None
    elif error_summary:
        safe_error_summary = redact_sensitive_text(error_summary).strip()[:MAX_ERROR_SUMMARY_LENGTH]
    else:
        safe_error_summary = sanitize_error_summary(bounded_status, safe_error_code)

    safe_method = re.sub(r"[^A-Z]", "", str(http_method or "GET").upper())[:16] or "GET"
    safe_endpoint = redact_sensitive_text(str(endpoint_template or "/<unmatched>")).strip()[
        :MAX_ENDPOINT_LENGTH
    ]
    safe_duration = max(0.0, round(float(duration_ms), 2))
    timestamp = occurred_at_utc if occurred_at_utc is not None else utc_now_naive()
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    values = {
        "OccurredAtUtc": timestamp,
        "RequestId": sanitize_request_id(request_id),
        "HttpMethod": safe_method,
        "EndpointTemplate": safe_endpoint or "/<unmatched>",
        "HttpStatus": bounded_status,
        "StatusClass": status_cls,
        "IsServerFailure": is_server_failure,
        "IsClientError": is_client_error,
        "DurationMs": safe_duration,
        "AuthenticatedUserId": safe_user_id,
        "IdentityType": safe_identity_type,
        "ErrorCode": safe_error_code,
        "ErrorSummary": safe_error_summary,
    }

    with get_platform_engine().begin() as connection:
        connection.execute(insert(api_request_logs_table).values(**values))


def safe_record_api_request_log(**kwargs: Any) -> bool:
    """Persist an API request log without ever breaking the HTTP response."""
    try:
        record_api_request_log(**kwargs)
        return True
    except Exception as exc:
        logger.warning(
            "Failed to persist ApiRequestLogs entry (exception_type=%s)",
            type(exc).__name__,
        )
        return False


# ---------------------------------------------------------------------------
# Filter builders
# ---------------------------------------------------------------------------


def _time_window_conditions(
    column: Column[Any],
    start_dt: datetime | None,
    end_dt: datetime | None,
    end_is_exclusive: bool,
) -> list[Any]:
    conditions: list[Any] = []
    if start_dt is not None:
        conditions.append(column >= start_dt)
    if end_dt is not None:
        if end_is_exclusive:
            conditions.append(column < end_dt)
        else:
            conditions.append(column <= end_dt)
    return conditions


def _search_log_conditions(
    *,
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
    end_is_exclusive: bool = False,
    user_id: str | None = None,
    identity_type: str | None = None,
    category: str | None = None,
    query: str | None = None,
    status_code: int | None = None,
    status_class: str | None = None,
    outcome: str | None = None,
    zero_results_only: bool = False,
    failed_only: bool = False,
    surface: str | None = None,
) -> list[Any]:
    t = search_logs_table
    conditions = _time_window_conditions(t.c.OccurredAtUtc, start_dt, end_dt, end_is_exclusive)

    if user_id is not None and user_id.strip():
        conditions.append(t.c.AuthenticatedUserId == user_id.strip())
    if identity_type:
        conditions.append(t.c.IdentityType == identity_type)
    if category is not None and category.strip():
        conditions.append(t.c.CategoryId == category.strip().lower())
    if query is not None and query.strip():
        _, normalized_filter = sanitize_query_for_log(query)
        if normalized_filter:
            conditions.append(t.c.NormalizedQuery.contains(normalized_filter, autoescape=True))
    if status_code is not None:
        conditions.append(t.c.HttpStatus == int(status_code))
    if status_class == "2xx":
        conditions.append(and_(t.c.HttpStatus >= 200, t.c.HttpStatus < 300))
    elif status_class == "4xx":
        conditions.append(and_(t.c.HttpStatus >= 400, t.c.HttpStatus < 500))
    elif status_class == "5xx":
        conditions.append(and_(t.c.HttpStatus >= 500, t.c.HttpStatus < 600))
    if outcome == "failed":
        conditions.append(t.c.Outcome.in_(["client_error", "server_error"]))
    elif outcome:
        conditions.append(t.c.Outcome == outcome)
    if zero_results_only:
        conditions.append(t.c.Outcome == "zero_results")
    if failed_only:
        conditions.append(t.c.Outcome.in_(["client_error", "server_error"]))
    if surface:
        conditions.append(t.c.SearchSurface == surface)

    return conditions


# ---------------------------------------------------------------------------
# Search Logs read & user breakdown queries
# ---------------------------------------------------------------------------


def _search_summary_select(conditions: list[Any]):
    t = search_logs_table
    stmt = select(
        func.count().label("total_attempts"),
        func.count(
            func.distinct(
                case(
                    (t.c.IdentityType == "authenticated", t.c.AuthenticatedUserId),
                    else_=None,
                )
            )
        ).label("unique_authenticated_users"),
        func.sum(case((t.c.IdentityType == "authenticated", 1), else_=0)).label("authenticated_attempts"),
        func.sum(case((t.c.IdentityType == "anonymous", 1), else_=0)).label("anonymous_attempts"),
        func.sum(case((t.c.IdentityType == "session", 1), else_=0)).label("session_attempts"),
        func.sum(
            case((and_(t.c.HttpStatus >= 200, t.c.HttpStatus < 300), 1), else_=0)
        ).label("successful_attempts"),
        func.sum(case((t.c.Outcome == "success", 1), else_=0)).label("attempts_with_results"),
        func.sum(case((t.c.Outcome == "zero_results", 1), else_=0)).label("zero_result_attempts"),
        func.sum(case((t.c.Outcome == "client_error", 1), else_=0)).label("client_error_attempts"),
        func.sum(case((t.c.Outcome == "server_error", 1), else_=0)).label("server_error_attempts"),
        func.avg(t.c.DurationMs).label("avg_duration_ms"),
    ).select_from(t)
    if conditions:
        stmt = stmt.where(*conditions)
    return stmt


def query_search_logs(
    *,
    page: int = 1,
    page_size: int = 25,
    start_utc: str | None = None,
    end_utc: str | None = None,
    user_id: str | None = None,
    identity_type: str | None = None,
    category: str | None = None,
    query: str | None = None,
    status_code: int | None = None,
    status_class: str | None = None,
    outcome: str | None = None,
    zero_results_only: bool = False,
    failed_only: bool = False,
    surface: str | None = None,
) -> dict[str, Any]:
    """Return paginated persistent search logs with summary aggregates."""
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= page_size <= 200:
        raise ValueError("page_size must be between 1 and 200")

    start_dt, end_dt, end_is_exclusive = validate_utc_window(start_utc, end_utc)
    conditions = _search_log_conditions(
        start_dt=start_dt,
        end_dt=end_dt,
        end_is_exclusive=end_is_exclusive,
        user_id=user_id,
        identity_type=identity_type,
        category=category,
        query=query,
        status_code=status_code,
        status_class=status_class,
        outcome=outcome,
        zero_results_only=zero_results_only,
        failed_only=failed_only,
        surface=surface,
    )

    t = search_logs_table
    summary_stmt = _search_summary_select(conditions)
    items_stmt = (
        select(
            t.c.SearchLogId,
            t.c.OccurredAtUtc,
            t.c.RequestId,
            t.c.EndpointPath,
            t.c.SearchSurface,
            t.c.CategoryId,
            t.c.QueryText,
            t.c.AuthenticatedUserId,
            t.c.IdentityType,
            t.c.HttpStatus,
            t.c.Outcome,
            t.c.ResultCount,
            t.c.PageNo,
            t.c.PageSize,
            t.c.FilterCount,
            t.c.DurationMs,
            t.c.ConfigVersion,
            t.c.IndexVersion,
            t.c.ErrorCode,
            t.c.ErrorCategory,
        )
        .select_from(t)
        .order_by(desc(t.c.OccurredAtUtc), desc(t.c.SearchLogId))
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    if conditions:
        items_stmt = items_stmt.where(*conditions)

    with get_platform_engine().connect() as connection:
        summary_row = connection.execute(summary_stmt).mappings().one()
        rows = connection.execute(items_stmt).mappings().all()

    total_attempts = int(summary_row["total_attempts"] or 0)
    authenticated_attempts = int(summary_row["authenticated_attempts"] or 0)
    anonymous_attempts = int(summary_row["anonymous_attempts"] or 0)
    session_attempts = int(summary_row["session_attempts"] or 0)
    successful_attempts = int(summary_row["successful_attempts"] or 0)
    attempts_with_results = int(summary_row["attempts_with_results"] or 0)
    zero_result_attempts = int(summary_row["zero_result_attempts"] or 0)
    client_error_attempts = int(summary_row["client_error_attempts"] or 0)
    server_error_attempts = int(summary_row["server_error_attempts"] or 0)
    avg_duration = (
        round(float(summary_row["avg_duration_ms"]), 2)
        if summary_row["avg_duration_ms"] is not None
        else None
    )
    total_pages = (total_attempts + page_size - 1) // page_size if total_attempts > 0 else 0

    return {
        "filters": {
            "start_utc": start_utc,
            "end_utc": end_utc,
            "user_id": user_id.strip() if user_id and user_id.strip() else None,
            "identity_type": identity_type,
            "category": category.strip().lower() if category and category.strip() else None,
            "query": query.strip() if query and query.strip() else None,
            "status_code": status_code,
            "status_class": status_class,
            "outcome": outcome,
            "zero_results_only": bool(zero_results_only),
            "failed_only": bool(failed_only),
            "surface": surface,
        },
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_count": total_attempts,
            "total_pages": total_pages,
        },
        "summary": {
            "total_attempts": total_attempts,
            "unique_authenticated_users": int(summary_row["unique_authenticated_users"] or 0),
            "authenticated_attempts": authenticated_attempts,
            "anonymous_attempts": anonymous_attempts,
            "session_attempts": session_attempts,
            "unauthenticated_attempts": anonymous_attempts + session_attempts,
            "successful_attempts": successful_attempts,
            "attempts_with_results": attempts_with_results,
            "zero_result_attempts": zero_result_attempts,
            "client_error_attempts_4xx": client_error_attempts,
            "server_error_attempts_5xx": server_error_attempts,
            "failed_attempts": client_error_attempts + server_error_attempts,
            "avg_duration_ms": avg_duration,
        },
        "items": [
            {
                "search_log_id": int(row["SearchLogId"]),
                "occurred_at_utc": format_utc_iso(row["OccurredAtUtc"]),
                "request_id": row["RequestId"],
                "endpoint_path": row["EndpointPath"],
                "search_surface": row["SearchSurface"],
                "category_id": row["CategoryId"],
                "query": row["QueryText"],
                "authenticated_user_id": row["AuthenticatedUserId"],
                "identity_type": row["IdentityType"],
                "http_status": int(row["HttpStatus"]),
                "outcome": row["Outcome"],
                "result_count": int(row["ResultCount"]) if row["ResultCount"] is not None else None,
                "page_no": int(row["PageNo"]),
                "page_size": int(row["PageSize"]),
                "filter_count": int(row["FilterCount"]),
                "duration_ms": round(float(row["DurationMs"]), 2),
                "config_version": int(row["ConfigVersion"]) if row["ConfigVersion"] is not None else None,
                "index_version": int(row["IndexVersion"]) if row["IndexVersion"] is not None else None,
                "error_code": row["ErrorCode"],
                "error_category": row["ErrorCategory"],
            }
            for row in rows
        ],
    }


def get_search_attempts_per_user(
    *,
    page: int = 1,
    page_size: int = 25,
    start_utc: str | None = None,
    end_utc: str | None = None,
    category: str | None = None,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Return search attempt counts per authenticated user plus overall identity totals."""
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= page_size <= 200:
        raise ValueError("page_size must be between 1 and 200")

    start_dt, end_dt, end_is_exclusive = validate_utc_window(start_utc, end_utc)
    base_conditions = _search_log_conditions(
        start_dt=start_dt,
        end_dt=end_dt,
        end_is_exclusive=end_is_exclusive,
        category=category,
        user_id=user_id,
    )

    t = search_logs_table
    summary_stmt = _search_summary_select(base_conditions)

    user_conditions = [
        *base_conditions,
        t.c.IdentityType == "authenticated",
        t.c.AuthenticatedUserId.is_not(None),
    ]
    attempt_count_expr = func.count()
    users_stmt = (
        select(
            t.c.AuthenticatedUserId.label("user_id"),
            attempt_count_expr.label("total_attempts"),
            func.sum(
                case((and_(t.c.HttpStatus >= 200, t.c.HttpStatus < 300), 1), else_=0)
            ).label("successful_attempts"),
            func.sum(case((t.c.Outcome == "zero_results", 1), else_=0)).label("zero_result_attempts"),
            func.sum(case((t.c.Outcome == "client_error", 1), else_=0)).label("client_error_attempts"),
            func.sum(case((t.c.Outcome == "server_error", 1), else_=0)).label("server_error_attempts"),
            func.avg(t.c.DurationMs).label("avg_duration_ms"),
            func.max(t.c.OccurredAtUtc).label("last_search_at_utc"),
        )
        .select_from(t)
        .where(*user_conditions)
        .group_by(t.c.AuthenticatedUserId)
        .order_by(desc(attempt_count_expr), t.c.AuthenticatedUserId.asc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )

    with get_platform_engine().connect() as connection:
        summary_row = connection.execute(summary_stmt).mappings().one()
        rows = connection.execute(users_stmt).mappings().all()

    unique_users = int(summary_row["unique_authenticated_users"] or 0)
    anonymous_attempts = int(summary_row["anonymous_attempts"] or 0)
    session_attempts = int(summary_row["session_attempts"] or 0)
    total_pages = (unique_users + page_size - 1) // page_size if unique_users > 0 else 0

    return {
        "filters": {
            "start_utc": start_utc,
            "end_utc": end_utc,
            "category": category.strip().lower() if category and category.strip() else None,
            "user_id": user_id.strip() if user_id and user_id.strip() else None,
        },
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_count": unique_users,
            "total_pages": total_pages,
        },
        "summary": {
            "total_attempts": int(summary_row["total_attempts"] or 0),
            "unique_authenticated_users": unique_users,
            "authenticated_attempts": int(summary_row["authenticated_attempts"] or 0),
            "anonymous_attempts": anonymous_attempts,
            "session_attempts": session_attempts,
            "unauthenticated_attempts": anonymous_attempts + session_attempts,
        },
        "items": [
            {
                "user_id": row["user_id"],
                "total_attempts": int(row["total_attempts"] or 0),
                "successful_attempts": int(row["successful_attempts"] or 0),
                "zero_result_attempts": int(row["zero_result_attempts"] or 0),
                "client_error_attempts_4xx": int(row["client_error_attempts"] or 0),
                "server_error_attempts_5xx": int(row["server_error_attempts"] or 0),
                "avg_duration_ms": (
                    round(float(row["avg_duration_ms"]), 2)
                    if row["avg_duration_ms"] is not None
                    else None
                ),
                "last_search_at_utc": format_utc_iso(row["last_search_at_utc"]),
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# API failure monitoring & KPI aggregation
# ---------------------------------------------------------------------------


def _query_api_monitoring(
    connection: Any,
    *,
    start_dt: datetime | None,
    end_dt: datetime | None,
    end_is_exclusive: bool,
    endpoint: str | None = None,
    top_endpoints_limit: int = 10,
    recent_failures_limit: int = 20,
) -> dict[str, Any]:
    t = api_request_logs_table
    conditions = _time_window_conditions(t.c.OccurredAtUtc, start_dt, end_dt, end_is_exclusive)
    if endpoint is not None and endpoint.strip():
        conditions.append(t.c.EndpointTemplate == endpoint.strip())

    summary_stmt = select(
        func.count().label("total_api_requests"),
        func.sum(case((t.c.HttpStatus < 400, 1), else_=0)).label("successful_requests"),
        func.sum(case((t.c.IsClientError == True, 1), else_=0)).label("client_error_requests_4xx"),  # noqa: E712
        func.sum(case((t.c.IsServerFailure == True, 1), else_=0)).label("server_failure_requests_5xx"),  # noqa: E712
        func.avg(t.c.DurationMs).label("avg_response_time_ms"),
    ).select_from(t)
    if conditions:
        summary_stmt = summary_stmt.where(*conditions)

    server_fail_expr = func.sum(
        case((t.c.IsServerFailure == True, 1), else_=0)  # noqa: E712
    )
    total_req_expr = func.count()
    endpoints_stmt = (
        select(
            t.c.EndpointTemplate.label("endpoint"),
            total_req_expr.label("total_requests"),
            server_fail_expr.label("server_failure_count_5xx"),
            func.sum(case((t.c.IsClientError == True, 1), else_=0)).label("client_error_count_4xx"),  # noqa: E712
            func.avg(t.c.DurationMs).label("avg_duration_ms"),
            func.max(
                case((t.c.IsServerFailure == True, t.c.OccurredAtUtc), else_=None)  # noqa: E712
            ).label("last_failure_at_utc"),
        )
        .select_from(t)
        .group_by(t.c.EndpointTemplate)
        .having(server_fail_expr > 0)
        .order_by(desc(server_fail_expr), desc(total_req_expr), t.c.EndpointTemplate.asc())
        .limit(top_endpoints_limit)
    )
    if conditions:
        endpoints_stmt = endpoints_stmt.where(*conditions)

    recent_conditions = [*conditions, t.c.IsServerFailure == True]  # noqa: E712
    recent_stmt = (
        select(
            t.c.RequestLogId,
            t.c.OccurredAtUtc,
            t.c.RequestId,
            t.c.HttpMethod,
            t.c.EndpointTemplate,
            t.c.HttpStatus,
            t.c.DurationMs,
            t.c.ErrorCode,
            t.c.ErrorSummary,
        )
        .select_from(t)
        .where(*recent_conditions)
        .order_by(desc(t.c.OccurredAtUtc), desc(t.c.RequestLogId))
        .limit(recent_failures_limit)
    )

    summary_row = connection.execute(summary_stmt).mappings().one()
    endpoint_rows = connection.execute(endpoints_stmt).mappings().all()
    recent_rows = connection.execute(recent_stmt).mappings().all()

    total_api = int(summary_row["total_api_requests"] or 0)
    successful = int(summary_row["successful_requests"] or 0)
    client_4xx = int(summary_row["client_error_requests_4xx"] or 0)
    server_5xx = int(summary_row["server_failure_requests_5xx"] or 0)
    avg_ms = (
        round(float(summary_row["avg_response_time_ms"]), 2)
        if summary_row["avg_response_time_ms"] is not None
        else None
    )

    endpoints_out: list[dict[str, Any]] = []
    for row in endpoint_rows:
        ep_total = int(row["total_requests"] or 0)
        ep_5xx = int(row["server_failure_count_5xx"] or 0)
        ep_4xx = int(row["client_error_count_4xx"] or 0)
        endpoints_out.append(
            {
                "endpoint": row["endpoint"],
                "total_requests": ep_total,
                "server_failure_count_5xx": ep_5xx,
                "server_failure_rate_pct": _pct(ep_5xx, ep_total),
                "client_error_count_4xx": ep_4xx,
                "avg_duration_ms": (
                    round(float(row["avg_duration_ms"]), 2)
                    if row["avg_duration_ms"] is not None
                    else None
                ),
                "last_failure_at_utc": format_utc_iso(row["last_failure_at_utc"]),
            }
        )

    endpoints_out.sort(
        key=lambda item: (
            item["server_failure_count_5xx"],
            item["server_failure_rate_pct"] or 0.0,
            item["total_requests"],
        ),
        reverse=True,
    )

    return {
        "total_api_requests": total_api,
        "successful_requests": successful,
        "client_error_requests_4xx": client_4xx,
        "server_failure_requests_5xx": server_5xx,
        "server_failure_rate_pct": _pct(server_5xx, total_api),
        "server_failure_rate_numerator": server_5xx,
        "server_failure_rate_denominator": total_api,
        "server_failure_rate_definition": _SERVER_FAILURE_RATE_DEFINITION,
        "client_error_rate_pct": _pct(client_4xx, total_api),
        "avg_response_time_ms": avg_ms,
        "most_failure_prone_endpoints": endpoints_out,
        "recent_server_failures": [
            {
                "request_log_id": int(row["RequestLogId"]),
                "occurred_at_utc": format_utc_iso(row["OccurredAtUtc"]),
                "request_id": row["RequestId"],
                "http_method": row["HttpMethod"],
                "endpoint": row["EndpointTemplate"],
                "http_status": int(row["HttpStatus"]),
                "duration_ms": round(float(row["DurationMs"]), 2),
                "error_code": row["ErrorCode"],
                "error_summary": row["ErrorSummary"],
            }
            for row in recent_rows
        ],
    }


def get_api_failure_metrics(
    *,
    start_utc: str | None = None,
    end_utc: str | None = None,
    endpoint: str | None = None,
    top_endpoints_limit: int = 10,
    recent_failures_limit: int = 20,
) -> dict[str, Any]:
    """Return backend-calculated API request counts, 4xx vs 5xx separation & failure-prone endpoints."""
    if not 1 <= top_endpoints_limit <= 50:
        raise ValueError("top_endpoints_limit must be between 1 and 50")
    if not 1 <= recent_failures_limit <= 100:
        raise ValueError("recent_failures_limit must be between 1 and 100")

    start_dt, end_dt, end_is_exclusive = validate_utc_window(start_utc, end_utc)
    with get_platform_engine().connect() as connection:
        monitoring = _query_api_monitoring(
            connection,
            start_dt=start_dt,
            end_dt=end_dt,
            end_is_exclusive=end_is_exclusive,
            endpoint=endpoint,
            top_endpoints_limit=top_endpoints_limit,
            recent_failures_limit=recent_failures_limit,
        )

    return {
        "window": {
            "start_utc": start_utc,
            "end_utc": end_utc,
            "endpoint": endpoint.strip() if endpoint and endpoint.strip() else None,
        },
        **monitoring,
    }


# ---------------------------------------------------------------------------
# Relevance and rejection metrics (feedback-derived, from searchai.SearchFeedback)
# ---------------------------------------------------------------------------


def _query_relevance_summary(
    connection: Any,
    *,
    start_dt: datetime | None,
    end_dt: datetime | None,
    end_is_exclusive: bool,
    category: str | None = None,
) -> dict[str, Any]:
    fb = search_feedback_table
    conditions = _time_window_conditions(fb.c.CreatedAtUtc, start_dt, end_dt, end_is_exclusive)
    if category is not None and category.strip():
        conditions.append(fb.c.CategoryId == category.strip().lower())

    summary_stmt = select(
        func.count().label("total_rated_results"),
        func.sum(case((fb.c.IsRelevant == True, 1), else_=0)).label("relevant_judgments"),  # noqa: E712
        func.sum(case((fb.c.IsRelevant == False, 1), else_=0)).label("not_relevant_judgments"),  # noqa: E712
    ).select_from(fb)
    if conditions:
        summary_stmt = summary_stmt.where(*conditions)

    row = connection.execute(summary_stmt).mappings().one()
    total_rated = int(row["total_rated_results"] or 0)
    relevant = int(row["relevant_judgments"] or 0)
    not_relevant = int(row["not_relevant_judgments"] or 0)

    return {
        "relevant_judgments": relevant,
        "not_relevant_judgments": not_relevant,
        "total_rated_results": total_rated,
        "positive_feedback_percentage": _pct(relevant, total_rated),
        "negative_feedback_percentage": _pct(not_relevant, total_rated),
        "negative_feedback_numerator": not_relevant,
        "negative_feedback_denominator": total_rated,
        "negative_feedback_definition": _NEGATIVE_FEEDBACK_DEFINITION,
    }


def get_relevance_metrics(
    *,
    start_utc: str | None = None,
    end_utc: str | None = None,
    category: str | None = None,
    recent_negative_limit: int = 20,
) -> dict[str, Any]:
    """Calculate feedback-derived relevance & negative-feedback metrics from SearchFeedback."""
    if not 1 <= recent_negative_limit <= 100:
        raise ValueError("recent_negative_limit must be between 1 and 100")

    start_dt, end_dt, end_is_exclusive = validate_utc_window(start_utc, end_utc)
    fb = search_feedback_table
    cats = search_categories_table
    conditions = _time_window_conditions(fb.c.CreatedAtUtc, start_dt, end_dt, end_is_exclusive)
    cleaned_category = category.strip().lower() if category and category.strip() else None
    if cleaned_category:
        conditions.append(fb.c.CategoryId == cleaned_category)

    not_rel_expr = func.sum(
        case((fb.c.IsRelevant == False, 1), else_=0)  # noqa: E712
    )
    total_rated_expr = func.count()

    breakdown_stmt = (
        select(
            fb.c.CategoryId.label("category_id"),
            cats.c.DisplayName.label("display_name"),
            total_rated_expr.label("total_rated_results"),
            func.sum(case((fb.c.IsRelevant == True, 1), else_=0)).label("relevant_judgments"),  # noqa: E712
            not_rel_expr.label("not_relevant_judgments"),
        )
        .select_from(fb.outerjoin(cats, fb.c.CategoryId == cats.c.CategoryId))
        .group_by(fb.c.CategoryId, cats.c.DisplayName)
        .order_by(desc(not_rel_expr), desc(total_rated_expr), fb.c.CategoryId.asc())
    )
    if conditions:
        breakdown_stmt = breakdown_stmt.where(*conditions)

    recent_neg_conditions = [*conditions, fb.c.IsRelevant == False]  # noqa: E712
    recent_neg_stmt = (
        select(
            fb.c.FeedbackId,
            fb.c.CategoryId,
            fb.c.QueryText,
            fb.c.DocumentId,
            fb.c.Comment,
            fb.c.ResultRank,
            fb.c.ResultScore,
            fb.c.ConfigVersion,
            fb.c.IndexVersion,
            fb.c.CreatedAtUtc,
            fb.c.CreatedBy,
        )
        .select_from(fb)
        .where(*recent_neg_conditions)
        .order_by(desc(fb.c.CreatedAtUtc), desc(fb.c.FeedbackId))
        .limit(recent_negative_limit)
    )

    with get_platform_engine().connect() as connection:
        summary = _query_relevance_summary(
            connection,
            start_dt=start_dt,
            end_dt=end_dt,
            end_is_exclusive=end_is_exclusive,
            category=cleaned_category,
        )
        cat_rows = connection.execute(breakdown_stmt).mappings().all()
        neg_rows = connection.execute(recent_neg_stmt).mappings().all()

    category_breakdown = []
    for row in cat_rows:
        cat_total = int(row["total_rated_results"] or 0)
        cat_rel = int(row["relevant_judgments"] or 0)
        cat_not_rel = int(row["not_relevant_judgments"] or 0)
        category_breakdown.append(
            {
                "category_id": row["category_id"],
                "display_name": row["display_name"] or row["category_id"],
                "relevant_judgments": cat_rel,
                "not_relevant_judgments": cat_not_rel,
                "total_rated_results": cat_total,
                "positive_feedback_percentage": _pct(cat_rel, cat_total),
                "negative_feedback_percentage": _pct(cat_not_rel, cat_total),
                "negative_feedback_numerator": cat_not_rel,
                "negative_feedback_denominator": cat_total,
            }
        )

    recent_negative_examples = [
        {
            "feedback_id": int(row["FeedbackId"]),
            "category_id": row["CategoryId"],
            "query": row["QueryText"],
            "document_id": row["DocumentId"],
            "comment": row["Comment"],
            "result_rank": int(row["ResultRank"]) if row["ResultRank"] is not None else None,
            "result_score": float(row["ResultScore"]) if row["ResultScore"] is not None else None,
            "config_version": int(row["ConfigVersion"]) if row["ConfigVersion"] is not None else None,
            "index_version": int(row["IndexVersion"]) if row["IndexVersion"] is not None else None,
            "created_at_utc": format_utc_iso(row["CreatedAtUtc"]),
            "created_by": row["CreatedBy"],
        }
        for row in neg_rows
    ]

    return {
        "window": {
            "start_utc": start_utc,
            "end_utc": end_utc,
            "category": cleaned_category,
        },
        "metric_classification": "feedback_derived_relevance",
        "is_ground_truth": False,
        "disclaimer": _RELEVANCE_DISCLAIMER,
        "summary": summary,
        "category_breakdown": category_breakdown,
        "recent_negative_examples": recent_negative_examples,
    }


def get_kpi_metrics(
    *,
    start_utc: str | None = None,
    end_utc: str | None = None,
    category: str | None = None,
    top_endpoints_limit: int = 10,
    recent_failures_limit: int = 20,
) -> dict[str, Any]:
    """Return combined KPI overview with search KPIs, API failure monitoring, and feedback summary."""
    if not 1 <= top_endpoints_limit <= 50:
        raise ValueError("top_endpoints_limit must be between 1 and 50")
    if not 1 <= recent_failures_limit <= 100:
        raise ValueError("recent_failures_limit must be between 1 and 100")

    start_dt, end_dt, end_is_exclusive = validate_utc_window(start_utc, end_utc)
    cleaned_category = category.strip().lower() if category and category.strip() else None
    search_conditions = _search_log_conditions(
        start_dt=start_dt,
        end_dt=end_dt,
        end_is_exclusive=end_is_exclusive,
        category=cleaned_category,
    )
    search_summary_stmt = _search_summary_select(search_conditions)

    with get_platform_engine().connect() as connection:
        search_row = connection.execute(search_summary_stmt).mappings().one()
        api_monitoring = _query_api_monitoring(
            connection,
            start_dt=start_dt,
            end_dt=end_dt,
            end_is_exclusive=end_is_exclusive,
            top_endpoints_limit=top_endpoints_limit,
            recent_failures_limit=recent_failures_limit,
        )
        relevance_summary = _query_relevance_summary(
            connection,
            start_dt=start_dt,
            end_dt=end_dt,
            end_is_exclusive=end_is_exclusive,
            category=cleaned_category,
        )

    total_attempts = int(search_row["total_attempts"] or 0)
    unique_auth_users = int(search_row["unique_authenticated_users"] or 0)
    auth_searches = int(search_row["authenticated_attempts"] or 0)
    anon_searches = int(search_row["anonymous_attempts"] or 0)
    session_searches = int(search_row["session_attempts"] or 0)
    successful_searches = int(search_row["successful_attempts"] or 0)
    with_results = int(search_row["attempts_with_results"] or 0)
    zero_results = int(search_row["zero_result_attempts"] or 0)
    client_4xx = int(search_row["client_error_attempts"] or 0)
    server_5xx = int(search_row["server_error_attempts"] or 0)
    avg_search_ms = (
        round(float(search_row["avg_duration_ms"]), 2)
        if search_row["avg_duration_ms"] is not None
        else None
    )

    return {
        "window": {
            "start_utc": start_utc,
            "end_utc": end_utc,
            "category": cleaned_category,
        },
        "search_kpis": {
            "total_search_attempts": total_attempts,
            "unique_authenticated_users": unique_auth_users,
            "authenticated_searches": auth_searches,
            "anonymous_searches": anon_searches,
            "session_searches": session_searches,
            "unauthenticated_searches": anon_searches + session_searches,
            "successful_searches": successful_searches,
            "searches_with_results": with_results,
            "zero_result_searches": zero_results,
            "zero_result_rate_pct": _pct(zero_results, successful_searches),
            "zero_result_rate_numerator": zero_results,
            "zero_result_rate_denominator": successful_searches,
            "zero_result_rate_definition": _ZERO_RESULT_RATE_DEFINITION,
            "client_error_searches_4xx": client_4xx,
            "server_error_searches_5xx": server_5xx,
            "search_server_failure_rate_pct": _pct(server_5xx, total_attempts),
            "avg_response_time_ms": avg_search_ms,
        },
        "api_monitoring": api_monitoring,
        "relevance_feedback": {
            "metric_classification": "feedback_derived_relevance",
            "is_ground_truth": False,
            "disclaimer": _RELEVANCE_DISCLAIMER,
            **relevance_summary,
        },
    }


# ---------------------------------------------------------------------------
# Live System Health summary (Independent General Search Platform + optional read-only Prod)
# ---------------------------------------------------------------------------


def _default_disabled_production_snapshot() -> dict[str, Any]:
    return {
        "enabled": False,
        "status": "disabled",
        "read_only": True,
        "ready_count": 0,
        "total_count": 0,
        "total_records": 0,
        "detail": (
            "Optional read-only production Product & Company Search observability "
            "is disabled until Stage 3 verification."
        ),
        "indexes": {},
    }


def get_system_health(
    app_state: Any,
    *,
    recent_failures_limit: int = 10,
    production_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble live health status for Search_Admin's General Search Platform components."""
    if not 1 <= recent_failures_limit <= 50:
        raise ValueError("recent_failures_limit must be between 1 and 50")

    from app.schemas.platform import CategoryConfig
    from app.services import embedding_model, platform_search, source_sync

    checked_at = utc_now_naive()
    init_error = getattr(app_state, "initialization_error", None)
    init_task = getattr(app_state, "initialization_task", None)
    init_in_progress = bool(init_task is not None and not init_task.done())
    db_startup_ready = bool(getattr(app_state, "platform_db_ready", False))

    # 1. API / Backend process
    api_component: dict[str, Any] = {
        "status": "healthy",
        "service": "search-admin-platform",
        "detail": "BONC General Search Platform & Admin API process is responding.",
    }

    # 2. Live General Search Platform Database connectivity check
    db_ok, db_latency_ms, db_ping_detail = check_platform_db_ready()
    if db_ok:
        db_status = "healthy"
        db_detail = db_ping_detail
    elif init_error and not db_startup_ready:
        db_status = "unhealthy"
        db_detail = "General Search Platform database initialization failed during startup."
    elif init_in_progress:
        db_status = "degraded"
        db_detail = "General Search Platform database connection is initializing."
    else:
        db_status = "unavailable"
        db_detail = db_ping_detail

    database_component: dict[str, Any] = {
        "status": db_status,
        "startup_ready": db_startup_ready,
        "latency_ms": db_latency_ms,
        "detail": db_detail,
    }

    # 3. Embedding model readiness
    model_name = getattr(embedding_model, "MODEL_NAME", None)
    embedding_dim = getattr(embedding_model, "EMBEDDING_DIM", None)
    model_startup_ready = bool(getattr(app_state, "embedding_model_ready", False))
    cache_info_fn = getattr(embedding_model.get_model, "cache_info", None)
    model_loaded = (
        bool(cache_info_fn().currsize > 0)
        if callable(cache_info_fn)
        else model_startup_ready
    )

    if model_startup_ready or model_loaded:
        model_status = "healthy"
        model_detail = f"Embedding model ({model_name or 'configured'}) is loaded and ready."
    elif init_error and db_startup_ready:
        model_status = "unhealthy"
        model_detail = "Embedding model initialization failed during startup."
    elif init_in_progress:
        model_status = "degraded"
        model_detail = "Embedding model is warming up."
    else:
        model_status = "unavailable"
        model_detail = "Embedding model is not loaded yet (lazy-loaded on first semantic query)."

    embedding_component: dict[str, Any] = {
        "status": model_status,
        "model_name": model_name,
        "embedding_dim": embedding_dim,
        "loaded": model_loaded,
        "startup_ready": model_startup_ready,
        "detail": model_detail,
    }

    # 4. Optional Read-Only Production Product & Company Search Observability (disabled by default)
    production_component = (
        dict(production_snapshot)
        if isinstance(production_snapshot, dict)
        else _default_disabled_production_snapshot()
    )
    prod_status = str(production_component.get("status") or "disabled")

    # 5. Category-level index & sync status (General Search Platform)
    source_profiles = source_sync.list_source_profiles()
    cached_statuses = platform_search.get_category_index_statuses()
    category_items: list[dict[str, Any]] = []
    cat_status = "unavailable"
    cat_detail = "Category index information is unavailable while database is disconnected."
    total_categories: int | None = None
    active_categories: int | None = None
    total_category_docs: int | None = None

    if db_status == "healthy":
        try:
            category_rows_stmt = text(
                """
                SELECT c.CategoryId, c.ConfigJson, c.Status, c.ConfigVersion, c.IndexVersion,
                       c.UpdatedAtUtc, c.UpdatedBy,
                       COALESCE(doc_counts.DocumentCount, 0) AS DocumentCount
                FROM searchai.SearchCategories c
                LEFT JOIN (
                    SELECT CategoryId, COUNT(*) AS DocumentCount
                    FROM searchai.SearchDocuments
                    GROUP BY CategoryId
                ) doc_counts ON doc_counts.CategoryId = c.CategoryId
                ORDER BY c.DisplayName
                """
            )
            with get_platform_engine().connect() as connection:
                raw_cat_rows = connection.execute(category_rows_stmt).mappings().all()

            records = [
                {
                    "config": CategoryConfig.model_validate_json(row["ConfigJson"]),
                    "status": row["Status"],
                    "config_version": int(row["ConfigVersion"]),
                    "index_version": int(row["IndexVersion"]),
                    "updated_at_utc": row["UpdatedAtUtc"],
                    "updated_by": row["UpdatedBy"],
                    "document_count": int(row["DocumentCount"] or 0),
                }
                for row in raw_cat_rows
            ]
            total_categories = len(records)
            active_categories = 0
            total_category_docs = 0
            has_degraded_category = False

            for rec in records:
                cfg = rec["config"]
                cat_id = cfg.category_id
                doc_count = int(rec.get("document_count") or 0)
                cfg_ver = int(rec.get("config_version") or 1)
                idx_ver = int(rec.get("index_version") or 0)
                is_active = rec.get("status") == "active" and bool(cfg.active)
                if is_active:
                    active_categories += 1
                total_category_docs += doc_count

                cache_entry = cached_statuses.get(cat_id)
                if doc_count == 0:
                    cache_status = "empty"
                elif cache_entry is not None:
                    version_matches = cache_entry["cached_index_version"] == idx_ver and (
                        cache_entry["cached_config_version"] is None
                        or cache_entry["cached_config_version"] == cfg_ver
                    )
                    cache_status = "warm" if version_matches else "stale"
                else:
                    cache_status = "cold"

                item_health = (
                    "degraded"
                    if is_active and (doc_count == 0 or cache_status == "stale")
                    else "healthy"
                )
                if item_health == "degraded":
                    has_degraded_category = True

                source_type = cfg.source.type
                source_target = (
                    f"[{cfg.source.schema}].[{cfg.source.table}]"
                    if source_type == "sqlserver"
                    else "push"
                )
                category_items.append(
                    {
                        "category_id": cat_id,
                        "display_name": cfg.display_name,
                        "status": rec.get("status") or ("active" if cfg.active else "disabled"),
                        "active": is_active,
                        "public_search_enabled": bool(cfg.public_search_enabled),
                        "source_type": source_type,
                        "source_target": source_target,
                        "document_count": doc_count,
                        "config_version": cfg_ver,
                        "index_version": idx_ver,
                        "updated_at_utc": format_utc_iso(rec.get("updated_at_utc")),
                        "updated_by": rec.get("updated_by"),
                        "cache_status": cache_status,
                        "cached_document_count": (
                            cache_entry["cached_document_count"] if cache_entry else None
                        ),
                        "vector_index_built": (
                            bool(cache_entry["vector_index_built"]) if cache_entry else False
                        ),
                        "health_state": item_health,
                    }
                )

            if has_degraded_category:
                cat_status = "degraded"
                cat_detail = (
                    "One or more active categories have 0 indexed documents or a stale worker cache."
                )
            else:
                cat_status = "healthy"
                cat_detail = (
                    f"{active_categories} active of {total_categories} configured search "
                    f"categories ({total_category_docs} total indexed documents)."
                )
        except Exception as exc:
            logger.warning(
                "System health category inspection failed (exception_type=%s)",
                type(exc).__name__,
            )
            cat_status = "unavailable"
            cat_detail = "Category index metadata could not be read from searchai.SearchCategories."

    category_indexes_component: dict[str, Any] = {
        "status": cat_status,
        "total_categories": total_categories,
        "active_categories": active_categories,
        "total_documents": total_category_docs,
        "source_profile_count": len(source_profiles),
        "source_profiles": source_profiles,
        "detail": cat_detail,
        "items": category_items,
    }

    # 6. Recent HTTP 5xx server failures (last 24h)
    failures_status = "unavailable"
    failures_detail = "Server failure telemetry is unavailable while database is disconnected."
    total_api_24h: int | None = None
    server_5xx_24h: int | None = None
    client_4xx_24h: int | None = None
    failure_rate_24h: float | None = None
    recent_failure_items: list[dict[str, Any]] = []

    if db_status == "healthy":
        try:
            window_start = checked_at - timedelta(hours=24)
            with get_platform_engine().connect() as connection:
                monitoring = _query_api_monitoring(
                    connection,
                    start_dt=window_start,
                    end_dt=None,
                    end_is_exclusive=False,
                    top_endpoints_limit=5,
                    recent_failures_limit=recent_failures_limit,
                )
            total_api_24h = monitoring["total_api_requests"]
            server_5xx_24h = monitoring["server_failure_requests_5xx"]
            client_4xx_24h = monitoring["client_error_requests_4xx"]
            failure_rate_24h = monitoring["server_failure_rate_pct"]
            recent_failure_items = monitoring["recent_server_failures"]
            if server_5xx_24h > 0:
                failures_status = "degraded"
                failures_detail = (
                    f"{server_5xx_24h} HTTP 5xx server failure(s) recorded in the last 24 hours."
                )
            else:
                failures_status = "healthy"
                failures_detail = "No HTTP 5xx server failures recorded in the last 24 hours."
        except Exception as exc:
            logger.warning(
                "System health API failure query unavailable (exception_type=%s)",
                type(exc).__name__,
            )
            failures_status = "unavailable"
            failures_detail = (
                "Observability request log storage is unavailable "
                "(ensure General Search Platform schema is provisioned)."
            )

    recent_failures_component: dict[str, Any] = {
        "status": failures_status,
        "window_hours": 24,
        "total_api_requests_24h": total_api_24h,
        "server_failures_24h": server_5xx_24h,
        "client_errors_24h": client_4xx_24h,
        "server_failure_rate_24h_pct": failure_rate_24h,
        "detail": failures_detail,
        "items": recent_failure_items,
    }

    # Overall status aggregation:
    # Disabled optional production observability NEVER degrades Search_Admin's own health.
    core_statuses = {db_status, model_status}
    all_statuses = {
        api_component["status"],
        db_status,
        model_status,
        cat_status,
        failures_status,
    }
    if prod_status not in {"disabled", "healthy"}:
        all_statuses.add("degraded")

    if "unhealthy" in core_statuses:
        overall_status = "unhealthy"
    elif db_status == "unavailable":
        overall_status = "unavailable"
    elif "degraded" in all_statuses or "unavailable" in all_statuses:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return {
        "status": overall_status,
        "service": "search-admin-platform",
        "checked_at_utc": format_utc_iso(checked_at),
        "initialization_error": init_error,
        "components": {
            "api": api_component,
            "database": database_component,
            "embedding_model": embedding_component,
            "production_search": production_component,
            "search_indexes": production_component,
            "category_indexes": category_indexes_component,
            "recent_server_failures": recent_failures_component,
        },
    }
