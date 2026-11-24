"""Independent SQL Server database layer for the General Search Platform.

This module exclusively owns and accesses the General Search Platform's
``searchai.*`` tables:
  - searchai.SearchCategories
  - searchai.SearchCategoryHistory
  - searchai.SearchDocuments
  - searchai.SearchFeedback
  - searchai.SearchLogs
  - searchai.ApiRequestLogs

Strict isolation guarantees:
  - Never imports ``py-backend/app/shared/db.py``.
  - Never reflects or queries legacy Product & Company Search or BrochureIQ
    tables (dbo.Brochures, dbo.Products, dbo.Company, dbo.ProductsAndServices,
    dbo.B2BCompanies, dbo.B2BProducts).
  - Never modifies production databases or runs DDL against SQL Server.
"""
from __future__ import annotations

import threading
import time

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL, Engine
from sqlalchemy.pool import StaticPool

from app.config import (
    get_app_env,
    get_platform_sql_connection_string,
    get_platform_sql_max_overflow,
    get_platform_sql_odbc_connect,
    get_platform_sql_pool_recycle,
    get_platform_sql_pool_size,
    get_platform_sql_pool_timeout,
)
from app.logger import logger

OWNED_PLATFORM_SCHEMA = "searchai"
OWNED_PLATFORM_TABLES = frozenset(
    {
        "SearchCategories",
        "SearchCategoryHistory",
        "SearchDocuments",
        "SearchFeedback",
        "SearchLogs",
        "ApiRequestLogs",
    }
)
FORBIDDEN_LEGACY_TABLES = frozenset(
    {
        "Brochures",
        "Products",
        "Company",
        "ProductsAndServices",
        "B2BCompanies",
        "B2BProducts",
    }
)

_engine_lock = threading.RLock()
_engine: Engine | None = None


def build_platform_engine_url() -> str | URL:
    """Build the SQLAlchemy target URL for the General Search Platform database.

    Reads ``SEARCH_PLATFORM_SQL_ODBC_CONNECT_<ENV>`` (or unsuffixed fallback)
    first, then ``SEARCH_PLATFORM_SQL_CONNECTION_STRING_<ENV>`` (or unsuffixed
    fallback). Intentionally independent from legacy BrochureIQ/monolith
    ``SQL_SERVER_*`` environment variables.
    """
    env = get_app_env()
    suffix = env.upper()

    odbc_str = get_platform_sql_odbc_connect()
    if odbc_str:
        logger.info("General Search Platform SQL target: %s (ODBC connection string)", env)
        return URL.create("mssql+pyodbc", query={"odbc_connect": odbc_str})

    conn_str = get_platform_sql_connection_string()
    if conn_str:
        logger.info("General Search Platform SQL target: %s (SQLAlchemy URL)", env)
        return conn_str

    raise RuntimeError(
        f"No General Search Platform database configured for APP_ENV={env}. "
        f"Set SEARCH_PLATFORM_SQL_ODBC_CONNECT_{suffix} or "
        f"SEARCH_PLATFORM_SQL_CONNECTION_STRING_{suffix}."
    )


def connect_platform_db() -> Engine:
    """Initialize the pooled SQLAlchemy engine and verify connectivity via SELECT 1.

    Does NOT reflect any legacy dbo tables.
    """
    global _engine
    with _engine_lock:
        if _engine is not None:
            return _engine

        url = build_platform_engine_url()
        url_str = str(url)
        is_sqlite = url_str.startswith("sqlite:")

        try:
            if is_sqlite:
                is_memory = url_str.endswith(":memory:") or url_str == "sqlite://"
                kwargs: dict = {
                    "future": True,
                    "connect_args": {"check_same_thread": False},
                }
                if is_memory:
                    kwargs["poolclass"] = StaticPool
                candidate = create_engine(url, **kwargs)
            else:
                candidate = create_engine(
                    url,
                    pool_pre_ping=True,
                    future=True,
                    pool_size=get_platform_sql_pool_size(),
                    max_overflow=get_platform_sql_max_overflow(),
                    pool_timeout=get_platform_sql_pool_timeout(),
                    pool_recycle=get_platform_sql_pool_recycle(),
                )

            with candidate.connect() as conn:
                conn.execute(text("SELECT 1")).scalar()

            _engine = candidate
            logger.info("General Search Platform database connected")
            return _engine
        except Exception as exc:
            logger.error(
                "General Search Platform database connection failed (exception_type=%s)",
                type(exc).__name__,
            )
            _engine = None
            raise


def set_platform_engine(engine: Engine) -> None:
    """Inject a pre-built SQLAlchemy engine (primarily for isolated automated tests)."""
    global _engine
    with _engine_lock:
        _engine = engine


def get_platform_engine() -> Engine:
    """Return the active General Search Platform SQLAlchemy engine."""
    with _engine_lock:
        if _engine is None:
            raise RuntimeError("General Search Platform database is not connected yet")
        return _engine


def reset_platform_engine(*, dispose: bool = True) -> None:
    """Clear and optionally dispose the active platform engine."""
    global _engine
    with _engine_lock:
        if _engine is not None and dispose:
            _engine.dispose()
        _engine = None


def is_sqlite_engine(engine: Engine) -> bool:
    return engine.dialect.name == "sqlite"


def check_platform_db_ready() -> tuple[bool, float | None, str]:
    """Execute a live SELECT 1 ping against the General Search Platform database."""
    try:
        engine = get_platform_engine()
    except RuntimeError:
        return False, None, "General Search Platform database engine is not connected."

    started = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")).scalar()
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        dialect_label = "SQLite" if is_sqlite_engine(engine) else "SQL Server"
        return (
            True,
            latency_ms,
            f"General Search Platform {dialect_label} connectivity verified via live query.",
        )
    except Exception as exc:
        logger.warning(
            "General Search Platform DB readiness ping failed (exception_type=%s)",
            type(exc).__name__,
        )
        return False, None, "General Search Platform database connectivity check failed."


def create_in_memory_sqlite_platform_engine() -> Engine:
    """Create an isolated in-memory SQLite engine with an attached ``searchai`` schema.

    Intended strictly for automated unit/integration tests. Mirrors the exact
    tables from Migrations 004, 005, 006, and 007 (rollback provenance column)
    without ever touching SQL Server or any legacy dbo table.
    """
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _attach_searchai(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("ATTACH DATABASE ':memory:' AS searchai")
            cursor.execute("PRAGMA foreign_keys = ON")
        finally:
            cursor.close()

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE searchai.SearchCategories (
                    CategoryId     TEXT PRIMARY KEY,
                    DisplayName    TEXT NOT NULL,
                    ConfigJson     TEXT NOT NULL,
                    Status         TEXT NOT NULL DEFAULT 'disabled',
                    ConfigVersion  INTEGER NOT NULL DEFAULT 1,
                    IndexVersion   INTEGER NOT NULL DEFAULT 0,
                    CreatedAtUtc   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UpdatedAtUtc   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UpdatedBy      TEXT NOT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE searchai.SearchCategoryHistory (
                    HistoryId             INTEGER PRIMARY KEY AUTOINCREMENT,
                    CategoryId            TEXT NOT NULL REFERENCES SearchCategories(CategoryId) ON DELETE CASCADE,
                    ConfigVersion         INTEGER NOT NULL,
                    ConfigJson            TEXT NOT NULL,
                    Status                TEXT NOT NULL,
                    ChangedAtUtc          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    ChangedBy             TEXT NOT NULL,
                    ChangeReason          TEXT NULL,
                    RolledBackFromVersion INTEGER NULL,
                    UNIQUE(CategoryId, ConfigVersion)
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE searchai.SearchDocuments (
                    CategoryId   TEXT NOT NULL REFERENCES SearchCategories(CategoryId) ON DELETE CASCADE,
                    DocumentId   TEXT NOT NULL,
                    Title        TEXT NOT NULL DEFAULT '',
                    FieldsJson   TEXT NOT NULL,
                    MetadataJson TEXT NOT NULL DEFAULT '{}',
                    CreatedAtUtc DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UpdatedAtUtc DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (CategoryId, DocumentId)
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE searchai.SearchFeedback (
                    FeedbackId    INTEGER PRIMARY KEY AUTOINCREMENT,
                    CategoryId    TEXT NOT NULL REFERENCES SearchCategories(CategoryId) ON DELETE CASCADE,
                    QueryText     TEXT NOT NULL,
                    DocumentId    TEXT NOT NULL,
                    IsRelevant    BOOLEAN NOT NULL,
                    Comment       TEXT NULL,
                    CreatedAtUtc  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CreatedBy     TEXT NOT NULL,
                    ResultRank    INTEGER NULL,
                    ResultScore   REAL NULL,
                    ConfigVersion INTEGER NULL,
                    IndexVersion  INTEGER NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE searchai.SearchLogs (
                    SearchLogId         INTEGER PRIMARY KEY AUTOINCREMENT,
                    OccurredAtUtc       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    RequestId           TEXT NOT NULL,
                    EndpointPath        TEXT NOT NULL,
                    SearchSurface       TEXT NOT NULL,
                    CategoryId          TEXT NOT NULL,
                    ResolvedCategoryId  TEXT NULL REFERENCES SearchCategories(CategoryId) ON DELETE SET NULL,
                    QueryText           TEXT NOT NULL,
                    NormalizedQuery     TEXT NOT NULL,
                    AuthenticatedUserId TEXT NULL,
                    IdentityType        TEXT NOT NULL DEFAULT 'anonymous',
                    SessionIdHash       TEXT NULL,
                    HttpStatus          INTEGER NOT NULL,
                    Outcome             TEXT NOT NULL,
                    ResultCount         INTEGER NULL,
                    PageNo              INTEGER NOT NULL DEFAULT 1,
                    PageSize            INTEGER NOT NULL DEFAULT 10,
                    FilterCount         INTEGER NOT NULL DEFAULT 0,
                    DurationMs          REAL NOT NULL,
                    ConfigVersion       INTEGER NULL,
                    IndexVersion        INTEGER NULL,
                    ErrorCode           TEXT NULL,
                    ErrorCategory       TEXT NULL
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE searchai.ApiRequestLogs (
                    RequestLogId        INTEGER PRIMARY KEY AUTOINCREMENT,
                    OccurredAtUtc       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    RequestId           TEXT NOT NULL,
                    HttpMethod          TEXT NOT NULL,
                    EndpointTemplate    TEXT NOT NULL,
                    HttpStatus          INTEGER NOT NULL,
                    StatusClass         TEXT NOT NULL,
                    IsServerFailure     BOOLEAN NOT NULL DEFAULT 0,
                    IsClientError       BOOLEAN NOT NULL DEFAULT 0,
                    DurationMs          REAL NOT NULL,
                    AuthenticatedUserId TEXT NULL,
                    IdentityType        TEXT NOT NULL DEFAULT 'anonymous',
                    ErrorCode           TEXT NULL,
                    ErrorSummary        TEXT NULL
                )
                """
            )
        )
    return engine
