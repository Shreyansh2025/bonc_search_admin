"""Isolated Admin-only SQLite store for temporary local admin sessions and login rate limits.

This lightweight SQLite store exists exclusively to manage local Admin browser
sessions, CSRF tokens, and IP-hashed login rate limiting until BONC JWT
authentication replaces local auth in a future task. It is completely isolated
from both the General Search Platform SQL Server database and the original
production database.
"""
from __future__ import annotations

import threading

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

from app.config import get_admin_auth_db_url
from app.logger import logger

admin_auth_metadata = MetaData()
_BIGINT_PK_TYPE = BigInteger().with_variant(Integer, "sqlite")

admin_sessions_table = Table(
    "admin_sessions",
    admin_auth_metadata,
    Column("SessionId", String(64), primary_key=True),
    Column("SessionTokenHash", String(64), nullable=False, unique=True),
    Column("CsrfToken", String(128), nullable=False),
    Column("AdminUsername", String(128), nullable=False),
    Column("CreatedAtUtc", DateTime, nullable=False),
    Column("LastSeenAtUtc", DateTime, nullable=False),
    Column("ExpiresAtUtc", DateTime, nullable=False),
    Column("RevokedAtUtc", DateTime, nullable=True),
    Column("RevokedReason", String(128), nullable=True),
    Column("ClientIpHash", String(64), nullable=True),
    Column("UserAgent", String(256), nullable=True),
)

admin_login_attempts_table = Table(
    "admin_login_attempts",
    admin_auth_metadata,
    Column("AttemptId", _BIGINT_PK_TYPE, primary_key=True, autoincrement=True),
    Column("ClientKeyHash", String(64), nullable=False),
    Column("AttemptedAtUtc", DateTime, nullable=False),
    Column("Succeeded", Boolean, nullable=False),
)

Index("ix_admin_sessions_expires", admin_sessions_table.c.ExpiresAtUtc)
Index(
    "ix_admin_login_attempts_key_time",
    admin_login_attempts_table.c.ClientKeyHash,
    admin_login_attempts_table.c.AttemptedAtUtc,
)

_engine_lock = threading.RLock()
_engine: Engine | None = None
_engine_url: str | None = None


def _build_engine(url: str) -> Engine:
    is_memory = url.endswith(":memory:") or url == "sqlite://"
    kwargs: dict = {
        "future": True,
        "connect_args": {"check_same_thread": False, "timeout": 10},
    }
    if is_memory:
        kwargs["poolclass"] = StaticPool

    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("PRAGMA busy_timeout = 5000")
            if not is_memory:
                cursor.execute("PRAGMA journal_mode = WAL")
        finally:
            cursor.close()

    admin_auth_metadata.create_all(engine)
    return engine


def init_auth_db(url: str | None = None) -> Engine:
    """Initialize (or return) the isolated Admin-local SQLite engine."""
    global _engine, _engine_url
    target_url = url or get_admin_auth_db_url()
    with _engine_lock:
        if _engine is not None and _engine_url == target_url:
            return _engine
        if _engine is not None:
            _engine.dispose()
        _engine = _build_engine(target_url)
        _engine_url = target_url
        logger.info("Search Admin local auth store initialized")
        return _engine


def get_auth_engine() -> Engine:
    """Return the active Admin auth SQLite engine, initializing lazily if needed."""
    global _engine
    with _engine_lock:
        if _engine is None:
            return init_auth_db()
        return _engine


def reset_auth_engine() -> None:
    """Dispose the active engine (used for clean shutdown and isolated unit tests)."""
    global _engine, _engine_url
    with _engine_lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _engine_url = None


def check_auth_db_ready() -> bool:
    try:
        with get_auth_engine().connect() as conn:
            conn.execute(text("SELECT 1")).scalar()
        return True
    except Exception as exc:
        logger.error(
            "Admin local auth store readiness check failed (exception_type=%s)",
            type(exc).__name__,
        )
        return False
