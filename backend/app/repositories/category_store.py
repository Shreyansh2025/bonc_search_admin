"""General Search Platform persistence for search categories, history, rollback, documents & feedback.

Operates strictly against the ``searchai.*`` schema owned by Search_Admin via
``app.db.platform_db.get_platform_engine()``. Uses exact T-SQL (``COUNT_BIG``,
``SELECT TOP``, ``MERGE``) on SQL Server (``mssql``) and native equivalent SQL
on SQLite (``sqlite``) for isolated automated tests.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from app.db.platform_db import get_platform_engine, is_sqlite_engine
from app.schemas.platform import CategoryConfig, SearchDocument


class CategoryNotFoundError(LookupError):
    pass


class CategoryHistoryNotFoundError(LookupError):
    pass


class CategoryAlreadyExistsError(ValueError):
    pass


class CategoryStoreError(RuntimeError):
    pass


class CategoryVersionConflictError(CategoryStoreError):
    pass


def _utc_now_naive() -> datetime:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


_GET_CATEGORY = text(
    """
    SELECT c.CategoryId, c.ConfigJson, c.Status, c.ConfigVersion, c.IndexVersion,
           c.UpdatedAtUtc, c.UpdatedBy
    FROM searchai.SearchCategories c
    WHERE c.CategoryId = :category_id
    """
)

_GET_CATEGORY_WITH_COUNT_MSSQL = text(
    """
    SELECT c.CategoryId, c.ConfigJson, c.Status, c.ConfigVersion, c.IndexVersion,
           c.UpdatedAtUtc, c.UpdatedBy,
           (SELECT COUNT_BIG(*) FROM searchai.SearchDocuments d WHERE d.CategoryId = c.CategoryId) AS DocumentCount
    FROM searchai.SearchCategories c
    WHERE c.CategoryId = :category_id
    """
)

_GET_CATEGORY_WITH_COUNT_SQLITE = text(
    """
    SELECT c.CategoryId, c.ConfigJson, c.Status, c.ConfigVersion, c.IndexVersion,
           c.UpdatedAtUtc, c.UpdatedBy,
           (SELECT COUNT(*) FROM searchai.SearchDocuments d WHERE d.CategoryId = c.CategoryId) AS DocumentCount
    FROM searchai.SearchCategories c
    WHERE c.CategoryId = :category_id
    """
)

_LIST_CATEGORIES = text(
    """
    SELECT c.CategoryId, c.ConfigJson, c.Status, c.ConfigVersion, c.IndexVersion,
           c.UpdatedAtUtc, c.UpdatedBy
    FROM searchai.SearchCategories c
    ORDER BY c.DisplayName
    """
)

_LIST_CATEGORIES_WITH_COUNTS_MSSQL = text(
    """
    SELECT c.CategoryId, c.ConfigJson, c.Status, c.ConfigVersion, c.IndexVersion,
           c.UpdatedAtUtc, c.UpdatedBy,
           COALESCE(doc_counts.DocumentCount, 0) AS DocumentCount
    FROM searchai.SearchCategories c
    LEFT JOIN (
        SELECT CategoryId, COUNT_BIG(*) AS DocumentCount
        FROM searchai.SearchDocuments
        GROUP BY CategoryId
    ) doc_counts ON doc_counts.CategoryId = c.CategoryId
    ORDER BY c.DisplayName
    """
)

_LIST_CATEGORIES_WITH_COUNTS_SQLITE = text(
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

_INSERT_CATEGORY = text(
    """
    INSERT INTO searchai.SearchCategories
        (CategoryId, DisplayName, ConfigJson, Status, ConfigVersion, IndexVersion,
         CreatedAtUtc, UpdatedAtUtc, UpdatedBy)
    VALUES
        (:category_id, :display_name, :config_json, :status, 1, 0,
         :created_at_utc, :updated_at_utc, :updated_by)
    """
)

_INSERT_CATEGORY_HISTORY = text(
    """
    INSERT INTO searchai.SearchCategoryHistory
        (CategoryId, ConfigVersion, ConfigJson, Status, ChangedAtUtc,
         ChangedBy, ChangeReason, RolledBackFromVersion)
    VALUES
        (:category_id, :version, :config_json, :status, :changed_at_utc,
         :updated_by, :change_reason, :rolled_back_from_version)
    """
)

_LIST_CATEGORY_HISTORY = text(
    """
    SELECT HistoryId, ConfigVersion, ConfigJson, Status,
           ChangedAtUtc, ChangedBy, ChangeReason, RolledBackFromVersion
    FROM searchai.SearchCategoryHistory
    WHERE CategoryId = :category_id
    ORDER BY ConfigVersion DESC
    """
)

_GET_CATEGORY_HISTORY_VERSION = text(
    """
    SELECT HistoryId, ConfigVersion, ConfigJson, Status,
           ChangedAtUtc, ChangedBy, ChangeReason, RolledBackFromVersion
    FROM searchai.SearchCategoryHistory
    WHERE CategoryId = :category_id AND ConfigVersion = :target_version
    """
)

_UPDATE_CATEGORY = text(
    """
    UPDATE searchai.SearchCategories
    SET DisplayName = :display_name,
        ConfigJson = :config_json,
        Status = :status,
        ConfigVersion = ConfigVersion + 1,
        IndexVersion = IndexVersion + 1,
        UpdatedAtUtc = :updated_at_utc,
        UpdatedBy = :updated_by
    WHERE CategoryId = :category_id AND ConfigVersion = :expected_version
    """
)

_COUNT_CATEGORY_DOCUMENTS = text(
    """
    SELECT COUNT(DocumentId)
    FROM searchai.SearchDocuments
    WHERE CategoryId = :category_id
    """
)

_LIST_FEEDBACK_MSSQL = text(
    """
    SELECT TOP (:limit)
        FeedbackId, QueryText, DocumentId, IsRelevant, Comment, CreatedAtUtc, CreatedBy,
        ResultRank, ResultScore, ConfigVersion, IndexVersion
    FROM searchai.SearchFeedback
    WHERE CategoryId = :category_id
    ORDER BY CreatedAtUtc DESC, FeedbackId DESC
    """
)

_LIST_FEEDBACK_SQLITE = text(
    """
    SELECT
        FeedbackId, QueryText, DocumentId, IsRelevant, Comment, CreatedAtUtc, CreatedBy,
        ResultRank, ResultScore, ConfigVersion, IndexVersion
    FROM searchai.SearchFeedback
    WHERE CategoryId = :category_id
    ORDER BY CreatedAtUtc DESC, FeedbackId DESC
    LIMIT :limit
    """
)

_FEEDBACK_COUNTS_MSSQL = text(
    """
    SELECT
        COUNT_BIG(*) AS TotalCount,
        SUM(CASE WHEN IsRelevant = 1 THEN 1 ELSE 0 END) AS RelevantCount,
        SUM(CASE WHEN IsRelevant = 0 THEN 1 ELSE 0 END) AS NotRelevantCount
    FROM searchai.SearchFeedback
    WHERE CategoryId = :category_id
    """
)

_FEEDBACK_COUNTS_SQLITE = text(
    """
    SELECT
        COUNT(*) AS TotalCount,
        SUM(CASE WHEN IsRelevant = 1 THEN 1 ELSE 0 END) AS RelevantCount,
        SUM(CASE WHEN IsRelevant = 0 THEN 1 ELSE 0 END) AS NotRelevantCount
    FROM searchai.SearchFeedback
    WHERE CategoryId = :category_id
    """
)

_DELETE_DOCUMENTS = text("DELETE FROM searchai.SearchDocuments WHERE CategoryId = :category_id")

_INSERT_DOCUMENT = text(
    """
    INSERT INTO searchai.SearchDocuments
        (CategoryId, DocumentId, Title, FieldsJson, MetadataJson)
    VALUES
        (:category_id, :document_id, :title, :fields_json, :metadata_json)
    """
)

_UPSERT_DOCUMENT_MSSQL = text(
    """
    MERGE searchai.SearchDocuments AS target
    USING (
        SELECT :category_id AS CategoryId,
               :document_id AS DocumentId,
               :title AS Title,
               :fields_json AS FieldsJson,
               :metadata_json AS MetadataJson
    ) AS source
    ON target.CategoryId = source.CategoryId
       AND target.DocumentId = source.DocumentId
    WHEN MATCHED THEN
        UPDATE SET Title = source.Title,
                   FieldsJson = source.FieldsJson,
                   MetadataJson = source.MetadataJson,
                   UpdatedAtUtc = SYSUTCDATETIME()
    WHEN NOT MATCHED THEN
        INSERT (CategoryId, DocumentId, Title, FieldsJson, MetadataJson)
        VALUES (source.CategoryId, source.DocumentId, source.Title,
                source.FieldsJson, source.MetadataJson);
    """
)

_UPSERT_DOCUMENT_SQLITE = text(
    """
    INSERT INTO searchai.SearchDocuments
        (CategoryId, DocumentId, Title, FieldsJson, MetadataJson, UpdatedAtUtc)
    VALUES
        (:category_id, :document_id, :title, :fields_json, :metadata_json, CURRENT_TIMESTAMP)
    ON CONFLICT (CategoryId, DocumentId) DO UPDATE SET
        Title = excluded.Title,
        FieldsJson = excluded.FieldsJson,
        MetadataJson = excluded.MetadataJson,
        UpdatedAtUtc = CURRENT_TIMESTAMP
    """
)

_LIST_DOCUMENTS = text(
    """
    SELECT DocumentId, Title, FieldsJson, MetadataJson
    FROM searchai.SearchDocuments
    WHERE CategoryId = :category_id
    ORDER BY DocumentId
    """
)

_BUMP_INDEX_VERSION = text(
    """
    UPDATE searchai.SearchCategories
    SET IndexVersion = IndexVersion + 1,
        UpdatedAtUtc = :updated_at_utc,
        UpdatedBy = :updated_by
    WHERE CategoryId = :category_id
    """
)


def _category_from_row(row: Any) -> dict[str, Any]:
    config = CategoryConfig.model_validate_json(row["ConfigJson"])
    record: dict[str, Any] = {
        "config": config,
        "status": row["Status"],
        "config_version": int(row["ConfigVersion"]),
        "index_version": int(row["IndexVersion"]),
        "updated_at_utc": row["UpdatedAtUtc"],
        "updated_by": row["UpdatedBy"],
    }
    if "DocumentCount" in row:
        record["document_count"] = int(row["DocumentCount"] or 0)
    return record


def get_category(category_id: str, *, include_document_count: bool = False) -> dict[str, Any]:
    engine = get_platform_engine()
    if include_document_count:
        statement = (
            _GET_CATEGORY_WITH_COUNT_SQLITE
            if is_sqlite_engine(engine)
            else _GET_CATEGORY_WITH_COUNT_MSSQL
        )
    else:
        statement = _GET_CATEGORY
    with engine.connect() as connection:
        row = connection.execute(statement, {"category_id": category_id}).mappings().first()
    if row is None:
        raise CategoryNotFoundError(category_id)
    return _category_from_row(row)


def list_categories(*, include_document_count: bool = True) -> list[dict[str, Any]]:
    engine = get_platform_engine()
    if include_document_count:
        statement = (
            _LIST_CATEGORIES_WITH_COUNTS_SQLITE
            if is_sqlite_engine(engine)
            else _LIST_CATEGORIES_WITH_COUNTS_MSSQL
        )
    else:
        statement = _LIST_CATEGORIES
    with engine.connect() as connection:
        rows = connection.execute(statement).mappings().all()
    return [_category_from_row(row) for row in rows]


def create_category(config: CategoryConfig, *, updated_by: str) -> dict[str, Any]:
    now_utc = _utc_now_naive()
    values = {
        "category_id": config.category_id,
        "display_name": config.display_name,
        "config_json": config.model_dump_json(),
        "status": "active" if config.active else "disabled",
        "created_at_utc": now_utc,
        "updated_at_utc": now_utc,
        "updated_by": updated_by,
    }
    try:
        with get_platform_engine().begin() as connection:
            connection.execute(_INSERT_CATEGORY, values)
            connection.execute(
                _INSERT_CATEGORY_HISTORY,
                {
                    "category_id": config.category_id,
                    "version": 1,
                    "config_json": values["config_json"],
                    "status": values["status"],
                    "changed_at_utc": now_utc,
                    "updated_by": updated_by,
                    "change_reason": "Category created",
                    "rolled_back_from_version": None,
                },
            )
    except Exception as exc:
        err_text = str(exc).lower()
        if "duplicate" in err_text or "unique" in err_text or "2627" in err_text:
            raise CategoryAlreadyExistsError(config.category_id) from exc
        raise CategoryStoreError("Unable to create search category") from exc
    record = get_category(config.category_id)
    record["document_count"] = 0
    return record


def update_category(
    config: CategoryConfig,
    *,
    expected_version: int,
    updated_by: str,
    change_reason: str | None = None,
) -> dict[str, Any]:
    now_utc = _utc_now_naive()
    config_json = config.model_dump_json()
    status = "active" if config.active else "disabled"
    values = {
        "category_id": config.category_id,
        "display_name": config.display_name,
        "config_json": config_json,
        "status": status,
        "expected_version": expected_version,
        "updated_at_utc": now_utc,
        "updated_by": updated_by,
    }
    with get_platform_engine().begin() as connection:
        result = connection.execute(_UPDATE_CATEGORY, values)
        if result.rowcount != 1:
            current = connection.execute(
                text(
                    "SELECT ConfigVersion FROM searchai.SearchCategories "
                    "WHERE CategoryId = :category_id"
                ),
                {"category_id": config.category_id},
            ).scalar_one_or_none()
            if current is None:
                raise CategoryNotFoundError(config.category_id)
            raise CategoryVersionConflictError(
                f"Configuration version conflict; current version is {current}"
            )
        connection.execute(
            _INSERT_CATEGORY_HISTORY,
            {
                "category_id": config.category_id,
                "version": expected_version + 1,
                "config_json": config_json,
                "status": status,
                "changed_at_utc": now_utc,
                "updated_by": updated_by,
                "change_reason": change_reason,
                "rolled_back_from_version": None,
            },
        )
        doc_count = int(
            connection.execute(
                _COUNT_CATEGORY_DOCUMENTS, {"category_id": config.category_id}
            ).scalar_one()
            or 0
        )
    record = get_category(config.category_id)
    record["document_count"] = doc_count
    return record


def rollback_category(
    category_id: str,
    *,
    target_version: int,
    expected_version: int,
    updated_by: str,
    reason: str,
) -> dict[str, Any]:
    """Atomically restore a historical category configuration as a new version.

    - Preserves all current and previous rows in searchai.SearchCategoryHistory.
    - Increments both ConfigVersion and IndexVersion so worker caches refresh.
    - Enforces optimistic concurrency via expected_version.
    - Never invents a default configuration; target_version must exist in history.
    """
    if target_version < 1:
        raise ValueError("target_version must be at least 1")
    if expected_version < 1:
        raise ValueError("expected_version must be at least 1")
    cleaned_reason = (reason or "").strip()
    if not cleaned_reason:
        raise ValueError("Rollback reason is required")

    now_utc = _utc_now_naive()
    audit_reason = f"Rollback to v{target_version}: {cleaned_reason}"[:1000]

    with get_platform_engine().begin() as connection:
        current_row = connection.execute(
            text(
                "SELECT ConfigVersion FROM searchai.SearchCategories "
                "WHERE CategoryId = :category_id"
            ),
            {"category_id": category_id},
        ).mappings().first()
        if current_row is None:
            raise CategoryNotFoundError(category_id)

        current_version = int(current_row["ConfigVersion"])
        if current_version != expected_version:
            raise CategoryVersionConflictError(
                f"Configuration version conflict; current version is {current_version}"
            )

        history_row = connection.execute(
            _GET_CATEGORY_HISTORY_VERSION,
            {"category_id": category_id, "target_version": target_version},
        ).mappings().first()
        if history_row is None:
            raise CategoryHistoryNotFoundError(
                f"Historical configuration version {target_version} was not found for category '{category_id}'"
            )

        if target_version == current_version:
            raise CategoryVersionConflictError(
                f"Target version {target_version} is already the active configuration version"
            )

        try:
            restored_config = CategoryConfig.model_validate_json(history_row["ConfigJson"])
        except Exception as exc:
            raise CategoryStoreError(
                f"Historical configuration version {target_version} failed validation"
            ) from exc

        if restored_config.category_id != category_id:
            raise CategoryStoreError(
                "Historical configuration category_id does not match target category"
            )

        restored_json = restored_config.model_dump_json()
        restored_status = "active" if restored_config.active else "disabled"
        new_version = expected_version + 1

        update_result = connection.execute(
            _UPDATE_CATEGORY,
            {
                "category_id": category_id,
                "display_name": restored_config.display_name,
                "config_json": restored_json,
                "status": restored_status,
                "expected_version": expected_version,
                "updated_at_utc": now_utc,
                "updated_by": updated_by,
            },
        )
        if update_result.rowcount != 1:
            latest = connection.execute(
                text(
                    "SELECT ConfigVersion FROM searchai.SearchCategories "
                    "WHERE CategoryId = :category_id"
                ),
                {"category_id": category_id},
            ).scalar_one_or_none()
            if latest is None:
                raise CategoryNotFoundError(category_id)
            raise CategoryVersionConflictError(
                f"Configuration version conflict; current version is {latest}"
            )

        connection.execute(
            _INSERT_CATEGORY_HISTORY,
            {
                "category_id": category_id,
                "version": new_version,
                "config_json": restored_json,
                "status": restored_status,
                "changed_at_utc": now_utc,
                "updated_by": updated_by,
                "change_reason": audit_reason,
                "rolled_back_from_version": target_version,
            },
        )

        doc_count = int(
            connection.execute(
                _COUNT_CATEGORY_DOCUMENTS, {"category_id": category_id}
            ).scalar_one()
            or 0
        )

    record = get_category(category_id)
    record["document_count"] = doc_count
    record["rolled_back_from_version"] = target_version
    record["previous_config_version"] = expected_version
    record["rollback_reason"] = cleaned_reason
    return record


def get_category_history(category_id: str) -> list[dict[str, Any]]:
    get_category(category_id)
    with get_platform_engine().connect() as connection:
        rows = connection.execute(
            _LIST_CATEGORY_HISTORY, {"category_id": category_id}
        ).mappings().all()
    return [
        {
            "history_id": int(row["HistoryId"]),
            "config_version": int(row["ConfigVersion"]),
            "config": CategoryConfig.model_validate_json(row["ConfigJson"]),
            "status": row["Status"],
            "changed_at_utc": row["ChangedAtUtc"],
            "changed_by": row["ChangedBy"],
            "change_reason": row["ChangeReason"],
            "rolled_back_from_version": (
                int(row["RolledBackFromVersion"])
                if row.get("RolledBackFromVersion") is not None
                else None
            ),
        }
        for row in rows
    ]


def get_feedback(category_id: str, *, limit: int = 100) -> dict[str, Any]:
    """Read-only retrieval of historical feedback judgments for one category."""
    get_category(category_id)
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    engine = get_platform_engine()
    list_stmt = _LIST_FEEDBACK_SQLITE if is_sqlite_engine(engine) else _LIST_FEEDBACK_MSSQL
    counts_stmt = _FEEDBACK_COUNTS_SQLITE if is_sqlite_engine(engine) else _FEEDBACK_COUNTS_MSSQL

    with engine.connect() as connection:
        rows = connection.execute(list_stmt, {"category_id": category_id, "limit": limit}).mappings().all()
        counts = connection.execute(counts_stmt, {"category_id": category_id}).mappings().one()
    return {
        "total_count": int(counts["TotalCount"] or 0),
        "relevant_count": int(counts["RelevantCount"] or 0),
        "not_relevant_count": int(counts["NotRelevantCount"] or 0),
        "items": [
            {
                "feedback_id": int(row["FeedbackId"]),
                "query": row["QueryText"],
                "document_id": row["DocumentId"],
                "is_relevant": bool(row["IsRelevant"]),
                "comment": row["Comment"],
                "created_at_utc": row["CreatedAtUtc"],
                "created_by": row["CreatedBy"],
                "result_rank": int(row["ResultRank"]) if row["ResultRank"] is not None else None,
                "result_score": float(row["ResultScore"]) if row["ResultScore"] is not None else None,
                "config_version": int(row["ConfigVersion"]) if row["ConfigVersion"] is not None else None,
                "index_version": int(row["IndexVersion"]) if row["IndexVersion"] is not None else None,
            }
            for row in rows
        ],
    }


def list_documents(category_id: str) -> list[dict[str, Any]]:
    with get_platform_engine().connect() as connection:
        rows = connection.execute(_LIST_DOCUMENTS, {"category_id": category_id}).mappings().all()
    documents: list[dict[str, Any]] = []
    for row in rows:
        documents.append(
            {
                "document_id": str(row["DocumentId"]),
                "title": row["Title"] or "",
                "fields": json.loads(row["FieldsJson"]),
                "metadata": json.loads(row["MetadataJson"]),
            }
        )
    return documents


def replace_documents(
    category_id: str,
    documents: list[SearchDocument],
    *,
    updated_by: str,
    replace_all: bool = False,
) -> int:
    """Upsert documents (or replace the full snapshot) and bump index version."""
    if not documents:
        raise ValueError("At least one document is required")
    ids = [doc.document_id for doc in documents]
    if len(ids) != len(set(ids)):
        raise ValueError("Document IDs must be unique in one ingestion batch")

    engine = get_platform_engine()
    upsert_stmt = _UPSERT_DOCUMENT_SQLITE if is_sqlite_engine(engine) else _UPSERT_DOCUMENT_MSSQL
    statement = _INSERT_DOCUMENT if replace_all else upsert_stmt

    with engine.begin() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM searchai.SearchCategories WHERE CategoryId = :category_id"),
            {"category_id": category_id},
        ).first()
        if exists is None:
            raise CategoryNotFoundError(category_id)

        if replace_all:
            connection.execute(_DELETE_DOCUMENTS, {"category_id": category_id})
        connection.execute(
            statement,
            [
                {
                    "category_id": category_id,
                    "document_id": doc.document_id,
                    "title": doc.title,
                    "fields_json": json.dumps(doc.fields, ensure_ascii=False),
                    "metadata_json": json.dumps(doc.metadata, ensure_ascii=False),
                }
                for doc in documents
            ],
        )
        connection.execute(
            _BUMP_INDEX_VERSION,
            {
                "category_id": category_id,
                "updated_at_utc": _utc_now_naive(),
                "updated_by": updated_by,
            },
        )
    return len(documents)
