/*
    General Search Platform Reference Schema (SQL Server)
    =========================================================================
    Owned exclusively by Search_Admin (BONC General Search Platform).

    IMPORTANT SAFETY NOTICE:
    - This script is a REFERENCE schema definition for provisioning a new
      local, staging, or approved dedicated General Search Platform SQL Server
      database.
    - DO NOT run this script blindly against production without DBA review,
      explicit environment verification, and change-management approval.
    - This schema owns ONLY the six ``searchai.*`` tables listed below:
        1. searchai.SearchCategories
        2. searchai.SearchCategoryHistory  (including RolledBackFromVersion)
        3. searchai.SearchDocuments
        4. searchai.SearchFeedback         (including ranking snapshot columns)
        5. searchai.SearchLogs
        6. searchai.ApiRequestLogs
    - Intentionally EXCLUDED:
        - Legacy Product & Company Search tables (dbo.Company, dbo.Products,
          dbo.ProductsAndServices, dbo.B2BCompanies, dbo.B2BProducts)
        - BrochureIQ tables (dbo.Brochures)
        - Retired legacy Catalog Thresholds tables (searchai.SearchAISettings)
        - Admin authentication tables (authentication is owned externally by
          BONC JWT via .NET getUserDetail; Search_Admin stores no local user or
          session tables)
*/
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;

BEGIN TRY
    BEGIN TRANSACTION;

    IF SCHEMA_ID(N'searchai') IS NULL
    BEGIN
        EXECUTE (N'CREATE SCHEMA [searchai] AUTHORIZATION [dbo];');
    END;

    -- 1. Configurable Search Categories (Engines)
    IF OBJECT_ID(N'searchai.SearchCategories', N'U') IS NULL
    BEGIN
        CREATE TABLE searchai.SearchCategories (
            CategoryId       NVARCHAR(64)  NOT NULL,
            DisplayName      NVARCHAR(120) NOT NULL,
            ConfigJson       NVARCHAR(MAX) NOT NULL,
            Status           NVARCHAR(20)  NOT NULL CONSTRAINT DF_SearchCategories_Status DEFAULT N'disabled',
            ConfigVersion    INT           NOT NULL CONSTRAINT DF_SearchCategories_ConfigVersion DEFAULT 1,
            IndexVersion     INT           NOT NULL CONSTRAINT DF_SearchCategories_IndexVersion DEFAULT 0,
            CreatedAtUtc     DATETIME2(3)  NOT NULL CONSTRAINT DF_SearchCategories_CreatedAtUtc DEFAULT SYSUTCDATETIME(),
            UpdatedAtUtc     DATETIME2(3)  NOT NULL CONSTRAINT DF_SearchCategories_UpdatedAtUtc DEFAULT SYSUTCDATETIME(),
            UpdatedBy        NVARCHAR(256) NOT NULL,
            CONSTRAINT PK_SearchCategories PRIMARY KEY (CategoryId),
            CONSTRAINT CK_SearchCategories_Status CHECK (Status IN (N'active', N'disabled')),
            CONSTRAINT CK_SearchCategories_ConfigVersion CHECK (ConfigVersion >= 1),
            CONSTRAINT CK_SearchCategories_IndexVersion CHECK (IndexVersion >= 0),
            CONSTRAINT CK_SearchCategories_ConfigJson CHECK (ISJSON(ConfigJson) = 1)
        );
    END;

    -- 2. Immutable Category Configuration History & Rollback Provenance
    IF OBJECT_ID(N'searchai.SearchCategoryHistory', N'U') IS NULL
    BEGIN
        CREATE TABLE searchai.SearchCategoryHistory (
            HistoryId             BIGINT IDENTITY(1,1) NOT NULL,
            CategoryId            NVARCHAR(64)         NOT NULL,
            ConfigVersion         INT                  NOT NULL,
            ConfigJson            NVARCHAR(MAX)        NOT NULL,
            Status                NVARCHAR(20)         NOT NULL,
            ChangedAtUtc          DATETIME2(3)         NOT NULL CONSTRAINT DF_SearchCategoryHistory_ChangedAtUtc DEFAULT SYSUTCDATETIME(),
            ChangedBy             NVARCHAR(256)        NOT NULL,
            ChangeReason          NVARCHAR(1000)       NULL,
            RolledBackFromVersion INT                  NULL,
            CONSTRAINT PK_SearchCategoryHistory PRIMARY KEY (HistoryId),
            CONSTRAINT FK_SearchCategoryHistory_Category FOREIGN KEY (CategoryId)
                REFERENCES searchai.SearchCategories(CategoryId) ON DELETE CASCADE,
            CONSTRAINT UQ_SearchCategoryHistory_Version UNIQUE (CategoryId, ConfigVersion),
            CONSTRAINT CK_SearchCategoryHistory_ConfigJson CHECK (ISJSON(ConfigJson) = 1),
            CONSTRAINT CK_SearchCategoryHistory_RolledBackFromVersion CHECK (
                RolledBackFromVersion IS NULL OR RolledBackFromVersion >= 1
            )
        );
    END;

    -- 3. Normalized Searchable Documents
    IF OBJECT_ID(N'searchai.SearchDocuments', N'U') IS NULL
    BEGIN
        CREATE TABLE searchai.SearchDocuments (
            CategoryId   NVARCHAR(64)   NOT NULL,
            DocumentId   NVARCHAR(200)  NOT NULL,
            Title        NVARCHAR(1000) NOT NULL CONSTRAINT DF_SearchDocuments_Title DEFAULT N'',
            FieldsJson   NVARCHAR(MAX)  NOT NULL,
            MetadataJson NVARCHAR(MAX)  NOT NULL CONSTRAINT DF_SearchDocuments_Metadata DEFAULT N'{}',
            CreatedAtUtc DATETIME2(3)   NOT NULL CONSTRAINT DF_SearchDocuments_CreatedAtUtc DEFAULT SYSUTCDATETIME(),
            UpdatedAtUtc DATETIME2(3)   NOT NULL CONSTRAINT DF_SearchDocuments_UpdatedAtUtc DEFAULT SYSUTCDATETIME(),
            CONSTRAINT PK_SearchDocuments PRIMARY KEY (CategoryId, DocumentId),
            CONSTRAINT FK_SearchDocuments_Category FOREIGN KEY (CategoryId)
                REFERENCES searchai.SearchCategories(CategoryId) ON DELETE CASCADE,
            CONSTRAINT CK_SearchDocuments_FieldsJson CHECK (ISJSON(FieldsJson) = 1),
            CONSTRAINT CK_SearchDocuments_MetadataJson CHECK (ISJSON(MetadataJson) = 1)
        );
        CREATE INDEX IX_SearchDocuments_Category ON searchai.SearchDocuments(CategoryId);
    END;

    -- 4. Historical Relevance Feedback (read-only analytics in Search_Admin)
    IF OBJECT_ID(N'searchai.SearchFeedback', N'U') IS NULL
    BEGIN
        CREATE TABLE searchai.SearchFeedback (
            FeedbackId    BIGINT IDENTITY(1,1) NOT NULL,
            CategoryId    NVARCHAR(64)         NOT NULL,
            QueryText     NVARCHAR(500)        NOT NULL,
            DocumentId    NVARCHAR(200)        NOT NULL,
            IsRelevant    BIT                  NOT NULL,
            Comment       NVARCHAR(1000)       NULL,
            CreatedAtUtc  DATETIME2(3)         NOT NULL CONSTRAINT DF_SearchFeedback_CreatedAtUtc DEFAULT SYSUTCDATETIME(),
            CreatedBy     NVARCHAR(256)        NOT NULL,
            ResultRank    INT                  NULL,
            ResultScore   FLOAT(53)            NULL,
            ConfigVersion INT                  NULL,
            IndexVersion  INT                  NULL,
            CONSTRAINT PK_SearchFeedback PRIMARY KEY (FeedbackId),
            CONSTRAINT FK_SearchFeedback_Category FOREIGN KEY (CategoryId)
                REFERENCES searchai.SearchCategories(CategoryId) ON DELETE CASCADE,
            CONSTRAINT CK_SearchFeedback_ResultRank CHECK (ResultRank IS NULL OR ResultRank BETWEEN 1 AND 100),
            CONSTRAINT CK_SearchFeedback_ResultScore CHECK (ResultScore IS NULL OR (ResultScore >= 0 AND ResultScore <= 100)),
            CONSTRAINT CK_SearchFeedback_ConfigVersion CHECK (ConfigVersion IS NULL OR ConfigVersion >= 1),
            CONSTRAINT CK_SearchFeedback_IndexVersion CHECK (IndexVersion IS NULL OR IndexVersion >= 0)
        );
        CREATE INDEX IX_SearchFeedback_Category_Created
            ON searchai.SearchFeedback(CategoryId, CreatedAtUtc DESC);
        CREATE INDEX IX_SearchFeedback_CreatedAt_IsRelevant
            ON searchai.SearchFeedback(CreatedAtUtc DESC, IsRelevant)
            INCLUDE (CategoryId, QueryText, DocumentId);
        CREATE INDEX IX_SearchFeedback_NotRelevant_CreatedAt
            ON searchai.SearchFeedback(CreatedAtUtc DESC, FeedbackId DESC)
            INCLUDE (CategoryId, QueryText, DocumentId, Comment, CreatedBy)
            WHERE IsRelevant = 0;
    END;

    -- 5. Persistent Search Execution Logs
    IF OBJECT_ID(N'searchai.SearchLogs', N'U') IS NULL
    BEGIN
        CREATE TABLE searchai.SearchLogs (
            SearchLogId         BIGINT IDENTITY(1,1) NOT NULL,
            OccurredAtUtc       DATETIME2(3)         NOT NULL CONSTRAINT DF_SearchLogs_OccurredAtUtc DEFAULT SYSUTCDATETIME(),
            RequestId           NVARCHAR(64)         NOT NULL,
            EndpointPath        NVARCHAR(128)        NOT NULL,
            SearchSurface       NVARCHAR(16)         NOT NULL,
            CategoryId          NVARCHAR(64)         NOT NULL,
            ResolvedCategoryId  NVARCHAR(64)         NULL,
            QueryText           NVARCHAR(500)        NOT NULL,
            NormalizedQuery     NVARCHAR(500)        NOT NULL,
            AuthenticatedUserId NVARCHAR(256)        NULL,
            IdentityType        NVARCHAR(32)         NOT NULL CONSTRAINT DF_SearchLogs_IdentityType DEFAULT N'anonymous',
            SessionIdHash       NVARCHAR(64)         NULL,
            HttpStatus          SMALLINT             NOT NULL,
            Outcome             NVARCHAR(32)         NOT NULL,
            ResultCount         INT                  NULL,
            PageNo              INT                  NOT NULL CONSTRAINT DF_SearchLogs_PageNo DEFAULT 1,
            PageSize            INT                  NOT NULL CONSTRAINT DF_SearchLogs_PageSize DEFAULT 10,
            FilterCount         INT                  NOT NULL CONSTRAINT DF_SearchLogs_FilterCount DEFAULT 0,
            DurationMs          FLOAT(53)            NOT NULL,
            ConfigVersion       INT                  NULL,
            IndexVersion        INT                  NULL,
            ErrorCode           NVARCHAR(64)         NULL,
            ErrorCategory       NVARCHAR(32)         NULL,
            CONSTRAINT PK_SearchLogs PRIMARY KEY CLUSTERED (SearchLogId),
            CONSTRAINT FK_SearchLogs_ResolvedCategory FOREIGN KEY (ResolvedCategoryId)
                REFERENCES searchai.SearchCategories(CategoryId) ON DELETE SET NULL,
            CONSTRAINT CK_SearchLogs_SearchSurface CHECK (SearchSurface IN (N'public', N'admin')),
            CONSTRAINT CK_SearchLogs_IdentityType CHECK (IdentityType IN (N'authenticated', N'anonymous', N'session')),
            CONSTRAINT CK_SearchLogs_IdentityConsistency CHECK (
                (IdentityType = N'authenticated' AND AuthenticatedUserId IS NOT NULL)
                OR (IdentityType IN (N'anonymous', N'session') AND AuthenticatedUserId IS NULL)
            ),
            CONSTRAINT CK_SearchLogs_HttpStatus CHECK (HttpStatus BETWEEN 100 AND 599),
            CONSTRAINT CK_SearchLogs_Outcome CHECK (Outcome IN (N'success', N'zero_results', N'client_error', N'server_error')),
            CONSTRAINT CK_SearchLogs_ResultCount CHECK (ResultCount IS NULL OR ResultCount >= 0),
            CONSTRAINT CK_SearchLogs_PageNo CHECK (PageNo >= 1),
            CONSTRAINT CK_SearchLogs_PageSize CHECK (PageSize BETWEEN 1 AND 100),
            CONSTRAINT CK_SearchLogs_FilterCount CHECK (FilterCount >= 0),
            CONSTRAINT CK_SearchLogs_DurationMs CHECK (DurationMs >= 0),
            CONSTRAINT CK_SearchLogs_ConfigVersion CHECK (ConfigVersion IS NULL OR ConfigVersion >= 1),
            CONSTRAINT CK_SearchLogs_IndexVersion CHECK (IndexVersion IS NULL OR IndexVersion >= 0),
            CONSTRAINT CK_SearchLogs_ErrorCategory CHECK (
                ErrorCategory IS NULL
                OR ErrorCategory IN (N'validation', N'auth', N'not_found', N'forbidden', N'server_error', N'dependency_error')
            )
        );
        CREATE INDEX IX_SearchLogs_OccurredAtUtc
            ON searchai.SearchLogs(OccurredAtUtc DESC, SearchLogId DESC)
            INCLUDE (CategoryId, IdentityType, AuthenticatedUserId, HttpStatus, Outcome, ResultCount, DurationMs);
        CREATE INDEX IX_SearchLogs_Category_OccurredAtUtc
            ON searchai.SearchLogs(CategoryId, OccurredAtUtc DESC)
            INCLUDE (IdentityType, AuthenticatedUserId, HttpStatus, Outcome, ResultCount, DurationMs);
        CREATE INDEX IX_SearchLogs_User_OccurredAtUtc
            ON searchai.SearchLogs(AuthenticatedUserId, OccurredAtUtc DESC)
            INCLUDE (CategoryId, HttpStatus, Outcome, DurationMs)
            WHERE AuthenticatedUserId IS NOT NULL;
        CREATE INDEX IX_SearchLogs_Outcome_OccurredAtUtc
            ON searchai.SearchLogs(Outcome, OccurredAtUtc DESC)
            INCLUDE (CategoryId, HttpStatus, ResultCount, AuthenticatedUserId);
        CREATE INDEX IX_SearchLogs_HttpStatus_OccurredAtUtc
            ON searchai.SearchLogs(HttpStatus, OccurredAtUtc DESC);
        CREATE INDEX IX_SearchLogs_RequestId
            ON searchai.SearchLogs(RequestId);
        CREATE INDEX IX_SearchLogs_ResolvedCategoryId
            ON searchai.SearchLogs(ResolvedCategoryId)
            WHERE ResolvedCategoryId IS NOT NULL;
    END;

    -- 6. Persistent API Request & 5xx Failure Telemetry
    IF OBJECT_ID(N'searchai.ApiRequestLogs', N'U') IS NULL
    BEGIN
        CREATE TABLE searchai.ApiRequestLogs (
            RequestLogId        BIGINT IDENTITY(1,1) NOT NULL,
            OccurredAtUtc       DATETIME2(3)         NOT NULL CONSTRAINT DF_ApiRequestLogs_OccurredAtUtc DEFAULT SYSUTCDATETIME(),
            RequestId           NVARCHAR(64)         NOT NULL,
            HttpMethod          NVARCHAR(16)         NOT NULL,
            EndpointTemplate    NVARCHAR(200)        NOT NULL,
            HttpStatus          SMALLINT             NOT NULL,
            StatusClass         NVARCHAR(8)          NOT NULL,
            IsServerFailure     BIT                  NOT NULL CONSTRAINT DF_ApiRequestLogs_IsServerFailure DEFAULT 0,
            IsClientError       BIT                  NOT NULL CONSTRAINT DF_ApiRequestLogs_IsClientError DEFAULT 0,
            DurationMs          FLOAT(53)            NOT NULL,
            AuthenticatedUserId NVARCHAR(256)        NULL,
            IdentityType        NVARCHAR(32)         NOT NULL CONSTRAINT DF_ApiRequestLogs_IdentityType DEFAULT N'anonymous',
            ErrorCode           NVARCHAR(64)         NULL,
            ErrorSummary        NVARCHAR(256)        NULL,
            CONSTRAINT PK_ApiRequestLogs PRIMARY KEY CLUSTERED (RequestLogId),
            CONSTRAINT CK_ApiRequestLogs_HttpStatus CHECK (HttpStatus BETWEEN 100 AND 599),
            CONSTRAINT CK_ApiRequestLogs_StatusClass CHECK (StatusClass IN (N'1xx', N'2xx', N'3xx', N'4xx', N'5xx')),
            CONSTRAINT CK_ApiRequestLogs_ServerFailureMatch CHECK (
                (HttpStatus >= 500 AND IsServerFailure = 1)
                OR (HttpStatus < 500 AND IsServerFailure = 0)
            ),
            CONSTRAINT CK_ApiRequestLogs_ClientErrorMatch CHECK (
                (HttpStatus BETWEEN 400 AND 499 AND IsClientError = 1)
                OR (HttpStatus NOT BETWEEN 400 AND 499 AND IsClientError = 0)
            ),
            CONSTRAINT CK_ApiRequestLogs_DurationMs CHECK (DurationMs >= 0),
            CONSTRAINT CK_ApiRequestLogs_IdentityType CHECK (IdentityType IN (N'authenticated', N'anonymous', N'session')),
            CONSTRAINT CK_ApiRequestLogs_IdentityConsistency CHECK (
                (IdentityType = N'authenticated' AND AuthenticatedUserId IS NOT NULL)
                OR (IdentityType IN (N'anonymous', N'session') AND AuthenticatedUserId IS NULL)
            )
        );
        CREATE INDEX IX_ApiRequestLogs_OccurredAtUtc
            ON searchai.ApiRequestLogs(OccurredAtUtc DESC, RequestLogId DESC)
            INCLUDE (EndpointTemplate, HttpStatus, StatusClass, IsServerFailure, IsClientError, DurationMs);
        CREATE INDEX IX_ApiRequestLogs_Endpoint_OccurredAtUtc
            ON searchai.ApiRequestLogs(EndpointTemplate, OccurredAtUtc DESC)
            INCLUDE (HttpStatus, IsServerFailure, IsClientError, DurationMs, ErrorCode);
        CREATE INDEX IX_ApiRequestLogs_ServerFailure_OccurredAtUtc
            ON searchai.ApiRequestLogs(OccurredAtUtc DESC, RequestLogId DESC)
            INCLUDE (RequestId, HttpMethod, EndpointTemplate, HttpStatus, DurationMs, ErrorCode, ErrorSummary)
            WHERE IsServerFailure = 1;
        CREATE INDEX IX_ApiRequestLogs_RequestId
            ON searchai.ApiRequestLogs(RequestId);
    END;

    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0 ROLLBACK;
    THROW;
END CATCH;
