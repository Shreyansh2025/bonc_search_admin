import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import {
  getSearchLogs,
  getSearchLogsByUser,
  type PlatformCategoryRecord,
  type SearchIdentityType,
  type SearchLogOutcome,
  type SearchLogsResponse,
  type SearchLogUsersResponse,
  type SearchStatusClass,
  type SearchSurfaceType,
} from "../lib/search-api";

export interface SearchLogsPanelProps {
  categories: PlatformCategoryRecord[];
  initialCategory?: string;
  initialFailedOnly?: boolean;
}

type LogsSubView = "history" | "users";

interface HistoryFilterState {
  startUtc: string;
  endUtc: string;
  userId: string;
  category: string;
  query: string;
  identityType: SearchIdentityType | "";
  statusCode: string;
  statusClass: SearchStatusClass | "";
  outcome: SearchLogOutcome | "";
  zeroResultsOnly: boolean;
  failedOnly: boolean;
  surface: SearchSurfaceType | "";
}

interface UserFilterState {
  startUtc: string;
  endUtc: string;
  category: string;
  userId: string;
}

const EMPTY_HISTORY_FILTERS: HistoryFilterState = {
  startUtc: "",
  endUtc: "",
  userId: "",
  category: "",
  query: "",
  identityType: "",
  statusCode: "",
  statusClass: "",
  outcome: "",
  zeroResultsOnly: false,
  failedOnly: false,
  surface: "",
};

const EMPTY_USER_FILTERS: UserFilterState = {
  startUtc: "",
  endUtc: "",
  category: "",
  userId: "",
};

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatMs(value?: number | null): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return `${value.toFixed(1)} ms`;
}

function outcomeBadgeClass(outcome: string): string {
  switch (outcome) {
    case "success":
      return "badge-ok";
    case "zero_results":
      return "badge-warn";
    case "client_error":
      return "badge-warn";
    case "server_error":
      return "badge-danger";
    default:
      return "badge-muted";
  }
}

function outcomeLabel(outcome: string): string {
  switch (outcome) {
    case "success":
      return "Success";
    case "zero_results":
      return "Zero Results";
    case "client_error":
      return "Client Error";
    case "server_error":
      return "Server Error";
    default:
      return outcome;
  }
}

function statusBadgeClass(status: number): string {
  if (status >= 200 && status < 300) return "badge-ok";
  if (status >= 400 && status < 500) return "badge-warn";
  if (status >= 500) return "badge-danger";
  return "badge-muted";
}

function identityBadgeClass(identityType: string): string {
  if (identityType === "authenticated") return "badge-info";
  if (identityType === "session") return "badge-warn";
  return "badge-muted";
}

export default function SearchLogsPanel({
  categories,
  initialCategory = "",
  initialFailedOnly = false,
}: SearchLogsPanelProps) {
  const [subView, setSubView] = useState<LogsSubView>("history");

  // Search History state
  const [draftFilters, setDraftFilters] = useState<HistoryFilterState>(() => ({
    ...EMPTY_HISTORY_FILTERS,
    category: initialCategory,
    failedOnly: initialFailedOnly,
  }));
  const [appliedFilters, setAppliedFilters] = useState<HistoryFilterState>(() => ({
    ...EMPTY_HISTORY_FILTERS,
    category: initialCategory,
    failedOnly: initialFailedOnly,
  }));
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPageSize, setHistoryPageSize] = useState(25);
  const [logsResponse, setLogsResponse] = useState<SearchLogsResponse | null>(null);
  const [logsLoading, setLogsLoading] = useState(true);
  const [logsError, setLogsError] = useState("");
  const [validationError, setValidationError] = useState("");

  // Per-User Activity state
  const [draftUserFilters, setDraftUserFilters] = useState<UserFilterState>(() => ({
    ...EMPTY_USER_FILTERS,
    category: initialCategory,
  }));
  const [appliedUserFilters, setAppliedUserFilters] = useState<UserFilterState>(() => ({
    ...EMPTY_USER_FILTERS,
    category: initialCategory,
  }));
  const [usersPage, setUsersPage] = useState(1);
  const [usersPageSize, setUsersPageSize] = useState(25);
  const [usersResponse, setUsersResponse] = useState<SearchLogUsersResponse | null>(null);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState("");
  const [userValidationError, setUserValidationError] = useState("");

  useEffect(() => {
    if (initialCategory || initialFailedOnly) {
      const next: HistoryFilterState = {
        ...EMPTY_HISTORY_FILTERS,
        category: initialCategory,
        failedOnly: initialFailedOnly,
      };
      setDraftFilters(next);
      setAppliedFilters(next);
      setHistoryPage(1);
      setDraftUserFilters((prev) => ({ ...prev, category: initialCategory }));
      setAppliedUserFilters((prev) => ({ ...prev, category: initialCategory }));
      setUsersPage(1);
    }
  }, [initialCategory, initialFailedOnly]);

  const loadSearchLogs = useCallback(async () => {
    setLogsLoading(true);
    setLogsError("");
    try {
      const parsedStatus = appliedFilters.statusCode.trim()
        ? Number(appliedFilters.statusCode.trim())
        : null;
      const result = await getSearchLogs({
        page: historyPage,
        page_size: historyPageSize,
        start_utc: appliedFilters.startUtc || undefined,
        end_utc: appliedFilters.endUtc || undefined,
        user_id: appliedFilters.userId || undefined,
        category: appliedFilters.category || undefined,
        query: appliedFilters.query || undefined,
        identity_type: appliedFilters.identityType || undefined,
        status_code: parsedStatus,
        status_class: appliedFilters.statusClass || undefined,
        outcome: appliedFilters.outcome || undefined,
        zero_results_only: appliedFilters.zeroResultsOnly,
        failed_only: appliedFilters.failedOnly,
        surface: appliedFilters.surface || undefined,
      });
      setLogsResponse(result);
    } catch (error) {
      setLogsResponse(null);
      setLogsError(
        error instanceof Error ? error.message : "Unable to load search logs.",
      );
    } finally {
      setLogsLoading(false);
    }
  }, [appliedFilters, historyPage, historyPageSize]);

  const loadUserActivity = useCallback(async () => {
    setUsersLoading(true);
    setUsersError("");
    try {
      const result = await getSearchLogsByUser({
        page: usersPage,
        page_size: usersPageSize,
        start_utc: appliedUserFilters.startUtc || undefined,
        end_utc: appliedUserFilters.endUtc || undefined,
        category: appliedUserFilters.category || undefined,
        user_id: appliedUserFilters.userId || undefined,
      });
      setUsersResponse(result);
    } catch (error) {
      setUsersResponse(null);
      setUsersError(
        error instanceof Error ? error.message : "Unable to load per-user search activity.",
      );
    } finally {
      setUsersLoading(false);
    }
  }, [appliedUserFilters, usersPage, usersPageSize]);

  useEffect(() => {
    if (subView === "history") {
      void loadSearchLogs();
    } else {
      void loadUserActivity();
    }
  }, [loadSearchLogs, loadUserActivity, subView]);

  const applyHistoryFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setValidationError("");
    if (draftFilters.startUtc && draftFilters.endUtc && draftFilters.startUtc > draftFilters.endUtc) {
      setValidationError("Start date must be earlier than or equal to end date.");
      return;
    }
    if (draftFilters.statusCode.trim()) {
      const code = Number(draftFilters.statusCode.trim());
      if (!Number.isInteger(code) || code < 100 || code > 599) {
        setValidationError("HTTP status code must be an integer between 100 and 599.");
        return;
      }
    }
    setHistoryPage(1);
    setAppliedFilters({ ...draftFilters });
  };

  const resetHistoryFilters = () => {
    setValidationError("");
    setDraftFilters(EMPTY_HISTORY_FILTERS);
    setAppliedFilters(EMPTY_HISTORY_FILTERS);
    setHistoryPage(1);
  };

  const applyUserFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setUserValidationError("");
    if (
      draftUserFilters.startUtc &&
      draftUserFilters.endUtc &&
      draftUserFilters.startUtc > draftUserFilters.endUtc
    ) {
      setUserValidationError("Start date must be earlier than or equal to end date.");
      return;
    }
    setUsersPage(1);
    setAppliedUserFilters({ ...draftUserFilters });
  };

  const resetUserFilters = () => {
    setUserValidationError("");
    setDraftUserFilters(EMPTY_USER_FILTERS);
    setAppliedUserFilters(EMPTY_USER_FILTERS);
    setUsersPage(1);
  };

  const jumpToUserLogs = (userId: string) => {
    const nextFilters: HistoryFilterState = {
      ...EMPTY_HISTORY_FILTERS,
      startUtc: appliedUserFilters.startUtc,
      endUtc: appliedUserFilters.endUtc,
      category: appliedUserFilters.category,
      userId,
      identityType: "authenticated",
    };
    setDraftFilters(nextFilters);
    setAppliedFilters(nextFilters);
    setHistoryPage(1);
    setSubView("history");
  };

  const historyTotalPages = logsResponse?.pagination.total_pages ?? 0;
  const usersTotalPages = usersResponse?.pagination.total_pages ?? 0;

  return (
    <div className="ops-stack">
      <div className="sub-tabs" role="tablist" aria-label="Search Logs Views">
        <button
          type="button"
          role="tab"
          aria-selected={subView === "history"}
          className={`sub-tab ${subView === "history" ? "active" : ""}`}
          onClick={() => setSubView("history")}
        >
          Search History
          {logsResponse ? ` (${logsResponse.pagination.total_count.toLocaleString()})` : ""}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subView === "users"}
          className={`sub-tab ${subView === "users" ? "active" : ""}`}
          onClick={() => setSubView("users")}
        >
          Per-User Activity
          {usersResponse
            ? ` (${usersResponse.pagination.total_count.toLocaleString()} users)`
            : ""}
        </button>
      </div>

      {subView === "history" && (
        <>
          <section className="panel ops-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">PERSISTENT SEARCH LOGS</span>
                <h2>Filter Search History</h2>
              </div>
              <div className="inline-pills">
                <span className="method-badge">GET · /api/admin/platform/search-logs</span>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => void loadSearchLogs()}
                  disabled={logsLoading}
                >
                  {logsLoading ? "Refreshing…" : "↻ Refresh"}
                </button>
              </div>
            </div>

            {validationError && (
              <div className="inline-error" style={{ marginTop: 12 }}>
                <strong>Invalid filter</strong>
                <span>{validationError}</span>
              </div>
            )}

            <form onSubmit={applyHistoryFilters} style={{ marginTop: 14 }}>
              <div className="logs-filter-grid">
                <label className="setting-field">
                  <span>Start Date (UTC)</span>
                  <input
                    type="date"
                    value={draftFilters.startUtc}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({ ...prev, startUtc: e.target.value }))
                    }
                  />
                </label>

                <label className="setting-field">
                  <span>End Date (UTC)</span>
                  <input
                    type="date"
                    value={draftFilters.endUtc}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({ ...prev, endUtc: e.target.value }))
                    }
                  />
                </label>

                <label className="setting-field">
                  <span>Query Contains</span>
                  <input
                    type="text"
                    value={draftFilters.query}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({ ...prev, query: e.target.value }))
                    }
                    placeholder="e.g. python developer"
                  />
                </label>

                <label className="setting-field">
                  <span>Category</span>
                  <select
                    value={draftFilters.category}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({ ...prev, category: e.target.value }))
                    }
                  >
                    <option value="">All categories</option>
                    {categories.map((cat) => (
                      <option key={cat.config.category_id} value={cat.config.category_id}>
                        {cat.config.display_name} ({cat.config.category_id})
                      </option>
                    ))}
                  </select>
                </label>

                <label className="setting-field">
                  <span>User ID (exact)</span>
                  <input
                    type="text"
                    value={draftFilters.userId}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({ ...prev, userId: e.target.value }))
                    }
                    placeholder="e.g. ops.admin"
                  />
                </label>

                <label className="setting-field">
                  <span>Identity Type</span>
                  <select
                    value={draftFilters.identityType}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({
                        ...prev,
                        identityType: e.target.value as SearchIdentityType | "",
                      }))
                    }
                  >
                    <option value="">All identities</option>
                    <option value="authenticated">Authenticated</option>
                    <option value="anonymous">Anonymous</option>
                    <option value="session">Session (unauthenticated)</option>
                  </select>
                </label>

                <label className="setting-field">
                  <span>Search Outcome</span>
                  <select
                    value={draftFilters.outcome}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({
                        ...prev,
                        outcome: e.target.value as SearchLogOutcome | "",
                      }))
                    }
                  >
                    <option value="">All outcomes</option>
                    <option value="success">Success (results returned)</option>
                    <option value="zero_results">Zero results</option>
                    <option value="client_error">Client error (4xx)</option>
                    <option value="server_error">Server error (5xx)</option>
                    <option value="failed">All failed (4xx &amp; 5xx)</option>
                  </select>
                </label>

                <label className="setting-field">
                  <span>HTTP Status Class</span>
                  <select
                    value={draftFilters.statusClass}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({
                        ...prev,
                        statusClass: e.target.value as SearchStatusClass | "",
                      }))
                    }
                  >
                    <option value="">Any status class</option>
                    <option value="2xx">2xx Success</option>
                    <option value="4xx">4xx Client Error</option>
                    <option value="5xx">5xx Server Error</option>
                  </select>
                </label>

                <label className="setting-field">
                  <span>Exact HTTP Status</span>
                  <input
                    type="number"
                    min={100}
                    max={599}
                    value={draftFilters.statusCode}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({ ...prev, statusCode: e.target.value }))
                    }
                    placeholder="e.g. 200, 403, 500"
                  />
                </label>

                <label className="setting-field">
                  <span>Search Surface</span>
                  <select
                    value={draftFilters.surface}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({
                        ...prev,
                        surface: e.target.value as SearchSurfaceType | "",
                      }))
                    }
                  >
                    <option value="">All surfaces</option>
                    <option value="public">Public (/api/platform/search)</option>
                    <option value="admin">Admin (/api/admin/platform/search)</option>
                  </select>
                </label>
              </div>

              <div className="logs-toggle-row">
                <label className="platform-checkbox">
                  <input
                    type="checkbox"
                    checked={draftFilters.zeroResultsOnly}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({
                        ...prev,
                        zeroResultsOnly: e.target.checked,
                      }))
                    }
                  />
                  Zero-result searches only
                </label>
                <label className="platform-checkbox">
                  <input
                    type="checkbox"
                    checked={draftFilters.failedOnly}
                    onChange={(e) =>
                      setDraftFilters((prev) => ({
                        ...prev,
                        failedOnly: e.target.checked,
                      }))
                    }
                  />
                  Failed searches only (4xx / 5xx)
                </label>
                <span className="action-spacer" />
                <button
                  type="button"
                  className="secondary-button"
                  onClick={resetHistoryFilters}
                  disabled={logsLoading}
                >
                  Reset Filters
                </button>
                <button type="submit" className="primary-button" disabled={logsLoading}>
                  {logsLoading ? "Loading…" : "Apply Filters"}
                </button>
              </div>
            </form>
          </section>

          {logsResponse && (
            <section className="kpi-grid" aria-label="Matching Search Log Totals">
              <div className="kpi-card">
                <span>Matching Searches</span>
                <strong>{logsResponse.summary.total_attempts.toLocaleString()}</strong>
                <small>
                  {logsResponse.summary.authenticated_attempts.toLocaleString()} auth ·{" "}
                  {logsResponse.summary.anonymous_attempts.toLocaleString()} anon ·{" "}
                  {logsResponse.summary.session_attempts.toLocaleString()} session
                </small>
              </div>
              <div className="kpi-card">
                <span>Unique Auth Users</span>
                <strong>
                  {logsResponse.summary.unique_authenticated_users.toLocaleString()}
                </strong>
                <small>Within current filter</small>
              </div>
              <div className="kpi-card">
                <span>Successful (2xx)</span>
                <strong className="status-good">
                  {logsResponse.summary.successful_attempts.toLocaleString()}
                </strong>
                <small>
                  {logsResponse.summary.attempts_with_results.toLocaleString()} with results
                </small>
              </div>
              <div className="kpi-card">
                <span>Zero-Result Searches</span>
                <strong>{logsResponse.summary.zero_result_attempts.toLocaleString()}</strong>
                <small>HTTP 2xx with 0 results</small>
              </div>
              <div className="kpi-card">
                <span>Failed Searches</span>
                <strong
                  className={logsResponse.summary.failed_attempts > 0 ? "text-danger" : ""}
                >
                  {logsResponse.summary.failed_attempts.toLocaleString()}
                </strong>
                <small>
                  {logsResponse.summary.client_error_attempts_4xx.toLocaleString()} 4xx ·{" "}
                  {logsResponse.summary.server_error_attempts_5xx.toLocaleString()} 5xx
                </small>
              </div>
              <div className="kpi-card">
                <span>Avg Response Time</span>
                <strong>{formatMs(logsResponse.summary.avg_duration_ms)}</strong>
                <small>Across matching entries</small>
              </div>
            </section>
          )}

          <section className="panel ops-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">TIMESTAMPED SEARCH HISTORY</span>
                <h2>Search Execution Log</h2>
              </div>
              <label className="inline-page-size">
                <span>Rows per page</span>
                <select
                  value={historyPageSize}
                  onChange={(e) => {
                    setHistoryPageSize(Number(e.target.value));
                    setHistoryPage(1);
                  }}
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </label>
            </div>

            {logsError && (
              <div className="inline-error" style={{ marginTop: 14 }}>
                <strong>Unable to load search logs</strong>
                <span>{logsError}</span>
                <div style={{ marginTop: 6 }}>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => void loadSearchLogs()}
                  >
                    Retry
                  </button>
                </div>
              </div>
            )}

            {logsLoading ? (
              <div className="loading-state" style={{ marginTop: 14 }}>
                <span className="spinner dark" /> Loading search history…
              </div>
            ) : logsResponse && logsResponse.items.length === 0 ? (
              <div className="empty-state" style={{ marginTop: 14 }}>
                <div className="empty-icon">⌕</div>
                <h3>No search logs found</h3>
                <p>
                  No persisted search attempts matched your active filters. Try clearing
                  filters or broadening the date range.
                </p>
              </div>
            ) : logsResponse ? (
              <>
                <div className="table-scroll-wrap" style={{ marginTop: 14 }}>
                  <table className="audit-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Query</th>
                        <th>Category</th>
                        <th>User / Identity</th>
                        <th>Outcome</th>
                        <th>Results</th>
                        <th>Duration</th>
                        <th>HTTP Status</th>
                        <th>Request ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logsResponse.items.map((item) => (
                        <tr key={item.search_log_id}>
                          <td className="nowrap-cell">
                            {formatDateTime(item.occurred_at_utc)}
                          </td>
                          <td>
                            <div className="query-cell-text">{item.query || "(empty)"}</div>
                            <small className="cell-subtext">
                              {item.search_surface} · page {item.page_no} (size{" "}
                              {item.page_size})
                              {item.filter_count > 0
                                ? ` · ${item.filter_count} filter${item.filter_count === 1 ? "" : "s"}`
                                : ""}
                            </small>
                          </td>
                          <td>
                            <code className="code-pill">{item.category_id}</code>
                            {(item.config_version != null || item.index_version != null) && (
                              <small className="cell-subtext">
                                cfg v{item.config_version ?? "—"} · idx v
                                {item.index_version ?? "—"}
                              </small>
                            )}
                          </td>
                          <td>
                            {item.identity_type === "authenticated" &&
                            item.authenticated_user_id ? (
                              <div>
                                <strong>{item.authenticated_user_id}</strong>
                                <small className="cell-subtext">
                                  <span className="badge badge-info">Authenticated</span>
                                </small>
                              </div>
                            ) : (
                              <span
                                className={`badge ${identityBadgeClass(item.identity_type)}`}
                              >
                                {item.identity_type === "session"
                                  ? "Session (anon)"
                                  : "Anonymous"}
                              </span>
                            )}
                          </td>
                          <td>
                            <span className={`badge ${outcomeBadgeClass(item.outcome)}`}>
                              {outcomeLabel(item.outcome)}
                            </span>
                            {item.error_code && (
                              <small className="cell-subtext">{item.error_code}</small>
                            )}
                          </td>
                          <td>
                            {item.result_count !== null && item.result_count !== undefined
                              ? item.result_count.toLocaleString()
                              : "—"}
                          </td>
                          <td className="nowrap-cell">{formatMs(item.duration_ms)}</td>
                          <td>
                            <span className={`badge ${statusBadgeClass(item.http_status)}`}>
                              {item.http_status}
                            </span>
                          </td>
                          <td>
                            <code className="doc-id-code">{item.request_id}</code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="results-footer">
                  <span>
                    Page {logsResponse.pagination.page} of{" "}
                    {Math.max(1, historyTotalPages)} ·{" "}
                    {logsResponse.pagination.total_count.toLocaleString()} matching log
                    {logsResponse.pagination.total_count === 1 ? "" : "s"}
                  </span>
                  <div className="pagination-controls">
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={historyPage <= 1 || logsLoading}
                      onClick={() => setHistoryPage(1)}
                    >
                      « First
                    </button>
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={historyPage <= 1 || logsLoading}
                      onClick={() => setHistoryPage((p) => Math.max(1, p - 1))}
                    >
                      ← Previous
                    </button>
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={
                        historyTotalPages === 0 ||
                        historyPage >= historyTotalPages ||
                        logsLoading
                      }
                      onClick={() => setHistoryPage((p) => p + 1)}
                    >
                      Next →
                    </button>
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={
                        historyTotalPages === 0 ||
                        historyPage >= historyTotalPages ||
                        logsLoading
                      }
                      onClick={() => setHistoryPage(historyTotalPages)}
                    >
                      Last »
                    </button>
                  </div>
                </div>
              </>
            ) : null}
          </section>
        </>
      )}

      {subView === "users" && (
        <>
          <section className="panel ops-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">AUTHENTICATED USER SEARCH ACTIVITY</span>
                <h2>Filter Per-User Breakdown</h2>
              </div>
              <div className="inline-pills">
                <span className="method-badge">
                  GET · /api/admin/platform/search-logs/users
                </span>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => void loadUserActivity()}
                  disabled={usersLoading}
                >
                  {usersLoading ? "Refreshing…" : "↻ Refresh"}
                </button>
              </div>
            </div>

            {userValidationError && (
              <div className="inline-error" style={{ marginTop: 12 }}>
                <strong>Invalid filter</strong>
                <span>{userValidationError}</span>
              </div>
            )}

            <form onSubmit={applyUserFilters} style={{ marginTop: 14 }}>
              <div className="filter-bar">
                <label className="setting-field">
                  <span>Start Date (UTC)</span>
                  <input
                    type="date"
                    value={draftUserFilters.startUtc}
                    onChange={(e) =>
                      setDraftUserFilters((prev) => ({ ...prev, startUtc: e.target.value }))
                    }
                  />
                </label>

                <label className="setting-field">
                  <span>End Date (UTC)</span>
                  <input
                    type="date"
                    value={draftUserFilters.endUtc}
                    onChange={(e) =>
                      setDraftUserFilters((prev) => ({ ...prev, endUtc: e.target.value }))
                    }
                  />
                </label>

                <label className="setting-field">
                  <span>Category</span>
                  <select
                    value={draftUserFilters.category}
                    onChange={(e) =>
                      setDraftUserFilters((prev) => ({ ...prev, category: e.target.value }))
                    }
                  >
                    <option value="">All categories</option>
                    {categories.map((cat) => (
                      <option key={cat.config.category_id} value={cat.config.category_id}>
                        {cat.config.display_name} ({cat.config.category_id})
                      </option>
                    ))}
                  </select>
                </label>

                <label className="setting-field">
                  <span>User ID (exact)</span>
                  <input
                    type="text"
                    value={draftUserFilters.userId}
                    onChange={(e) =>
                      setDraftUserFilters((prev) => ({ ...prev, userId: e.target.value }))
                    }
                    placeholder="e.g. ops.admin"
                  />
                </label>

                <div className="filter-bar-actions">
                  <button
                    type="submit"
                    className="primary-button"
                    disabled={usersLoading}
                  >
                    Apply Filters
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={resetUserFilters}
                    disabled={usersLoading}
                  >
                    Reset
                  </button>
                </div>
              </div>
            </form>
          </section>

          {usersResponse && (
            <section className="kpi-grid" aria-label="Identity Summary">
              <div className="kpi-card">
                <span>Unique Authenticated Users</span>
                <strong>
                  {usersResponse.summary.unique_authenticated_users.toLocaleString()}
                </strong>
                <small>Distinct authenticated users in window</small>
              </div>
              <div className="kpi-card">
                <span>Authenticated Searches</span>
                <strong>
                  {usersResponse.summary.authenticated_attempts.toLocaleString()}
                </strong>
                <small>
                  Out of {usersResponse.summary.total_attempts.toLocaleString()} total
                  searches
                </small>
              </div>
              <div className="kpi-card">
                <span>Anonymous Searches</span>
                <strong>{usersResponse.summary.anonymous_attempts.toLocaleString()}</strong>
                <small>Excluded from per-user rows</small>
              </div>
              <div className="kpi-card">
                <span>Session Searches</span>
                <strong>{usersResponse.summary.session_attempts.toLocaleString()}</strong>
                <small>
                  {usersResponse.summary.unauthenticated_attempts.toLocaleString()} total
                  unauthenticated
                </small>
              </div>
            </section>
          )}

          <section className="panel ops-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">PER-USER ACTIVITY TABLE</span>
                <h2>Searches by Authenticated User</h2>
              </div>
              <label className="inline-page-size">
                <span>Users per page</span>
                <select
                  value={usersPageSize}
                  onChange={(e) => {
                    setUsersPageSize(Number(e.target.value));
                    setUsersPage(1);
                  }}
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </label>
            </div>

            {usersError && (
              <div className="inline-error" style={{ marginTop: 14 }}>
                <strong>Unable to load per-user activity</strong>
                <span>{usersError}</span>
                <div style={{ marginTop: 6 }}>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => void loadUserActivity()}
                  >
                    Retry
                  </button>
                </div>
              </div>
            )}

            {usersLoading ? (
              <div className="loading-state" style={{ marginTop: 14 }}>
                <span className="spinner dark" /> Loading per-user search activity…
              </div>
            ) : usersResponse && usersResponse.items.length === 0 ? (
              <div className="empty-state" style={{ marginTop: 14 }}>
                <div className="empty-icon">◎</div>
                <h3>No authenticated user activity found</h3>
                <p>
                  No authenticated searches matched the active filters. Anonymous and
                  session searches are summarized in the cards above.
                </p>
              </div>
            ) : usersResponse ? (
              <>
                <div className="table-scroll-wrap" style={{ marginTop: 14 }}>
                  <table className="audit-table">
                    <thead>
                      <tr>
                        <th>User</th>
                        <th>Total Searches</th>
                        <th>Successful Searches</th>
                        <th>Zero-Result Searches</th>
                        <th>Errors (4xx / 5xx)</th>
                        <th>Avg Response Time</th>
                        <th>Latest Search Time</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usersResponse.items.map((row) => (
                        <tr key={row.user_id}>
                          <td>
                            <strong>{row.user_id}</strong>
                          </td>
                          <td>
                            <strong>{row.total_attempts.toLocaleString()}</strong>
                          </td>
                          <td className="status-good">
                            {row.successful_attempts.toLocaleString()}
                          </td>
                          <td>{row.zero_result_attempts.toLocaleString()}</td>
                          <td>
                            {row.client_error_attempts_4xx.toLocaleString()} 4xx ·{" "}
                            <span
                              className={
                                row.server_error_attempts_5xx > 0 ? "text-danger" : ""
                              }
                            >
                              {row.server_error_attempts_5xx.toLocaleString()} 5xx
                            </span>
                          </td>
                          <td>{formatMs(row.avg_duration_ms)}</td>
                          <td className="nowrap-cell">
                            {formatDateTime(row.last_search_at_utc)}
                          </td>
                          <td>
                            <button
                              type="button"
                              className="secondary-button"
                              onClick={() => jumpToUserLogs(row.user_id)}
                            >
                              View Logs
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="results-footer">
                  <span>
                    Page {usersResponse.pagination.page} of{" "}
                    {Math.max(1, usersTotalPages)} ·{" "}
                    {usersResponse.pagination.total_count.toLocaleString()} authenticated
                    user{usersResponse.pagination.total_count === 1 ? "" : "s"}
                  </span>
                  <div className="pagination-controls">
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={usersPage <= 1 || usersLoading}
                      onClick={() => setUsersPage((p) => Math.max(1, p - 1))}
                    >
                      ← Previous
                    </button>
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={
                        usersTotalPages === 0 ||
                        usersPage >= usersTotalPages ||
                        usersLoading
                      }
                      onClick={() => setUsersPage((p) => p + 1)}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              </>
            ) : null}
          </section>
        </>
      )}
    </div>
  );
}
