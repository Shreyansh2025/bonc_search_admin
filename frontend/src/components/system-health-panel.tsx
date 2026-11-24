import { useCallback, useEffect, useState } from "react";
import {
  getApiFailureMetrics,
  getKpiMetrics,
  getRelevanceMetrics,
  getSystemHealth,
  syncPlatformCategory,
  type ApiFailureMetricsResponse,
  type HealthState,
  type KpiMetricsResponse,
  type PlatformCategoryRecord,
  type RelevanceMetricsResponse,
  type SystemHealthResponse,
} from "../lib/search-api";

export interface SystemHealthPanelProps {
  categories: PlatformCategoryRecord[];
  refreshNonce?: number;
  onHealthSnapshot?: (snapshot: SystemHealthResponse | null, errorMessage: string) => void;
  onCategoriesChanged?: () => void;
  onConfigureCategory?: (categoryId: string) => void;
  onInspectSearchLogs?: (filters?: { category?: string; failedOnly?: boolean }) => void;
}

type TimeRangePreset = "all" | "24h" | "7d" | "30d" | "custom";

const PRODUCTION_INDEX_LABELS: Record<string, string> = {
  b2bCompanies: "B2B Companies",
  b2bProducts: "B2B Products",
};

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatPercent(value?: number | null): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return `${value.toFixed(2)}%`;
}

function formatMs(value?: number | null): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return `${value.toFixed(1)} ms`;
}

function formatCount(value?: number | null): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return value.toLocaleString();
}

export function healthBadgeClass(state: HealthState): string {
  switch (state) {
    case "healthy":
      return "badge-ok";
    case "degraded":
      return "badge-warn";
    case "unhealthy":
      return "badge-danger";
    case "disabled":
      return "badge-muted";
    case "unavailable":
    default:
      return "badge-unavailable";
  }
}

export function healthLabel(state: HealthState): string {
  switch (state) {
    case "healthy":
      return "Healthy";
    case "degraded":
      return "Degraded";
    case "unhealthy":
      return "Unhealthy";
    case "disabled":
      return "Disabled";
    case "unavailable":
    default:
      return "Unavailable";
  }
}

function overallBannerClass(state: HealthState): string {
  switch (state) {
    case "healthy":
      return "ok";
    case "degraded":
      return "degraded";
    case "unhealthy":
      return "unhealthy";
    case "disabled":
    case "unavailable":
    default:
      return "unavailable";
  }
}

function cacheStatusLabel(status: string): string {
  switch (status) {
    case "warm":
      return "Warm (in-memory)";
    case "cold":
      return "Cold (lazy-build)";
    case "stale":
      return "Stale (version mismatch)";
    case "empty":
      return "Empty (0 docs)";
    default:
      return status;
  }
}

function cacheBadgeClass(status: string): string {
  switch (status) {
    case "warm":
      return "badge-ok";
    case "cold":
      return "badge-info";
    case "stale":
      return "badge-warn";
    case "empty":
      return "badge-muted";
    default:
      return "badge-muted";
  }
}

function resolveWindowBounds(
  preset: TimeRangePreset,
  customStart: string,
  customEnd: string,
): { startUtc?: string; endUtc?: string } {
  if (preset === "all") return {};
  if (preset === "custom") {
    return {
      startUtc: customStart.trim() || undefined,
      endUtc: customEnd.trim() || undefined,
    };
  }
  const now = Date.now();
  const hours = preset === "24h" ? 24 : preset === "7d" ? 24 * 7 : 24 * 30;
  return {
    startUtc: new Date(now - hours * 60 * 60 * 1000).toISOString(),
  };
}

export default function SystemHealthPanel({
  categories,
  refreshNonce = 0,
  onHealthSnapshot,
  onCategoriesChanged,
  onConfigureCategory,
  onInspectSearchLogs,
}: SystemHealthPanelProps) {
  // 1. Live System Health state
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState("");
  const [lastAttemptedCheckAt, setLastAttemptedCheckAt] = useState<string | null>(null);
  const [syncingCategory, setSyncingCategory] = useState("");
  const [syncMessage, setSyncMessage] = useState("");
  const [syncError, setSyncError] = useState("");

  // 2. Analytics & KPI Dashboard filters
  const [timeRange, setTimeRange] = useState<TimeRangePreset>("7d");
  const [customStart, setCustomStart] = useState("");
  const [customEnd, setCustomEnd] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("");
  const [endpointFilter, setEndpointFilter] = useState("");
  const [appliedFilter, setAppliedFilter] = useState<{
    preset: TimeRangePreset;
    customStart: string;
    customEnd: string;
    category: string;
    endpoint: string;
  }>({
    preset: "7d",
    customStart: "",
    customEnd: "",
    category: "",
    endpoint: "",
  });

  // 3. Analytics API states (independently tracked so partial availability renders cleanly)
  const [kpiData, setKpiData] = useState<KpiMetricsResponse | null>(null);
  const [kpiLoading, setKpiLoading] = useState(true);
  const [kpiError, setKpiError] = useState("");

  const [apiFailureData, setApiFailureData] = useState<ApiFailureMetricsResponse | null>(null);
  const [apiFailureLoading, setApiFailureLoading] = useState(true);
  const [apiFailureError, setApiFailureError] = useState("");

  const [relevanceData, setRelevanceData] = useState<RelevanceMetricsResponse | null>(null);
  const [relevanceLoading, setRelevanceLoading] = useState(true);
  const [relevanceError, setRelevanceError] = useState("");
  const [analyticsUpdatedAt, setAnalyticsUpdatedAt] = useState<string | null>(null);

  const loadSystemHealth = useCallback(async () => {
    setHealthLoading(true);
    setHealthError("");
    const attemptedAt = new Date().toISOString();
    setLastAttemptedCheckAt(attemptedAt);
    try {
      const result = await getSystemHealth(10);
      setHealth(result);
      onHealthSnapshot?.(result, "");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unable to load backend system health.";
      setHealth(null);
      setHealthError(message);
      onHealthSnapshot?.(null, message);
    } finally {
      setHealthLoading(false);
    }
  }, [onHealthSnapshot]);

  const loadAnalytics = useCallback(
    async (filterState: {
      preset: TimeRangePreset;
      customStart: string;
      customEnd: string;
      category: string;
      endpoint: string;
    }) => {
      const { startUtc, endUtc } = resolveWindowBounds(
        filterState.preset,
        filterState.customStart,
        filterState.customEnd,
      );
      const categoryParam = filterState.category || undefined;
      const endpointParam = filterState.endpoint.trim() || undefined;

      setKpiLoading(true);
      setApiFailureLoading(true);
      setRelevanceLoading(true);
      setKpiError("");
      setApiFailureError("");
      setRelevanceError("");

      const [kpiResult, apiResult, relevanceResult] = await Promise.allSettled([
        getKpiMetrics({
          start_utc: startUtc,
          end_utc: endUtc,
          category: categoryParam,
          top_endpoints_limit: 10,
          recent_failures_limit: 20,
        }),
        getApiFailureMetrics({
          start_utc: startUtc,
          end_utc: endUtc,
          endpoint: endpointParam,
          top_endpoints_limit: 10,
          recent_failures_limit: 20,
        }),
        getRelevanceMetrics({
          start_utc: startUtc,
          end_utc: endUtc,
          category: categoryParam,
          recent_negative_limit: 20,
        }),
      ]);

      if (kpiResult.status === "fulfilled") {
        setKpiData(kpiResult.value);
      } else {
        setKpiData(null);
        setKpiError(
          kpiResult.reason instanceof Error
            ? kpiResult.reason.message
            : "Unable to load Search KPI metrics.",
        );
      }
      setKpiLoading(false);

      if (apiResult.status === "fulfilled") {
        setApiFailureData(apiResult.value);
      } else {
        setApiFailureData(null);
        setApiFailureError(
          apiResult.reason instanceof Error
            ? apiResult.reason.message
            : "Unable to load API failure monitoring metrics.",
        );
      }
      setApiFailureLoading(false);

      if (relevanceResult.status === "fulfilled") {
        setRelevanceData(relevanceResult.value);
      } else {
        setRelevanceData(null);
        setRelevanceError(
          relevanceResult.reason instanceof Error
            ? relevanceResult.reason.message
            : "Unable to load feedback-derived relevance metrics.",
        );
      }
      setRelevanceLoading(false);
      setAnalyticsUpdatedAt(new Date().toISOString());
    },
    [],
  );

  useEffect(() => {
    void loadSystemHealth();
  }, [loadSystemHealth, refreshNonce]);

  useEffect(() => {
    void loadAnalytics(appliedFilter);
  }, [appliedFilter, loadAnalytics, refreshNonce]);

  const handleApplyAnalyticsFilters = () => {
    if (timeRange === "custom" && customStart && customEnd && customStart > customEnd) {
      setKpiError("Start date must be earlier than or equal to end date.");
      return;
    }
    setAppliedFilter({
      preset: timeRange,
      customStart,
      customEnd,
      category: selectedCategory,
      endpoint: endpointFilter,
    });
  };

  const handleResetAnalyticsFilters = () => {
    setTimeRange("7d");
    setCustomStart("");
    setCustomEnd("");
    setSelectedCategory("");
    setEndpointFilter("");
    setAppliedFilter({
      preset: "7d",
      customStart: "",
      customEnd: "",
      category: "",
      endpoint: "",
    });
  };

  const handleSyncCategory = async (categoryId: string) => {
    setSyncingCategory(categoryId);
    setSyncMessage("");
    setSyncError("");
    try {
      const result = await syncPlatformCategory(categoryId);
      setSyncMessage(
        `Synchronized ${result.documents_synced.toLocaleString()} documents for "${categoryId}".`,
      );
      await loadSystemHealth();
      onCategoriesChanged?.();
    } catch (error) {
      setSyncError(
        error instanceof Error ? error.message : `Unable to synchronize "${categoryId}".`,
      );
    } finally {
      setSyncingCategory("");
    }
  };

  const overallState: HealthState = health ? health.status : "unavailable";
  const apiState: HealthState = health ? health.components.api.status : "unavailable";
  const dbComponent = health?.components.database ?? null;
  const modelComponent = health?.components.embedding_model ?? null;
  const productionIndexes =
    health?.components.production_search ?? health?.components.search_indexes ?? null;
  const categoryIndexes = health?.components.category_indexes ?? null;
  const recentFailures = health?.components.recent_server_failures ?? null;

  const categoryOptions =
    categories.length > 0
      ? categories.map((c) => ({
          id: c.config.category_id,
          label: `${c.config.display_name} (${c.config.category_id})`,
        }))
      : (categoryIndexes?.items || []).map((c) => ({
          id: c.category_id,
          label: `${c.display_name} (${c.category_id})`,
        }));

  return (
    <div className="ops-stack">
      {/* =================================================================== */}
      {/* 1. LIVE SYSTEM HEALTH                                               */}
      {/* =================================================================== */}
      <section className="ops-section" aria-label="System Health">
        <div className={`hl-overall ${overallBannerClass(overallState)}`}>
          <span className="hl-dot" />
          <div className="hl-overall-body">
            <div className="hl-overall-title-row">
              <strong>
                {healthLoading && !health
                  ? "Checking backend health…"
                  : `System Status: ${healthLabel(overallState)}`}
              </strong>
              <span className={`badge ${healthBadgeClass(overallState)}`}>
                {healthLabel(overallState)}
              </span>
            </div>
            <div className="hl-overall-meta">
              <span>
                Last health check:{" "}
                <strong>
                  {formatDateTime(health?.checked_at_utc || lastAttemptedCheckAt)}
                </strong>
              </span>
              {health?.service && (
                <span>
                  Service: <code>{health.service}</code>
                </span>
              )}
              {health?.initialization_error && (
                <span>
                  Startup error: <code>{health.initialization_error}</code>
                </span>
              )}
            </div>
          </div>
          <div className="hl-overall-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={() => {
                void loadSystemHealth();
                void loadAnalytics(appliedFilter);
              }}
              disabled={healthLoading}
            >
              {healthLoading ? "Refreshing…" : "↻ Refresh All"}
            </button>
          </div>
        </div>

        {healthError && (
          <div className="inline-error" role="alert">
            <strong>Backend health endpoint unreachable</strong>
            <span>{healthError}</span>
          </div>
        )}
        {syncError && (
          <div className="inline-error" role="alert">
            <strong>Category synchronization failed</strong>
            <span>{syncError}</span>
          </div>
        )}
        {syncMessage && <div className="success-message">{syncMessage}</div>}

        <div className="hl-grid">
          <article className="hl-card">
            <div className="hl-card-head">
              <span className="hl-name">API / Backend Service</span>
              <span className={`badge ${healthBadgeClass(apiState)}`}>
                {healthLabel(apiState)}
              </span>
            </div>
            <p className="hl-detail">
              {health?.components.api.detail ||
                (healthError
                  ? "Search AI backend did not respond to the health check."
                  : "Awaiting response from GET /api/admin/platform/system-health.")}
            </p>
            <div className="hl-meta-line">
              <span>Endpoint: <code>/api/admin/platform/system-health</code></span>
            </div>
          </article>

          <article className="hl-card">
            <div className="hl-card-head">
              <span className="hl-name">Database Connectivity</span>
              <span
                className={`badge ${healthBadgeClass(dbComponent?.status ?? "unavailable")}`}
              >
                {healthLabel(dbComponent?.status ?? "unavailable")}
              </span>
            </div>
            <p className="hl-detail">
              {dbComponent?.detail || "Database status unavailable."}
            </p>
            <div className="hl-meta-line">
              <span>
                Ping latency: <strong>{formatMs(dbComponent?.latency_ms)}</strong>
              </span>
              <span>
                Startup init:{" "}
                <strong>
                  {dbComponent
                    ? dbComponent.startup_ready
                      ? "Completed"
                      : "Pending / Not run"
                    : "—"}
                </strong>
              </span>
            </div>
          </article>

          <article className="hl-card">
            <div className="hl-card-head">
              <span className="hl-name">Embedding Model Readiness</span>
              <span
                className={`badge ${healthBadgeClass(modelComponent?.status ?? "unavailable")}`}
              >
                {healthLabel(modelComponent?.status ?? "unavailable")}
              </span>
            </div>
            <p className="hl-detail">
              {modelComponent?.detail || "Embedding model status unavailable."}
            </p>
            <div className="hl-meta-line">
              <span>
                Model:{" "}
                <code>{modelComponent?.model_name || "—"}</code>
              </span>
              <span>
                Dimensions:{" "}
                <strong>
                  {modelComponent?.embedding_dim != null
                    ? `${modelComponent.embedding_dim}-d`
                    : "—"}
                </strong>
              </span>
            </div>
          </article>

          <article className="hl-card">
            <div className="hl-card-head">
              <span className="hl-name">Production Search (Read-Only)</span>
              <span
                className={`badge ${healthBadgeClass(productionIndexes?.status ?? "disabled")}`}
              >
                {healthLabel(productionIndexes?.status ?? "disabled")}
              </span>
            </div>
            <p className="hl-detail">
              {productionIndexes?.detail ||
                "Optional read-only production Product & Company Search observability is disabled."}
            </p>
            <div className="hl-meta-line">
              <span>
                Ready:{" "}
                <strong>
                  {productionIndexes && productionIndexes.status !== "disabled"
                    ? `${productionIndexes.ready_count}/${productionIndexes.total_count}`
                    : "Disabled"}
                </strong>
              </span>
              <span>
                Records:{" "}
                <strong>
                  {productionIndexes && productionIndexes.status !== "disabled"
                    ? formatCount(productionIndexes.total_records)
                    : "—"}
                </strong>
              </span>
            </div>
          </article>
        </div>

        {/* Category-level index & sync status */}
        <section className="panel ops-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">CATEGORY-LEVEL INDEX &amp; SYNC STATUS</span>
              <h2>Platform Search Categories</h2>
            </div>
            <div className="inline-pills">
              <span
                className={`badge ${healthBadgeClass(categoryIndexes?.status ?? "unavailable")}`}
              >
                {healthLabel(categoryIndexes?.status ?? "unavailable")}
              </span>
              {categoryIndexes && (
                <span className="badge badge-info">
                  {categoryIndexes.source_profile_count} SQL profile
                  {categoryIndexes.source_profile_count === 1 ? "" : "s"}
                </span>
              )}
            </div>
          </div>
          <p className="panel-intro">
            {categoryIndexes?.detail ||
              "Category index status will appear once the backend health check succeeds."}
          </p>

          {healthLoading && !health ? (
            <div className="loading-state">
              <span className="spinner dark" /> Loading category index status…
            </div>
          ) : !categoryIndexes || categoryIndexes.status === "unavailable" ? (
            <div className="empty-state compact">
              <h3>Category index metadata unavailable</h3>
              <p>
                {categoryIndexes?.detail ||
                  "Unable to read searchai.SearchCategories from the backend."}
              </p>
            </div>
          ) : categoryIndexes.items.length === 0 ? (
            <div className="empty-state compact">
              <h3>No search categories configured</h3>
              <p>
                Create and sync a search engine under Data Sources &amp; Configuration to
                populate category indexes.
              </p>
            </div>
          ) : (
            <div className="table-scroll-wrap">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Health</th>
                    <th>Status / Access</th>
                    <th>Indexed Docs</th>
                    <th>Versions</th>
                    <th>Worker Cache</th>
                    <th>Source Mapping</th>
                    <th>Last Updated / Synced</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {categoryIndexes.items.map((cat) => (
                    <tr key={cat.category_id}>
                      <td>
                        <strong>{cat.display_name}</strong>{" "}
                        <code className="code-pill">{cat.category_id}</code>
                      </td>
                      <td>
                        <span className={`badge ${healthBadgeClass(cat.health_state)}`}>
                          {healthLabel(cat.health_state)}
                        </span>
                      </td>
                      <td>
                        <div className="inline-pills">
                          <span
                            className={`badge ${cat.active ? "badge-ok" : "badge-muted"}`}
                          >
                            {cat.active ? "Active" : cat.status}
                          </span>
                          <span
                            className={`badge ${cat.public_search_enabled ? "badge-warn" : "badge-info"}`}
                          >
                            {cat.public_search_enabled ? "Public" : "Admin-Only"}
                          </span>
                        </div>
                      </td>
                      <td>
                        <strong>{cat.document_count.toLocaleString()}</strong>
                      </td>
                      <td>
                        cfg v{cat.config_version} · idx v{cat.index_version}
                      </td>
                      <td>
                        <span className={`badge ${cacheBadgeClass(cat.cache_status)}`}>
                          {cacheStatusLabel(cat.cache_status)}
                        </span>
                        {cat.vector_index_built && (
                          <small className="cell-subtext">FAISS vectors ready</small>
                        )}
                      </td>
                      <td>
                        <code>{cat.source_target}</code>
                      </td>
                      <td>
                        <div>{formatDateTime(cat.updated_at_utc)}</div>
                        {cat.updated_by && (
                          <small className="cell-subtext">by {cat.updated_by}</small>
                        )}
                      </td>
                      <td>
                        <div className="inline-pills">
                          {cat.source_type === "sqlserver" && (
                            <button
                              type="button"
                              className="secondary-button"
                              disabled={syncingCategory === cat.category_id}
                              onClick={() => void handleSyncCategory(cat.category_id)}
                            >
                              {syncingCategory === cat.category_id
                                ? "Syncing…"
                                : "↻ Sync"}
                            </button>
                          )}
                          {onConfigureCategory && (
                            <button
                              type="button"
                              className="secondary-button"
                              onClick={() => onConfigureCategory(cat.category_id)}
                            >
                              Configure
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Optional Read-Only Production Observability & Recent 24h Server Failures side-by-side */}
        <div className="dashboard-two-col">
          <section className="panel ops-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">OPTIONAL PRODUCTION OBSERVABILITY (READ-ONLY)</span>
                <h2>Product &amp; Company Search Indexes</h2>
              </div>
              <span
                className={`badge ${healthBadgeClass(productionIndexes?.status ?? "disabled")}`}
              >
                {healthLabel(productionIndexes?.status ?? "disabled")}
              </span>
            </div>

            {!productionIndexes ||
            productionIndexes.status === "disabled" ||
            Object.keys(productionIndexes.indexes).length === 0 ? (
              <p className="panel-intro" style={{ marginTop: 12 }}>
                {productionIndexes?.detail ||
                  "Optional read-only production Product & Company Search observability is disabled until Stage 3 verification."}
              </p>
            ) : (
              <div className="table-scroll-wrap" style={{ marginTop: 12 }}>
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Index</th>
                      <th>Health</th>
                      <th>Build State</th>
                      <th>Records</th>
                      <th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(productionIndexes.indexes).map(([key, item]) => (
                      <tr key={key}>
                        <td>
                          <strong>{PRODUCTION_INDEX_LABELS[key] || key}</strong>
                          <small className="cell-subtext">{key}</small>
                        </td>
                        <td>
                          <span
                            className={`badge ${healthBadgeClass(item.health_state)}`}
                          >
                            {healthLabel(item.health_state)}
                          </span>
                        </td>
                        <td>
                          <code>{item.status}</code>
                          <small className="cell-subtext">
                            {item.index_built ? "FAISS built" : "Not built"}
                          </small>
                        </td>
                        <td>
                          <strong>{item.count.toLocaleString()}</strong>
                        </td>
                        <td>
                          {item.last_error ? (
                            <span className="badge badge-danger">{item.last_error}</span>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="panel ops-panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">RECENT SERVER FAILURES (LAST 24H)</span>
                <h2>HTTP 5xx Health Signal</h2>
              </div>
              <span
                className={`badge ${healthBadgeClass(recentFailures?.status ?? "unavailable")}`}
              >
                {healthLabel(recentFailures?.status ?? "unavailable")}
              </span>
            </div>
            <p className="panel-intro" style={{ marginTop: 8 }}>
              {recentFailures?.detail || "Recent failure telemetry is unavailable."}
            </p>

            {recentFailures && recentFailures.status !== "unavailable" && (
              <div className="engine-kpi-row" style={{ marginBottom: 12 }}>
                <div className="engine-kpi">
                  <span>5xx Failures (24h)</span>
                  <strong>{formatCount(recentFailures.server_failures_24h)}</strong>
                </div>
                <div className="engine-kpi">
                  <span>API Requests (24h)</span>
                  <strong>{formatCount(recentFailures.total_api_requests_24h)}</strong>
                </div>
                <div className="engine-kpi">
                  <span>5xx Rate (24h)</span>
                  <strong>{formatPercent(recentFailures.server_failure_rate_24h_pct)}</strong>
                </div>
                <div className="engine-kpi">
                  <span>4xx Client Errors</span>
                  <strong>{formatCount(recentFailures.client_errors_24h)}</strong>
                </div>
              </div>
            )}

            {!recentFailures || recentFailures.status === "unavailable" ? (
              <div className="empty-state compact">
                <h3>Server failure logs unavailable</h3>
                <p>
                  {recentFailures?.detail ||
                    "Confirm database connectivity and that Migration 006 (searchai.ApiRequestLogs) is applied."}
                </p>
              </div>
            ) : recentFailures.items.length === 0 ? (
              <div className="empty-state compact">
                <h3>No recent HTTP 5xx server failures</h3>
                <p>
                  Zero 5xx server errors were logged in{" "}
                  <code>searchai.ApiRequestLogs</code> over the last 24 hours.
                </p>
              </div>
            ) : (
              <div className="table-scroll-wrap">
                <table className="audit-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Endpoint</th>
                      <th>Status</th>
                      <th>Error</th>
                      <th>Request ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentFailures.items.slice(0, 6).map((failure) => (
                      <tr key={failure.request_log_id}>
                        <td>{formatDateTime(failure.occurred_at_utc)}</td>
                        <td>
                          <code>
                            {failure.http_method} {failure.endpoint}
                          </code>
                        </td>
                        <td>
                          <span className="badge badge-danger">{failure.http_status}</span>
                        </td>
                        <td>
                          <div>{failure.error_summary || "Server error"}</div>
                          {failure.error_code && (
                            <small className="cell-subtext">{failure.error_code}</small>
                          )}
                        </td>
                        <td>
                          <code className="doc-id-code">{failure.request_id}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      </section>

      {/* =================================================================== */}
      {/* 2. ANALYTICS & KPI DASHBOARD                                        */}
      {/* =================================================================== */}
      <section className="ops-section" aria-label="Analytics and KPI Dashboard">
        <div className="panel ops-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">ANALYTICS &amp; KPI DASHBOARD</span>
              <h2>Search KPIs, API Monitoring &amp; Relevance Feedback</h2>
            </div>
            <div className="inline-pills">
              {analyticsUpdatedAt && (
                <span className="meta-timestamp">
                  Updated {formatDateTime(analyticsUpdatedAt)}
                </span>
              )}
              {onInspectSearchLogs && (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() =>
                    onInspectSearchLogs({
                      category: appliedFilter.category || undefined,
                    })
                  }
                >
                  Open Search Logs →
                </button>
              )}
            </div>
          </div>

          <div className="filter-bar">
            <label className="setting-field">
              <span>Time Range</span>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value as TimeRangePreset)}
              >
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
                <option value="all">All recorded time</option>
                <option value="custom">Custom UTC dates</option>
              </select>
            </label>

            {timeRange === "custom" && (
              <>
                <label className="setting-field">
                  <span>Start Date (UTC)</span>
                  <input
                    type="date"
                    value={customStart}
                    onChange={(e) => setCustomStart(e.target.value)}
                  />
                </label>
                <label className="setting-field">
                  <span>End Date (UTC)</span>
                  <input
                    type="date"
                    value={customEnd}
                    onChange={(e) => setCustomEnd(e.target.value)}
                  />
                </label>
              </>
            )}

            <label className="setting-field">
              <span>Category (Search KPIs &amp; Relevance)</span>
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
              >
                <option value="">All categories</option>
                {categoryOptions.map((opt) => (
                  <option key={opt.id} value={opt.id}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="setting-field">
              <span>Endpoint Filter (API Monitoring)</span>
              <input
                type="text"
                value={endpointFilter}
                onChange={(e) => setEndpointFilter(e.target.value)}
                placeholder="e.g. /api/platform/search"
              />
            </label>

            <div className="filter-bar-actions">
              <button
                type="button"
                className="primary-button"
                onClick={handleApplyAnalyticsFilters}
                disabled={kpiLoading || apiFailureLoading || relevanceLoading}
              >
                Apply Filters
              </button>
              <button
                type="button"
                className="secondary-button"
                onClick={handleResetAnalyticsFilters}
                disabled={kpiLoading || apiFailureLoading || relevanceLoading}
              >
                Reset
              </button>
            </div>
          </div>
          <small className="settings-footnote">
            Category filter applies to <code>/metrics/kpis</code> (search KPIs) and{" "}
            <code>/metrics/relevance</code>. Endpoint filter applies to{" "}
            <code>/metrics/api-failures</code>.
          </small>
        </div>

        {/* 2A. Search KPIs */}
        <section className="panel ops-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">SEARCH KPIS</span>
              <h2>Search Volume, Identity &amp; Zero-Result Metrics</h2>
            </div>
            <span className="method-badge">GET · /api/admin/platform/metrics/kpis</span>
          </div>

          {kpiError && (
            <div className="inline-error" style={{ marginTop: 12 }}>
              <strong>Unable to load Search KPIs</strong>
              <span>{kpiError}</span>
            </div>
          )}

          {kpiLoading ? (
            <div className="loading-state" style={{ marginTop: 12 }}>
              <span className="spinner dark" /> Loading Search KPIs…
            </div>
          ) : kpiData ? (
            <>
              <div className="kpi-grid" style={{ marginTop: 14, marginBottom: 10 }}>
                <div className="kpi-card">
                  <span>Total Search Attempts</span>
                  <strong>{kpiData.search_kpis.total_search_attempts.toLocaleString()}</strong>
                  <small>
                    {kpiData.search_kpis.authenticated_searches.toLocaleString()} authenticated ·{" "}
                    {kpiData.search_kpis.client_error_searches_4xx.toLocaleString()} 4xx ·{" "}
                    {kpiData.search_kpis.server_error_searches_5xx.toLocaleString()} 5xx
                  </small>
                </div>
                <div className="kpi-card">
                  <span>Unique Users</span>
                  <strong>
                    {kpiData.search_kpis.unique_authenticated_users.toLocaleString()}
                  </strong>
                  <small>Distinct server-authenticated user IDs</small>
                </div>
                <div className="kpi-card">
                  <span>Anonymous Searches</span>
                  <strong>{kpiData.search_kpis.anonymous_searches.toLocaleString()}</strong>
                  <small>
                    {kpiData.search_kpis.session_searches.toLocaleString()} session-cookie ·{" "}
                    {kpiData.search_kpis.unauthenticated_searches.toLocaleString()} total
                    unauthenticated
                  </small>
                </div>
                <div className="kpi-card">
                  <span>Successful Searches (2xx)</span>
                  <strong>{kpiData.search_kpis.successful_searches.toLocaleString()}</strong>
                  <small>
                    {kpiData.search_kpis.searches_with_results.toLocaleString()} returned ≥1
                    result
                  </small>
                </div>
                <div className="kpi-card">
                  <span>Zero-Result Searches</span>
                  <strong>{kpiData.search_kpis.zero_result_searches.toLocaleString()}</strong>
                  <small>Successful (2xx) queries returning 0 results</small>
                </div>
                <div className="kpi-card">
                  <span>Zero-Result Rate</span>
                  <strong>{formatPercent(kpiData.search_kpis.zero_result_rate_pct)}</strong>
                  <small>
                    {kpiData.search_kpis.zero_result_rate_numerator.toLocaleString()} /{" "}
                    {kpiData.search_kpis.zero_result_rate_denominator.toLocaleString()} successful
                    searches
                  </small>
                </div>
                <div className="kpi-card">
                  <span>Average Response Time</span>
                  <strong>{formatMs(kpiData.search_kpis.avg_response_time_ms)}</strong>
                  <small>Mean server execution duration across logged searches</small>
                </div>
              </div>
              <div className="definition-note">
                <strong>Zero-result rate definition:</strong>{" "}
                {kpiData.search_kpis.zero_result_rate_definition}
              </div>
            </>
          ) : !kpiError ? (
            <div className="empty-state compact" style={{ marginTop: 12 }}>
              <h3>No search KPI data available</h3>
              <p>No search attempts match the selected window and category.</p>
            </div>
          ) : null}
        </section>

        {/* 2B. API Monitoring */}
        <section className="panel ops-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">API MONITORING</span>
              <h2>Request Volume, 4xx Client Errors &amp; 5xx Server Failures</h2>
            </div>
            <span className="method-badge">GET · /api/admin/platform/metrics/api-failures</span>
          </div>

          {apiFailureError && (
            <div className="inline-error" style={{ marginTop: 12 }}>
              <strong>Unable to load API failure metrics</strong>
              <span>{apiFailureError}</span>
            </div>
          )}

          {apiFailureLoading ? (
            <div className="loading-state" style={{ marginTop: 12 }}>
              <span className="spinner dark" /> Loading API monitoring metrics…
            </div>
          ) : apiFailureData ? (
            <>
              <div className="kpi-grid" style={{ marginTop: 14, marginBottom: 10 }}>
                <div className="kpi-card">
                  <span>Total API Requests</span>
                  <strong>{apiFailureData.total_api_requests.toLocaleString()}</strong>
                  <small>
                    {apiFailureData.successful_requests.toLocaleString()} non-error (&lt;400)
                  </small>
                </div>
                <div className="kpi-card">
                  <span>4xx Client Errors</span>
                  <strong>{apiFailureData.client_error_requests_4xx.toLocaleString()}</strong>
                  <small>
                    {formatPercent(apiFailureData.client_error_rate_pct)} of requests (excluded
                    from 5xx failures)
                  </small>
                </div>
                <div className="kpi-card">
                  <span>5xx Server Failures</span>
                  <strong
                    className={
                      apiFailureData.server_failure_requests_5xx > 0 ? "text-danger" : "status-good"
                    }
                  >
                    {apiFailureData.server_failure_requests_5xx.toLocaleString()}
                  </strong>
                  <small>Server-side HTTP 5xx failures</small>
                </div>
                <div className="kpi-card">
                  <span>Server Failure Rate (5xx)</span>
                  <strong>{formatPercent(apiFailureData.server_failure_rate_pct)}</strong>
                  <small>
                    {apiFailureData.server_failure_rate_numerator.toLocaleString()} /{" "}
                    {apiFailureData.server_failure_rate_denominator.toLocaleString()} monitored
                    API requests
                  </small>
                </div>
                <div className="kpi-card">
                  <span>Average API Latency</span>
                  <strong>{formatMs(apiFailureData.avg_response_time_ms)}</strong>
                  <small>
                    {apiFailureData.window.endpoint
                      ? `Filtered to ${apiFailureData.window.endpoint}`
                      : "All monitored /api/* and /internal/* routes"}
                  </small>
                </div>
              </div>

              <div className="definition-note" style={{ marginBottom: 16 }}>
                <strong>Server failure rate definition:</strong>{" "}
                {apiFailureData.server_failure_rate_definition}
              </div>

              <div className="dashboard-two-col">
                <div>
                  <h3 className="subpanel-title">Most Failure-Prone Endpoints (HTTP 5xx)</h3>
                  {apiFailureData.most_failure_prone_endpoints.length === 0 ? (
                    <div className="empty-state compact">
                      <h3>No 5xx-failing endpoints</h3>
                      <p>
                        No monitored endpoints recorded HTTP 5xx failures in the selected
                        window.
                      </p>
                    </div>
                  ) : (
                    <div className="table-scroll-wrap">
                      <table className="audit-table">
                        <thead>
                          <tr>
                            <th>Endpoint</th>
                            <th>5xx Count</th>
                            <th>5xx Rate</th>
                            <th>Total Reqs</th>
                            <th>4xx</th>
                            <th>Avg Latency</th>
                            <th>Last Failure</th>
                          </tr>
                        </thead>
                        <tbody>
                          {apiFailureData.most_failure_prone_endpoints.map((ep) => (
                            <tr key={ep.endpoint}>
                              <td>
                                <button
                                  type="button"
                                  className="link-code-btn"
                                  onClick={() => {
                                    setEndpointFilter(ep.endpoint);
                                    setAppliedFilter((prev) => ({
                                      ...prev,
                                      endpoint: ep.endpoint,
                                    }));
                                  }}
                                  title="Filter API monitoring to this endpoint"
                                >
                                  <code>{ep.endpoint}</code>
                                </button>
                              </td>
                              <td>
                                <span className="badge badge-danger">
                                  {ep.server_failure_count_5xx.toLocaleString()}
                                </span>
                              </td>
                              <td>
                                <strong>{formatPercent(ep.server_failure_rate_pct)}</strong>
                              </td>
                              <td>{ep.total_requests.toLocaleString()}</td>
                              <td>{ep.client_error_count_4xx.toLocaleString()}</td>
                              <td>{formatMs(ep.avg_duration_ms)}</td>
                              <td>{formatDateTime(ep.last_failure_at_utc)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                <div>
                  <h3 className="subpanel-title">Recent Server Failures (HTTP 5xx)</h3>
                  {apiFailureData.recent_server_failures.length === 0 ? (
                    <div className="empty-state compact">
                      <h3>No recent 5xx failures</h3>
                      <p>
                        No server failure entries were recorded for this time range
                        {apiFailureData.window.endpoint
                          ? ` on ${apiFailureData.window.endpoint}`
                          : ""}
                        .
                      </p>
                    </div>
                  ) : (
                    <div className="table-scroll-wrap">
                      <table className="audit-table">
                        <thead>
                          <tr>
                            <th>Timestamp</th>
                            <th>Route</th>
                            <th>Status</th>
                            <th>Duration</th>
                            <th>Error</th>
                            <th>Request ID</th>
                          </tr>
                        </thead>
                        <tbody>
                          {apiFailureData.recent_server_failures.map((item) => (
                            <tr key={item.request_log_id}>
                              <td>{formatDateTime(item.occurred_at_utc)}</td>
                              <td>
                                <code>
                                  {item.http_method} {item.endpoint}
                                </code>
                              </td>
                              <td>
                                <span className="badge badge-danger">
                                  {item.http_status}
                                </span>
                              </td>
                              <td>{formatMs(item.duration_ms)}</td>
                              <td>
                                <div>{item.error_summary || "Internal server error"}</div>
                                {item.error_code && (
                                  <small className="cell-subtext">{item.error_code}</small>
                                )}
                              </td>
                              <td>
                                <code className="doc-id-code">{item.request_id}</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : null}
        </section>

        {/* 2C. Feedback-Derived Relevance & Rejection */}
        <section className="panel ops-panel">
          <div className="panel-title-row">
            <div>
              <span className="section-kicker">
                FEEDBACK-DERIVED RELEVANCE &amp; REJECTION METRICS
              </span>
              <h2>Rated Search Result Feedback</h2>
            </div>
            <span className="method-badge">GET · /api/admin/platform/metrics/relevance</span>
          </div>

          <div className="notice notice-info" style={{ marginTop: 12, marginBottom: 14 }}>
            <div className="notice-icon">i</div>
            <div>
              <strong>Feedback-Derived Metric Scope (Not an Objective False-Positive Rate)</strong>
              <p>
                {relevanceData?.disclaimer ||
                  "Calculated strictly from recorded relevance feedback judgments in searchai.SearchFeedback. Negative-feedback percentage reflects rated rejection feedback, not an objective false-positive rate against an independent ground-truth dataset."}
              </p>
            </div>
          </div>

          {relevanceError && (
            <div className="inline-error">
              <strong>Unable to load feedback-derived relevance metrics</strong>
              <span>{relevanceError}</span>
            </div>
          )}

          {relevanceLoading ? (
            <div className="loading-state">
              <span className="spinner dark" /> Loading feedback-derived relevance metrics…
            </div>
          ) : relevanceData ? (
            <>
              <div className="kpi-grid" style={{ marginBottom: 10 }}>
                <div className="kpi-card">
                  <span>Relevant Judgments</span>
                  <strong className="status-good">
                    {relevanceData.summary.relevant_judgments.toLocaleString()}
                  </strong>
                  <small>
                    {formatPercent(relevanceData.summary.positive_feedback_percentage)} of
                    rated results
                  </small>
                </div>
                <div className="kpi-card">
                  <span>Not-Relevant Judgments</span>
                  <strong
                    className={
                      relevanceData.summary.not_relevant_judgments > 0 ? "text-danger" : ""
                    }
                  >
                    {relevanceData.summary.not_relevant_judgments.toLocaleString()}
                  </strong>
                  <small>Feedback entries marked not relevant</small>
                </div>
                <div className="kpi-card">
                  <span>Total Rated Results</span>
                  <strong>{relevanceData.summary.total_rated_results.toLocaleString()}</strong>
                  <small>Denominator for feedback-derived percentages</small>
                </div>
                <div className="kpi-card">
                  <span>Negative-Feedback Percentage</span>
                  <strong>
                    {formatPercent(relevanceData.summary.negative_feedback_percentage)}
                  </strong>
                  <small>
                    {relevanceData.summary.negative_feedback_numerator.toLocaleString()} /{" "}
                    {relevanceData.summary.negative_feedback_denominator.toLocaleString()} rated
                    results (feedback-derived)
                  </small>
                </div>
              </div>

              <div className="definition-note" style={{ marginBottom: 16 }}>
                <strong>Negative-feedback percentage definition:</strong>{" "}
                {relevanceData.summary.negative_feedback_definition}
              </div>

              <div className="dashboard-two-col">
                <div>
                  <h3 className="subpanel-title">Feedback Breakdown by Category</h3>
                  {relevanceData.category_breakdown.length === 0 ? (
                    <div className="empty-state compact">
                      <h3>No rated results by category</h3>
                      <p>No relevance feedback judgments match the selected filters.</p>
                    </div>
                  ) : (
                    <div className="table-scroll-wrap">
                      <table className="audit-table">
                        <thead>
                          <tr>
                            <th>Category</th>
                            <th>Total Rated</th>
                            <th>Relevant</th>
                            <th>Not Relevant</th>
                            <th>Negative Feedback %</th>
                          </tr>
                        </thead>
                        <tbody>
                          {relevanceData.category_breakdown.map((row) => (
                            <tr key={row.category_id}>
                              <td>
                                <strong>{row.display_name}</strong>{" "}
                                <code className="code-pill">{row.category_id}</code>
                              </td>
                              <td>{row.total_rated_results.toLocaleString()}</td>
                              <td className="status-good">
                                {row.relevant_judgments.toLocaleString()}
                              </td>
                              <td className="text-danger">
                                {row.not_relevant_judgments.toLocaleString()}
                              </td>
                              <td>
                                <strong>
                                  {formatPercent(row.negative_feedback_percentage)}
                                </strong>
                                <small className="cell-subtext">
                                  ({row.negative_feedback_numerator}/
                                  {row.negative_feedback_denominator})
                                </small>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                <div>
                  <h3 className="subpanel-title">Recent Negative Feedback</h3>
                  {relevanceData.recent_negative_examples.length === 0 ? (
                    <div className="empty-state compact">
                      <h3>No negative feedback recorded</h3>
                      <p>
                        No results were marked &ldquo;Not Relevant&rdquo; in the selected
                        time window and category.
                      </p>
                    </div>
                  ) : (
                    <div className="table-scroll-wrap">
                      <table className="audit-table">
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>Category</th>
                            <th>Query</th>
                            <th>Document &amp; Rank</th>
                            <th>Note / Actor</th>
                          </tr>
                        </thead>
                        <tbody>
                          {relevanceData.recent_negative_examples.map((item) => (
                            <tr key={item.feedback_id}>
                              <td>{formatDateTime(item.created_at_utc)}</td>
                              <td>
                                <code className="code-pill">{item.category_id}</code>
                              </td>
                              <td>
                                <strong>{item.query}</strong>
                              </td>
                              <td>
                                <code className="doc-id-code">{item.document_id}</code>
                                <small className="cell-subtext">
                                  {item.result_rank != null ? `Rank #${item.result_rank}` : "Rank —"}
                                  {item.result_score != null
                                    ? ` · ${item.result_score.toFixed(1)} pts`
                                    : ""}
                                  {item.config_version != null
                                    ? ` · cfg v${item.config_version}`
                                    : ""}
                                </small>
                              </td>
                              <td>
                                <div>{item.comment || "No note"}</div>
                                <small className="cell-subtext">
                                  {item.created_by || "admin"}
                                </small>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : null}
        </section>
      </section>
    </div>
  );
}
