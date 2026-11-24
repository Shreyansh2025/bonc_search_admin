import {
  getBoncAccessToken,
  getEffectiveFrontendAuthMode,
  invokeBoncHostLogout,
  refreshBoncAccessToken,
  setRuntimeAuthModeOverride,
} from "./bonc-auth.ts";

const rawBase =
  (typeof import.meta !== "undefined" &&
    (import.meta.env?.VITE_ADMIN_API_BASE_URL ||
      import.meta.env?.VITE_SEARCH_API_BASE_URL)) ||
  "/admin-api";
export const ADMIN_API_BASE = rawBase.replace(/\/$/, "");

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// Session CSRF token is held strictly in JS memory (local-dev cookie mode only) and never persisted to browser storage.
let activeCsrfToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;
let forbiddenHandler: ((message: string) => void) | null = null;
let csrfErrorHandler: ((message: string) => void) | null = null;

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export interface AdminSessionInfo {
  authenticated: boolean;
  auth_method: "session" | "bearer" | "jwt" | "bonc_jwt" | string;
  auth_mode?: "bonc_jwt" | "local_session" | string;
  user_id?: string | null;
  username: string;
  actor: string;
  roles?: string[];
  permissions?: string[];
  expires_at_utc?: string | null;
  csrf_token?: string | null;
  local_login_enabled?: boolean;
}

export interface PublicPlatformCategorySummary {
  category_id: string;
  display_name: string;
  description?: string | null;
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

export function setForbiddenHandler(handler: ((message: string) => void) | null): void {
  forbiddenHandler = handler;
}

export function setCsrfErrorHandler(handler: ((message: string) => void) | null): void {
  csrfErrorHandler = handler;
}

export function clearClientSessionState(): void {
  activeCsrfToken = null;
}

export function getInMemoryCsrfToken(): string | null {
  return activeCsrfToken;
}

export function buildQueryString(
  params: Record<string, string | number | boolean | null | undefined>,
): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) continue;
      searchParams.set(key, trimmed);
    } else if (typeof value === "boolean") {
      if (value) searchParams.set(key, "true");
    } else if (typeof value === "number" && Number.isFinite(value)) {
      searchParams.set(key, String(value));
    }
  }
  const encoded = searchParams.toString();
  return encoded ? `?${encoded}` : "";
}

function observeBackendAuthMode(response: Response): void {
  const headerMode = (response.headers.get("X-Auth-Mode") || "").trim().toLowerCase();
  if (headerMode === "bonc_jwt" || headerMode === "invalid") {
    activeCsrfToken = null;
    setRuntimeAuthModeOverride("bonc");
  }
}

async function adminFetch(
  path: string,
  init: RequestInit = {},
  options: { notifyOnUnauthorized?: boolean; allowRefreshRetry?: boolean } = {},
): Promise<Response> {
  const method = (init.method || "GET").toUpperCase();
  const isBoncMode = getEffectiveFrontendAuthMode() === "bonc";

  const execute = async (overrideBearerToken?: string | null): Promise<Response> => {
    const headers = new Headers(init.headers);
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }

    if (isBoncMode) {
      // BONC mode uses stateless Bearer tokens supplied strictly in-memory by the host.
      // Never attach cookie CSRF tokens or send ambient local session cookies.
      headers.delete("X-CSRF-Token");
      const token =
        overrideBearerToken !== undefined
          ? overrideBearerToken
          : await getBoncAccessToken();
      if (token) {
        headers.set("Authorization", `Bearer ${token}`);
      } else {
        headers.delete("Authorization");
      }
      return fetch(`${ADMIN_API_BASE}${path}`, {
        ...init,
        method,
        headers,
        credentials: "omit",
      });
    }

    // Explicit local-development cookie session mode (transition only).
    if (!SAFE_METHODS.has(method) && activeCsrfToken) {
      headers.set("X-CSRF-Token", activeCsrfToken);
    }
    return fetch(`${ADMIN_API_BASE}${path}`, {
      ...init,
      method,
      headers,
      credentials: "include",
    });
  };

  let response = await execute();
  observeBackendAuthMode(response);

  // When BONC access token expires (401), delegate refresh ONCE to the host BONC application.
  if (
    response.status === 401 &&
    isBoncMode &&
    options.allowRefreshRetry !== false
  ) {
    const refreshedToken = await refreshBoncAccessToken();
    if (refreshedToken) {
      response = await execute(refreshedToken);
      observeBackendAuthMode(response);
    }
  }

  if (response.status === 401) {
    activeCsrfToken = null;
    if (options.notifyOnUnauthorized !== false) {
      unauthorizedHandler?.();
    }
  }
  return response;
}

async function readJson<T>(response: Response, allowStatuses: number[] = []): Promise<T> {
  const text = await response.text();
  let payload: unknown;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    throw new ApiError(
      `Search Admin API returned an unreadable response (HTTP ${response.status}).`,
      response.status,
    );
  }

  if (!response.ok && !allowStatuses.includes(response.status)) {
    const message =
      payload && typeof payload === "object" && "detail" in payload && typeof payload.detail === "string"
        ? payload.detail
        : payload && typeof payload === "object" && "message" in payload && typeof payload.message === "string"
          ? payload.message
          : `Request failed with HTTP ${response.status}.`;
    if (response.status === 403) {
      if (message.toLowerCase().includes("csrf")) {
        csrfErrorHandler?.(message);
      } else {
        forbiddenHandler?.(message);
      }
    }
    throw new ApiError(message, response.status);
  }
  return payload as T;
}

// ---------------------------------------------------------------------------
// Public General Search Platform Discovery (Unauthenticated)
// ---------------------------------------------------------------------------

export async function getPublicPlatformCategories(): Promise<PublicPlatformCategorySummary[]> {
  const response = await fetch(`${ADMIN_API_BASE}/api/platform/categories`, {
    method: "GET",
    headers: { Accept: "application/json" },
    credentials: "omit",
  });
  return readJson<PublicPlatformCategorySummary[]>(response);
}

// ---------------------------------------------------------------------------
// Admin Authentication (BONC Host Bearer Token or Explicit Local-Dev Session)
// ---------------------------------------------------------------------------

export async function getAdminSession(): Promise<AdminSessionInfo | null> {
  const response = await adminFetch(
    "/api/admin/auth/session",
    { method: "GET" },
    { notifyOnUnauthorized: false },
  );
  if (response.status === 401) {
    activeCsrfToken = null;
    return null;
  }
  const session = await readJson<AdminSessionInfo>(response);
  if (session.auth_mode === "bonc_jwt" || session.local_login_enabled === false) {
    activeCsrfToken = null;
    setRuntimeAuthModeOverride("bonc");
  } else {
    activeCsrfToken = session.csrf_token || null;
  }
  return session;
}

export async function loginAdmin(input: {
  username: string;
  password: string;
}): Promise<AdminSessionInfo> {
  if (getEffectiveFrontendAuthMode() === "bonc") {
    throw new ApiError(
      "Independent Search Admin login is disabled in BONC mode. Sign in through BONC.",
      403,
    );
  }
  const response = await adminFetch(
    "/api/admin/auth/login",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: input.username.trim(),
        password: input.password,
      }),
    },
    { notifyOnUnauthorized: false },
  );
  const session = await readJson<AdminSessionInfo>(response);
  activeCsrfToken = session.csrf_token || null;
  return session;
}

export async function logoutAdmin(): Promise<{ hostHandled: boolean }> {
  if (getEffectiveFrontendAuthMode() === "bonc") {
    activeCsrfToken = null;
    const hostHandled = await invokeBoncHostLogout();
    return { hostHandled };
  }
  try {
    const response = await adminFetch(
      "/api/admin/auth/logout",
      { method: "POST" },
      { notifyOnUnauthorized: false },
    );
    if (response.status !== 401) {
      await readJson<{ authenticated: boolean; status: string }>(response);
    }
  } finally {
    activeCsrfToken = null;
  }
  return { hostHandled: false };
}

// ---------------------------------------------------------------------------
// General Search Platform Data Sources, Categories, Versioning & Rollback
// ---------------------------------------------------------------------------

export type PlatformFieldRole = "title" | "skill" | "location" | "category" | "description" | "general";

export interface PlatformFieldConfig {
  key: string;
  source_column: string;
  label: string;
  role: PlatformFieldRole;
  weight: number;
  searchable: boolean;
  semantic: boolean;
  aliases: string[];
  filterable?: boolean;
  data_type?: "text" | "keyword" | "integer" | "number" | "boolean" | "date";
  query_filter_mode?: "none" | "preferred" | "required";
  query_match?: "any" | "all";
}

export interface PlatformSynonymGroup {
  terms: string[];
}

export interface PlatformRulesConfig {
  lexical_enabled: boolean;
  semantic_enabled: boolean;
  semantic_min_score: number;
  semantic_high_confidence_score?: number;
  semantic_candidate_limit: number;
  lexical_weight: number;
  semantic_weight: number;
}

export interface PlatformSourceFilter {
  column: string;
  operator: "eq" | "ne" | "in" | "is_null" | "not_null";
  value?: string | number | boolean | null;
  values?: Array<string | number | boolean>;
}

export interface PlatformCategoryConfig {
  category_id: string;
  display_name: string;
  description?: string | null;
  source:
    | { type: "push" }
    | {
        type: "sqlserver";
        connection_env: string;
        schema: string;
        table: string;
        id_column: string;
        max_records: number;
        filters: PlatformSourceFilter[];
      };
  fields: PlatformFieldConfig[];
  synonyms?: PlatformSynonymGroup[];
  rules: PlatformRulesConfig;
  active: boolean;
  public_search_enabled: boolean;
}

export interface PlatformSourceProfile {
  profile_id: string;
  connection_env: string;
}

export interface PlatformSourceColumn {
  name: string;
  data_type: string;
  nullable: boolean;
  is_primary_key?: boolean;
  is_foreign_key?: boolean;
}

export interface PlatformSourceTable {
  schema: string;
  name: string;
  type: "BASE TABLE" | "VIEW" | string;
  primary_key_columns?: string[];
  columns: PlatformSourceColumn[];
}

export interface PlatformSourceRelationship {
  constraint_name: string;
  from_schema: string;
  from_table: string;
  to_schema: string;
  to_table: string;
  columns: Array<{
    from_column: string;
    to_column: string;
    ordinal_position: number;
  }>;
}

export interface PlatformSourceCatalog {
  profile_id: string;
  database: string;
  schemas: string[];
  tables: PlatformSourceTable[];
  relationships?: PlatformSourceRelationship[];
}

export interface PlatformMappingSuggestionField extends PlatformFieldConfig {
  confidence: "high" | "medium" | "low" | string;
  reason: string;
}

export interface PlatformSourceMappingSuggestions {
  profile_id: string;
  database: string;
  schema: string;
  table: string;
  table_type: string;
  id_column_suggestion: {
    column: string | null;
    confidence: "high" | "medium" | "none" | string;
    reason: string;
  };
  fields: PlatformMappingSuggestionField[];
  skipped_columns: Array<{ column: string; reason: string }>;
  potential_filter_columns: string[];
  warnings: string[];
}

export interface PlatformJoinViewPreview {
  profile_id: string;
  database: string;
  view_schema: string;
  view_name: string;
  document_id_column: string;
  joined_tables: Array<{ schema: string; table: string }>;
  relationship_count: number;
  view_sql: string;
  execution_performed: false;
  warnings: string[];
}

export interface PlatformSourceValidation {
  profile_id: string;
  database: string;
  schema: string;
  table: string;
  id_column: string;
  total_rows: number;
  non_null_ids: number;
  distinct_ids: number;
  null_id_count: number;
  blank_id_count: number;
  duplicate_id_count: number;
  max_records: number;
  is_valid: boolean;
  warnings: string[];
}

export async function getPlatformSourceProfiles(): Promise<PlatformSourceProfile[]> {
  const response = await adminFetch("/api/admin/platform/sources");
  const payload = await readJson<{ items: PlatformSourceProfile[] }>(response);
  return payload.items || [];
}

export async function discoverPlatformSourceSchema(input: {
  profileId: string;
  schema?: string;
}): Promise<PlatformSourceCatalog> {
  const params = new URLSearchParams();
  if (input.schema) params.set("schema", input.schema);
  const queryString = params.toString();
  const query = queryString ? `?${queryString}` : "";
  const response = await adminFetch(
    `/api/admin/platform/sources/${encodeURIComponent(input.profileId)}/schema${query}`,
  );
  return readJson<PlatformSourceCatalog>(response);
}

export async function suggestPlatformSourceMapping(input: {
  profileId: string;
  schema: string;
  table: string;
}): Promise<PlatformSourceMappingSuggestions> {
  const params = new URLSearchParams({
    schema: input.schema,
    table: input.table,
  });
  const response = await adminFetch(
    `/api/admin/platform/sources/${encodeURIComponent(input.profileId)}/mapping-suggestions?${params.toString()}`,
  );
  return readJson<PlatformSourceMappingSuggestions>(response);
}

export async function validatePlatformSource(input: {
  profileId: string;
  schema: string;
  table: string;
  idColumn: string;
  filters: PlatformSourceFilter[];
  maxRecords: number;
}): Promise<PlatformSourceValidation> {
  const response = await adminFetch(
    `/api/admin/platform/sources/${encodeURIComponent(input.profileId)}/validate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schema: input.schema,
        table: input.table,
        id_column: input.idColumn,
        filters: input.filters,
        max_records: input.maxRecords,
      }),
    },
  );
  return readJson<PlatformSourceValidation>(response);
}

export async function previewPlatformJoinView(input: {
  profileId: string;
  baseSchema: string;
  baseTable: string;
  baseIdColumn: string;
  viewSchema: string;
  viewName: string;
  selectedRelationships: PlatformSourceRelationship[];
}): Promise<PlatformJoinViewPreview> {
  const response = await adminFetch(
    `/api/admin/platform/sources/${encodeURIComponent(input.profileId)}/join-view-preview`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        base_schema: input.baseSchema,
        base_table: input.baseTable,
        base_id_column: input.baseIdColumn,
        view_schema: input.viewSchema,
        view_name: input.viewName,
        selected_relationships: input.selectedRelationships.map((relationship) => ({
          constraint_name: relationship.constraint_name,
          from_schema: relationship.from_schema,
          from_table: relationship.from_table,
          to_schema: relationship.to_schema,
          to_table: relationship.to_table,
        })),
      }),
    },
  );
  return readJson<PlatformJoinViewPreview>(response);
}

export interface PlatformCategoryRecord {
  config: PlatformCategoryConfig;
  status: "active" | "disabled" | string;
  config_version: number;
  index_version: number;
  document_count?: number;
  updated_at_utc?: string | null;
  updated_by?: string | null;
}

export interface PlatformCategoryRollbackResponse extends PlatformCategoryRecord {
  rolled_back_from_version: number;
  previous_config_version: number;
  rollback_reason: string;
}

export interface PlatformCategoryHistoryItem {
  history_id: number;
  config_version: number;
  config: PlatformCategoryConfig;
  status: string;
  changed_at_utc?: string | null;
  changed_by?: string | null;
  change_reason?: string | null;
  rolled_back_from_version?: number | null;
}

export async function getPlatformCategories(options?: {
  signal?: AbortSignal;
}): Promise<PlatformCategoryRecord[]> {
  const response = await adminFetch(
    "/api/admin/platform/categories",
    options?.signal ? { signal: options.signal } : {},
  );
  return readJson<PlatformCategoryRecord[]>(response);
}

export async function createPlatformCategory(
  config: PlatformCategoryConfig,
): Promise<PlatformCategoryRecord> {
  const response = await adminFetch("/api/admin/platform/categories", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  return readJson<PlatformCategoryRecord>(response);
}

export async function syncPlatformCategory(
  categoryId: string,
): Promise<{ status: string; category_id: string; documents_synced: number }> {
  const response = await adminFetch(
    `/api/admin/platform/categories/${encodeURIComponent(categoryId)}/sync`,
    { method: "POST" },
  );
  return readJson(response);
}

export interface PlatformSearchResult {
  id: string;
  title: string;
  fields: Record<string, string | number | boolean | null>;
  metadata: Record<string, string | number | boolean | null>;
  score: number;
  lexical_score: number;
  phrase_score?: number;
  semantic_score: number;
  preferred_filter_bonus?: number;
  matched_fields: string[];
  ranking_signals?: {
    engine: string;
    fusion: string;
    lexical_rank: number | null;
    semantic_rank: number | null;
    bm25f_raw: number;
    query_term_coverage: number;
    matched_terms: string[];
    missing_terms: string[];
    phrase_match: boolean;
    rrf_score?: number;
    rank_fusion_score: number;
    constraint_boost: number;
  };
  exact_identifier_match?: boolean;
  category: string;
}

export interface PlatformQueryConstraint {
  field: string;
  role: PlatformFieldRole;
  values: string[];
  match: "exact_index_value";
  query_match?: "any" | "all";
  applied_as: "ranking_hint_only" | "hard_filter";
}

export interface PlatformSearchFilter {
  field: string;
  operator:
    | "eq"
    | "ne"
    | "in"
    | "contains"
    | "gte"
    | "lte"
    | "between"
    | "is_null"
    | "not_null";
  value?: string | number | boolean | null;
  values?: Array<string | number | boolean>;
}

export interface PlatformQueryPlan {
  query_type: "field_guided" | "free_text";
  matched_aliases: Record<string, string[]>;
  matched_values: Record<string, string[]>;
  constraints: PlatformQueryConstraint[];
  unmatched_tokens: string[];
  lexical_query: string;
  expanded_lexical_query: string;
  synonym_expansions: Array<{ matched_term: string; alternatives: string[] }>;
  semantic_query: string;
  filters_applied: boolean;
  automatic_filters?: PlatformQueryConstraint[];
  explicit_filters?: PlatformSearchFilter[];
  filtered_document_count?: number;
  eligible_document_count?: number;
  semantic_high_confidence_score?: number;
  semantic_candidates_kept?: number;
  semantic_candidates_rejected?: number;
  ranking_engine?: string;
  ranking_fusion?: string;
  lexical_candidates?: number;
  explanation: string;
}

export interface PlatformSearchResponse {
  query: string;
  category: string;
  query_understanding: {
    normalised_query: string;
    query_type: "field_guided" | "free_text";
    field_hints: Record<string, string[]>;
    matched_aliases: Record<string, string[]>;
    matched_values: Record<string, string[]>;
    matched_fields: Record<string, string[]>;
    constraints: PlatformQueryConstraint[];
    lexical_query: string;
    expanded_lexical_query: string;
    synonym_expansions: Array<{ matched_term: string; alternatives: string[] }>;
    unmatched_tokens: string[];
    explanation: string;
  };
  query_plan: PlatformQueryPlan;
  corrected_query?: string;
  data: PlatformSearchResult[];
  total_count: number;
  page: number;
  page_size: number;
  config_version: number;
  index_version: number;
}

export async function runPlatformAdminSearch(input: {
  query: string;
  category: string;
  page?: number;
  pageSize?: number;
  filters?: PlatformSearchFilter[];
  signal?: AbortSignal;
}): Promise<PlatformSearchResponse> {
  const response = await adminFetch("/api/admin/platform/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: input.query,
      category: input.category,
      page: input.page ?? 1,
      page_size: input.pageSize ?? 10,
      filters: input.filters ?? [],
    }),
    ...(input.signal ? { signal: input.signal } : {}),
  });
  return readJson<PlatformSearchResponse>(response);
}

export async function ingestPlatformDocuments(
  categoryId: string,
  documents: Array<{
    document_id: string;
    title?: string;
    fields: Record<string, string | number | boolean | null>;
    metadata?: Record<string, string | number | boolean | null>;
  }>,
  replaceAll = false,
): Promise<{ status: string; category_id: string; documents_ingested: number }> {
  const response = await adminFetch(
    `/api/admin/platform/categories/${encodeURIComponent(categoryId)}/ingest`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ documents, replace_all: replaceAll }),
    },
  );
  return readJson(response);
}

export async function updatePlatformCategory(input: {
  categoryId: string;
  expectedVersion: number;
  config: PlatformCategoryConfig;
  changeReason?: string;
}): Promise<PlatformCategoryRecord> {
  const response = await adminFetch(
    `/api/admin/platform/categories/${encodeURIComponent(input.categoryId)}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        expected_version: input.expectedVersion,
        config: input.config,
        change_reason: input.changeReason?.trim() || null,
      }),
    },
  );
  return readJson<PlatformCategoryRecord>(response);
}

export async function rollbackPlatformCategory(input: {
  categoryId: string;
  targetVersion: number;
  expectedVersion: number;
  reason: string;
}): Promise<PlatformCategoryRollbackResponse> {
  const response = await adminFetch(
    `/api/admin/platform/categories/${encodeURIComponent(input.categoryId)}/rollback`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_version: input.targetVersion,
        expected_version: input.expectedVersion,
        reason: input.reason.trim(),
      }),
    },
  );
  return readJson<PlatformCategoryRollbackResponse>(response);
}

export async function getPlatformCategoryHistory(
  categoryId: string,
  options?: { signal?: AbortSignal },
): Promise<PlatformCategoryHistoryItem[]> {
  const response = await adminFetch(
    `/api/admin/platform/categories/${encodeURIComponent(categoryId)}/history`,
    options?.signal ? { signal: options.signal } : {},
  );
  const payload = await readJson<{ items: PlatformCategoryHistoryItem[] }>(response);
  return payload.items || [];
}

export interface PlatformFeedbackItem {
  feedback_id: number;
  query: string;
  document_id: string;
  is_relevant: boolean;
  comment?: string | null;
  created_at_utc?: string | null;
  created_by?: string | null;
  result_rank?: number | null;
  result_score?: number | null;
  config_version?: number | null;
  index_version?: number | null;
}

export interface PlatformFeedbackSummary {
  total_count: number;
  relevant_count: number;
  not_relevant_count: number;
  items: PlatformFeedbackItem[];
}

export async function getPlatformFeedback(
  categoryId: string,
  limit = 100,
  options?: { signal?: AbortSignal },
): Promise<PlatformFeedbackSummary> {
  const response = await adminFetch(
    `/api/admin/platform/categories/${encodeURIComponent(categoryId)}/feedback?limit=${limit}`,
    options?.signal ? { signal: options.signal } : {},
  );
  return readJson<PlatformFeedbackSummary>(response);
}

// ---------------------------------------------------------------------------
// System Health, Search Logs, and Analytics / KPI APIs
// ---------------------------------------------------------------------------

export type HealthState =
  | "healthy"
  | "degraded"
  | "unavailable"
  | "unhealthy"
  | "disabled";

export interface SystemHealthApiComponent {
  status: HealthState;
  service: string;
  detail: string;
}

export interface SystemHealthDatabaseComponent {
  status: HealthState;
  startup_ready: boolean;
  latency_ms: number | null;
  detail: string;
}

export interface SystemHealthEmbeddingComponent {
  status: HealthState;
  model_name: string | null;
  embedding_dim: number | null;
  loaded: boolean;
  startup_ready: boolean;
  detail: string;
}

export interface SystemHealthLegacyIndexItem {
  status: string;
  health_state: HealthState;
  count: number;
  index_built: boolean;
  last_error?: string | null;
}

export interface SystemHealthSearchIndexesComponent {
  enabled?: boolean;
  read_only?: boolean;
  status: HealthState;
  ready_count: number;
  total_count: number;
  total_records: number;
  detail: string;
  indexes: Record<string, SystemHealthLegacyIndexItem>;
}

export interface SystemHealthCategoryItem {
  category_id: string;
  display_name: string;
  status: string;
  active: boolean;
  public_search_enabled: boolean;
  source_type: "sqlserver" | "push" | string;
  source_target: string;
  document_count: number;
  config_version: number;
  index_version: number;
  updated_at_utc: string | null;
  updated_by: string | null;
  cache_status: "warm" | "cold" | "stale" | "empty" | string;
  cached_document_count: number | null;
  vector_index_built: boolean;
  health_state: HealthState;
}

export interface SystemHealthCategoriesComponent {
  status: HealthState;
  total_categories: number | null;
  active_categories: number | null;
  total_documents: number | null;
  source_profile_count: number;
  source_profiles: PlatformSourceProfile[];
  detail: string;
  items: SystemHealthCategoryItem[];
}

export interface ApiFailureEvent {
  request_log_id: number;
  occurred_at_utc: string | null;
  request_id: string;
  http_method: string;
  endpoint: string;
  http_status: number;
  duration_ms: number;
  error_code: string | null;
  error_summary: string | null;
}

export interface SystemHealthRecentFailuresComponent {
  status: HealthState;
  window_hours: number;
  total_api_requests_24h: number | null;
  server_failures_24h: number | null;
  client_errors_24h: number | null;
  server_failure_rate_24h_pct: number | null;
  detail: string;
  items: ApiFailureEvent[];
}

export interface SystemHealthResponse {
  status: HealthState;
  service: string;
  checked_at_utc: string;
  initialization_error: string | null;
  components: {
    api: SystemHealthApiComponent;
    database: SystemHealthDatabaseComponent;
    embedding_model: SystemHealthEmbeddingComponent;
    production_search?: SystemHealthSearchIndexesComponent;
    search_indexes: SystemHealthSearchIndexesComponent;
    category_indexes: SystemHealthCategoriesComponent;
    recent_server_failures: SystemHealthRecentFailuresComponent;
  };
}

export async function getSystemHealth(recentFailuresLimit = 10): Promise<SystemHealthResponse> {
  const qs = buildQueryString({ recent_failures_limit: recentFailuresLimit });
  const response = await adminFetch(`/api/admin/platform/system-health${qs}`);
  return readJson<SystemHealthResponse>(response);
}

export type SearchIdentityType = "authenticated" | "anonymous" | "session";
export type SearchStatusClass = "2xx" | "4xx" | "5xx";
export type SearchLogOutcome =
  | "success"
  | "zero_results"
  | "client_error"
  | "server_error"
  | "failed";
export type SearchSurfaceType = "public" | "admin";

export interface SearchLogsQueryParams {
  page?: number;
  page_size?: number;
  start_utc?: string;
  end_utc?: string;
  user_id?: string;
  identity_type?: SearchIdentityType | "";
  category?: string;
  query?: string;
  status_code?: number | null;
  status_class?: SearchStatusClass | "";
  outcome?: SearchLogOutcome | "";
  zero_results_only?: boolean;
  failed_only?: boolean;
  surface?: SearchSurfaceType | "";
}

export interface SearchLogItem {
  search_log_id: number;
  occurred_at_utc: string | null;
  request_id: string;
  endpoint_path: string;
  search_surface: SearchSurfaceType | string;
  category_id: string;
  query: string;
  authenticated_user_id: string | null;
  identity_type: SearchIdentityType | string;
  http_status: number;
  outcome: string;
  result_count: number | null;
  page_no: number;
  page_size: number;
  filter_count: number;
  duration_ms: number;
  config_version: number | null;
  index_version: number | null;
  error_code: string | null;
  error_category: string | null;
}

export interface PaginationMetadata {
  page: number;
  page_size: number;
  total_count: number;
  total_pages: number;
}

export interface SearchLogsSummary {
  total_attempts: number;
  unique_authenticated_users: number;
  authenticated_attempts: number;
  anonymous_attempts: number;
  session_attempts: number;
  unauthenticated_attempts: number;
  successful_attempts: number;
  attempts_with_results: number;
  zero_result_attempts: number;
  client_error_attempts_4xx: number;
  server_error_attempts_5xx: number;
  failed_attempts: number;
  avg_duration_ms: number | null;
}

export interface SearchLogsResponse {
  filters: Record<string, unknown>;
  pagination: PaginationMetadata;
  summary: SearchLogsSummary;
  items: SearchLogItem[];
}

export async function getSearchLogs(params: SearchLogsQueryParams = {}): Promise<SearchLogsResponse> {
  const qs = buildQueryString({
    page: params.page ?? 1,
    page_size: params.page_size ?? 25,
    start_utc: params.start_utc,
    end_utc: params.end_utc,
    user_id: params.user_id,
    identity_type: params.identity_type || undefined,
    category: params.category,
    query: params.query,
    status_code: params.status_code ?? undefined,
    status_class: params.status_class || undefined,
    outcome: params.outcome || undefined,
    zero_results_only: params.zero_results_only,
    failed_only: params.failed_only,
    surface: params.surface || undefined,
  });
  const response = await adminFetch(`/api/admin/platform/search-logs${qs}`);
  return readJson<SearchLogsResponse>(response);
}

export interface SearchLogUsersQueryParams {
  page?: number;
  page_size?: number;
  start_utc?: string;
  end_utc?: string;
  category?: string;
  user_id?: string;
}

export interface SearchLogUserActivityItem {
  user_id: string;
  total_attempts: number;
  successful_attempts: number;
  zero_result_attempts: number;
  client_error_attempts_4xx: number;
  server_error_attempts_5xx: number;
  avg_duration_ms: number | null;
  last_search_at_utc: string | null;
}

export interface SearchLogUsersSummary {
  total_attempts: number;
  unique_authenticated_users: number;
  authenticated_attempts: number;
  anonymous_attempts: number;
  session_attempts: number;
  unauthenticated_attempts: number;
}

export interface SearchLogUsersResponse {
  filters: Record<string, unknown>;
  pagination: PaginationMetadata;
  summary: SearchLogUsersSummary;
  items: SearchLogUserActivityItem[];
}

export async function getSearchLogsByUser(
  params: SearchLogUsersQueryParams = {},
): Promise<SearchLogUsersResponse> {
  const qs = buildQueryString({
    page: params.page ?? 1,
    page_size: params.page_size ?? 25,
    start_utc: params.start_utc,
    end_utc: params.end_utc,
    category: params.category,
    user_id: params.user_id,
  });
  const response = await adminFetch(`/api/admin/platform/search-logs/users${qs}`);
  return readJson<SearchLogUsersResponse>(response);
}

export interface KpiMetricsQueryParams {
  start_utc?: string;
  end_utc?: string;
  category?: string;
  top_endpoints_limit?: number;
  recent_failures_limit?: number;
}

export interface SearchKpisMetrics {
  total_search_attempts: number;
  unique_authenticated_users: number;
  authenticated_searches: number;
  anonymous_searches: number;
  session_searches: number;
  unauthenticated_searches: number;
  successful_searches: number;
  searches_with_results: number;
  zero_result_searches: number;
  zero_result_rate_pct: number | null;
  zero_result_rate_numerator: number;
  zero_result_rate_denominator: number;
  zero_result_rate_definition: string;
  client_error_searches_4xx: number;
  server_error_searches_5xx: number;
  search_server_failure_rate_pct: number | null;
  avg_response_time_ms: number | null;
}

export interface ApiFailureEndpointSummary {
  endpoint: string;
  total_requests: number;
  server_failure_count_5xx: number;
  server_failure_rate_pct: number | null;
  client_error_count_4xx: number;
  avg_duration_ms: number | null;
  last_failure_at_utc: string | null;
}

export interface ApiMonitoringMetrics {
  total_api_requests: number;
  successful_requests: number;
  client_error_requests_4xx: number;
  server_failure_requests_5xx: number;
  server_failure_rate_pct: number | null;
  server_failure_rate_numerator: number;
  server_failure_rate_denominator: number;
  server_failure_rate_definition: string;
  client_error_rate_pct: number | null;
  avg_response_time_ms: number | null;
  most_failure_prone_endpoints: ApiFailureEndpointSummary[];
  recent_server_failures: ApiFailureEvent[];
}

export interface RelevanceSummaryMetrics {
  relevant_judgments: number;
  not_relevant_judgments: number;
  total_rated_results: number;
  positive_feedback_percentage: number | null;
  negative_feedback_percentage: number | null;
  negative_feedback_numerator: number;
  negative_feedback_denominator: number;
  negative_feedback_definition: string;
}

export interface KpiMetricsResponse {
  window: {
    start_utc: string | null;
    end_utc: string | null;
    category: string | null;
  };
  search_kpis: SearchKpisMetrics;
  api_monitoring: ApiMonitoringMetrics;
  relevance_feedback: RelevanceSummaryMetrics & {
    metric_classification: string;
    is_ground_truth: boolean;
    disclaimer: string;
  };
}

export async function getKpiMetrics(params: KpiMetricsQueryParams = {}): Promise<KpiMetricsResponse> {
  const qs = buildQueryString({
    start_utc: params.start_utc,
    end_utc: params.end_utc,
    category: params.category,
    top_endpoints_limit: params.top_endpoints_limit,
    recent_failures_limit: params.recent_failures_limit,
  });
  const response = await adminFetch(`/api/admin/platform/metrics/kpis${qs}`);
  return readJson<KpiMetricsResponse>(response);
}

export interface ApiFailureMetricsQueryParams {
  start_utc?: string;
  end_utc?: string;
  endpoint?: string;
  top_endpoints_limit?: number;
  recent_failures_limit?: number;
}

export interface ApiFailureMetricsResponse extends ApiMonitoringMetrics {
  window: {
    start_utc: string | null;
    end_utc: string | null;
    endpoint: string | null;
  };
}

export async function getApiFailureMetrics(
  params: ApiFailureMetricsQueryParams = {},
): Promise<ApiFailureMetricsResponse> {
  const qs = buildQueryString({
    start_utc: params.start_utc,
    end_utc: params.end_utc,
    endpoint: params.endpoint,
    top_endpoints_limit: params.top_endpoints_limit,
    recent_failures_limit: params.recent_failures_limit,
  });
  const response = await adminFetch(`/api/admin/platform/metrics/api-failures${qs}`);
  return readJson<ApiFailureMetricsResponse>(response);
}

export interface RelevanceMetricsQueryParams {
  start_utc?: string;
  end_utc?: string;
  category?: string;
  recent_negative_limit?: number;
}

export interface RelevanceCategoryBreakdownItem {
  category_id: string;
  display_name: string;
  relevant_judgments: number;
  not_relevant_judgments: number;
  total_rated_results: number;
  positive_feedback_percentage: number | null;
  negative_feedback_percentage: number | null;
  negative_feedback_numerator: number;
  negative_feedback_denominator: number;
}

export interface RelevanceNegativeExampleItem {
  feedback_id: number;
  category_id: string;
  query: string;
  document_id: string;
  comment: string | null;
  result_rank: number | null;
  result_score: number | null;
  config_version: number | null;
  index_version: number | null;
  created_at_utc: string | null;
  created_by: string | null;
}

export interface RelevanceMetricsResponse {
  window: {
    start_utc: string | null;
    end_utc: string | null;
    category: string | null;
  };
  metric_classification: string;
  is_ground_truth: boolean;
  disclaimer: string;
  summary: RelevanceSummaryMetrics;
  category_breakdown: RelevanceCategoryBreakdownItem[];
  recent_negative_examples: RelevanceNegativeExampleItem[];
}

export async function getRelevanceMetrics(
  params: RelevanceMetricsQueryParams = {},
): Promise<RelevanceMetricsResponse> {
  const qs = buildQueryString({
    start_utc: params.start_utc,
    end_utc: params.end_utc,
    category: params.category,
    recent_negative_limit: params.recent_negative_limit,
  });
  const response = await adminFetch(`/api/admin/platform/metrics/relevance${qs}`);
  return readJson<RelevanceMetricsResponse>(response);
}
