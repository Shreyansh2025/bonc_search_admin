import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  hasInMemoryBoncAccessToken,
  resetBoncAuthAdapterForTests,
  setInMemoryBoncAccessToken,
} from "../../frontend/src/lib/bonc-auth.ts";
import * as searchApi from "../../frontend/src/lib/search-api.ts";
import {
  ADMIN_API_BASE,
  ApiError,
  buildQueryString,
  clearClientSessionState,
  getAdminSession,
  getApiFailureMetrics,
  getKpiMetrics,
  getPlatformCategories,
  getPlatformCategoryHistory,
  getPlatformFeedback,
  getPlatformSourceProfiles,
  getRelevanceMetrics,
  getSearchLogs,
  getSearchLogsByUser,
  getSystemHealth,
  logoutAdmin,
  rollbackPlatformCategory,
  runPlatformAdminSearch,
  setForbiddenHandler,
  setUnauthorizedHandler,
  syncPlatformCategory,
} from "../../frontend/src/lib/search-api.ts";

interface RecordedCall {
  url: string;
  init: RequestInit;
}

const originalFetch = globalThis.fetch;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_SRC = path.resolve(__dirname, "../../frontend/src");

function mockFetchSequence(
  responses: Array<{ status: number; body: unknown }>,
): RecordedCall[] {
  const calls: RecordedCall[] = [];
  let index = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    calls.push({ url: String(input), init });
    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return new Response(JSON.stringify(next.body), {
      status: next.status,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  return calls;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  clearClientSessionState();
  resetBoncAuthAdapterForTests();
  setUnauthorizedHandler(null);
  setForbiddenHandler(null);
});

describe("Search Admin frontend API contracts, Generic Engine Testing, BONC Bearer auth & boundary guards", () => {
  it("defaults ADMIN_API_BASE to /admin-api (independent Search Admin Backend)", () => {
    assert.equal(ADMIN_API_BASE, "/admin-api");
  });

  it("builds clean query strings omitting empty/false values", () => {
    assert.equal(
      buildQueryString({
        page: 2,
        page_size: 25,
        category: " people ",
        query: "",
        zero_results_only: true,
        failed_only: false,
        status_code: 403,
      }),
      "?page=2&page_size=25&category=people&zero_results_only=true&status_code=403",
    );
  });

  it("verifies BONC session, sends Bearer token with credentials:omit on writes/testing, and clears memory on logout", async () => {
    setInMemoryBoncAccessToken("bonc-demo-admin-jwt");
    const calls = mockFetchSequence([
      {
        status: 200,
        body: {
          authenticated: true,
          auth_method: "bonc_jwt",
          auth_mode: "bonc_jwt",
          user_id: "11111111-aaaa-4bbb-8ccc-000000000001",
          username: "admin@bonc",
          actor: "11111111-aaaa-4bbb-8ccc-000000000001",
          roles: ["Admin"],
        },
      },
      {
        status: 200,
        body: {
          query: "python backend",
          category: "people",
          query_understanding: {
            normalised_query: "python backend",
            query_type: "free_text",
            field_hints: {},
            matched_aliases: {},
            matched_values: {},
            matched_fields: {},
            constraints: [],
            lexical_query: "python backend",
            expanded_lexical_query: "python backend",
            synonym_expansions: [],
            unmatched_tokens: [],
            explanation: "Free text query",
          },
          query_plan: {
            query_type: "free_text",
            matched_aliases: {},
            matched_values: {},
            constraints: [],
            unmatched_tokens: [],
            lexical_query: "python backend",
            expanded_lexical_query: "python backend",
            synonym_expansions: [],
            semantic_query: "python backend",
            filters_applied: false,
            explanation: "Free text query",
          },
          data: [],
          total_count: 0,
          page: 1,
          page_size: 10,
          config_version: 2,
          index_version: 3,
        },
      },
      {
        status: 200,
        body: {
          config: { category_id: "people", display_name: "People" },
          status: "active",
          config_version: 4,
          index_version: 5,
          rolled_back_from_version: 2,
          previous_config_version: 3,
          rollback_reason: "Restore v2",
        },
      },
    ]);

    const session = await getAdminSession();
    assert.equal(session?.authenticated, true);
    assert.equal(calls[0].url, `${ADMIN_API_BASE}/api/admin/auth/session`);
    assert.equal(calls[0].init.credentials, "omit");
    assert.equal(
      new Headers(calls[0].init.headers).get("Authorization"),
      "Bearer bonc-demo-admin-jwt",
    );

    const searchResp = await runPlatformAdminSearch({
      query: "python backend",
      category: "people",
      page: 1,
      pageSize: 10,
      filters: [{ field: "location", operator: "eq", value: "Indore" }],
    });
    assert.equal(searchResp.category, "people");
    assert.equal(calls[1].url, `${ADMIN_API_BASE}/api/admin/platform/search`);
    assert.equal(calls[1].init.method, "POST");
    assert.equal(calls[1].init.credentials, "omit");
    const searchHeaders = new Headers(calls[1].init.headers);
    assert.equal(searchHeaders.get("Authorization"), "Bearer bonc-demo-admin-jwt");
    assert.equal(searchHeaders.get("X-CSRF-Token"), null);

    const restored = await rollbackPlatformCategory({
      categoryId: "people",
      targetVersion: 2,
      expectedVersion: 3,
      reason: "Restore v2",
    });
    assert.equal(restored.config_version, 4);
    assert.equal(calls[2].url, `${ADMIN_API_BASE}/api/admin/platform/categories/people/rollback`);
    assert.equal(calls[2].init.method, "POST");
    assert.equal(
      new Headers(calls[2].init.headers).get("Authorization"),
      "Bearer bonc-demo-admin-jwt",
    );

    await logoutAdmin();
    assert.equal(hasInMemoryBoncAccessToken(), false);
    assert.equal(calls.length, 3);
  });

  it("handles 401 expiry and 403 forbidden responses properly", async () => {
    let unauthorizedCount = 0;
    let forbiddenMessage = "";
    setUnauthorizedHandler(() => {
      unauthorizedCount += 1;
    });
    setForbiddenHandler((msg) => {
      forbiddenMessage = msg;
    });

    setInMemoryBoncAccessToken("bonc-token");
    mockFetchSequence([
      { status: 403, body: { detail: "Administrator access required" } },
      { status: 401, body: { detail: "Authentication required" } },
    ]);

    await assert.rejects(
      () =>
        rollbackPlatformCategory({
          categoryId: "people",
          targetVersion: 1,
          expectedVersion: 2,
          reason: "test",
        }),
      (err: unknown) => err instanceof ApiError && err.status === 403,
    );
    assert.equal(forbiddenMessage, "Administrator access required");
    assert.equal(unauthorizedCount, 0);
    assert.equal(hasInMemoryBoncAccessToken(), false);

    setInMemoryBoncAccessToken("expired-bonc-token");
    await assert.rejects(
      () => getSystemHealth(),
      (err: unknown) => err instanceof ApiError && err.status === 401,
    );
    assert.equal(unauthorizedCount, 1);
    assert.equal(hasInMemoryBoncAccessToken(), false);
  });

  it("wires Health, Logs, Metrics, Sources, Categories, History, Sync, and read-only Feedback routes cleanly", async () => {
    setInMemoryBoncAccessToken("bonc-admin-token");
    const calls = mockFetchSequence([
      { status: 200, body: { status: "healthy", components: {} } },
      { status: 200, body: { filters: {}, pagination: {}, summary: {}, items: [] } },
      { status: 200, body: { filters: {}, pagination: {}, summary: {}, items: [] } },
      { status: 200, body: { window: {}, search_kpis: {}, api_monitoring: {}, relevance_feedback: {} } },
      { status: 200, body: { window: {}, total_api_requests: 0 } },
      { status: 200, body: { window: {}, summary: {}, category_breakdown: [], recent_negative_examples: [] } },
      { status: 200, body: { items: [{ profile_id: "BONC_DEV", connection_env: "SEARCH_SOURCE_BONC_DEV" }] } },
      { status: 200, body: [] },
      { status: 200, body: { items: [] } },
      { status: 200, body: { status: "ok", category_id: "people", documents_synced: 10 } },
      { status: 200, body: { total_count: 0, relevant_count: 0, not_relevant_count: 0, items: [] } },
    ]);

    await getSystemHealth(12);
    assert.equal(calls[0].url, `${ADMIN_API_BASE}/api/admin/platform/system-health?recent_failures_limit=12`);

    await getSearchLogs({
      page: 2,
      page_size: 50,
      start_utc: "2026-11-01",
      end_utc: "2026-11-22",
      user_id: "alice",
      identity_type: "authenticated",
      category: "people",
      query: "python",
      status_code: 200,
      status_class: "2xx",
      outcome: "zero_results",
      zero_results_only: true,
      failed_only: false,
      surface: "public",
    });
    assert.equal(
      calls[1].url,
      `${ADMIN_API_BASE}/api/admin/platform/search-logs?page=2&page_size=50&start_utc=2026-11-01&end_utc=2026-11-22&user_id=alice&identity_type=authenticated&category=people&query=python&status_code=200&status_class=2xx&outcome=zero_results&zero_results_only=true&surface=public`,
    );

    await getSearchLogsByUser({ page: 1, page_size: 25, category: "jobs", user_id: "bob" });
    assert.equal(calls[2].url, `${ADMIN_API_BASE}/api/admin/platform/search-logs/users?page=1&page_size=25&category=jobs&user_id=bob`);

    await getKpiMetrics({ category: "articles", top_endpoints_limit: 10, recent_failures_limit: 20 });
    assert.equal(calls[3].url, `${ADMIN_API_BASE}/api/admin/platform/metrics/kpis?category=articles&top_endpoints_limit=10&recent_failures_limit=20`);

    await getApiFailureMetrics({ endpoint: "/api/platform/search" });
    assert.equal(calls[4].url, `${ADMIN_API_BASE}/api/admin/platform/metrics/api-failures?endpoint=%2Fapi%2Fplatform%2Fsearch`);

    await getRelevanceMetrics({ category: "people", recent_negative_limit: 15 });
    assert.equal(calls[5].url, `${ADMIN_API_BASE}/api/admin/platform/metrics/relevance?category=people&recent_negative_limit=15`);

    const profiles = await getPlatformSourceProfiles();
    assert.equal(profiles.length, 1);
    assert.equal(calls[6].url, `${ADMIN_API_BASE}/api/admin/platform/sources`);

    await getPlatformCategories();
    assert.equal(calls[7].url, `${ADMIN_API_BASE}/api/admin/platform/categories`);

    await getPlatformCategoryHistory("people");
    assert.equal(calls[8].url, `${ADMIN_API_BASE}/api/admin/platform/categories/people/history`);

    await syncPlatformCategory("people");
    assert.equal(calls[9].url, `${ADMIN_API_BASE}/api/admin/platform/categories/people/sync`);

    await getPlatformFeedback("people", 50);
    assert.equal(calls[10].url, `${ADMIN_API_BASE}/api/admin/platform/categories/people/feedback?limit=50`);
  });

  it("enforces boundaries: Generic Engine Testing kept; legacy login, CSRF, Catalog Thresholds, inline feedback writing, B2B playground & BrochureIQ removed", () => {
    assert.equal("runPlatformAdminSearch" in searchApi, true);

    assert.equal("loginAdmin" in searchApi, false);
    assert.equal("getInMemoryCsrfToken" in searchApi, false);
    assert.equal("setCsrfErrorHandler" in searchApi, false);
    assert.equal("getSearchSettings" in searchApi, false);
    assert.equal("updateSearchSettings" in searchApi, false);
    assert.equal("getSearchSettingsHistory" in searchApi, false);
    assert.equal("recordPlatformFeedback" in searchApi, false);
    assert.equal("runSearch" in searchApi, false);
    assert.equal("getReadiness" in searchApi, false);

    const filesToCheck = [
      path.join(FRONTEND_SRC, "App.tsx"),
      path.join(FRONTEND_SRC, "components", "platform-panel.tsx"),
      path.join(FRONTEND_SRC, "lib", "search-api.ts"),
      path.join(FRONTEND_SRC, "components", "search-logs-panel.tsx"),
      path.join(FRONTEND_SRC, "components", "system-health-panel.tsx"),
    ];

    const platformPanelContent = fs.readFileSync(
      path.join(FRONTEND_SRC, "components", "platform-panel.tsx"),
      "utf8",
    );
    assert.equal(
      platformPanelContent.includes("Generic Search Engine Testing"),
      true,
      "platform-panel.tsx must include Generic Search Engine Testing UI",
    );

    for (const filePath of filesToCheck) {
      const content = fs.readFileSync(filePath, "utf8");
      assert.equal(content.includes("Catalog Thresholds"), false, `${filePath} must not contain Catalog Thresholds`);
      assert.equal(content.includes("/api/admin/search-settings"), false, `${filePath} must not call legacy search-settings`);
      assert.equal(content.includes("B2B Catalog Playground"), false, `${filePath} must not contain B2B Catalog Playground`);
      assert.equal(content.includes("Mark Relevant"), false, `${filePath} must not contain inline Mark Relevant controls`);
      assert.equal(content.includes("BrochureIQ Products"), false, `${filePath} must not display BrochureIQ Products`);
      assert.equal(content.includes("localProducts"), false, `${filePath} must not reference localProducts`);
      assert.equal(content.includes("SEARCH_AI_ADMIN_API_TOKEN"), false, `${filePath} must not reference backend tokens`);
      assert.equal(content.includes("SEARCH_ADMIN_SERVICE_TOKEN"), false, `${filePath} must not reference backend tokens`);
      assert.equal(content.includes("SEARCH_ADMIN_API_TOKEN"), false, `${filePath} must not reference backend tokens`);
      assert.equal(content.includes("pyodbc"), false, `${filePath} must not reference SQL Server drivers`);
      assert.equal(content.includes("react-frontend"), false, `${filePath} must not import BrochureIQ frontend`);
      assert.equal(content.includes("@workspace/"), false, `${filePath} must not import monorepo workspace libs`);
    }
  });
});
