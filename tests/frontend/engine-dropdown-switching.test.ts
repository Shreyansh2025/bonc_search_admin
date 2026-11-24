import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  EngineRequestCoordinator,
  createInitialTestingContext,
  isAbortError,
  isSearchResultForActiveEngine,
  resolveCategoryAfterRefresh,
  resolveSelectedEngineRecord,
  transitionTestingEngine,
} from "../../frontend/src/lib/engine-testing-state.ts";
import {
  clearClientSessionState,
  runPlatformAdminSearch,
  type PlatformCategoryRecord,
  type PlatformSearchResponse,
} from "../../frontend/src/lib/search-api.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_SRC = path.resolve(__dirname, "../../frontend/src");
const originalFetch = globalThis.fetch;

function makeCategories(): PlatformCategoryRecord[] {
  return [
    {
      config: {
        category_id: "general_test",
        display_name: "General Search",
        description: "General Search push test engine",
        source: { type: "push" },
        fields: [
          {
            key: "title",
            source_column: "title",
            label: "Title",
            role: "title",
            weight: 4,
            searchable: true,
            semantic: true,
            aliases: ["title"],
            filterable: false,
            data_type: "text",
            query_filter_mode: "none",
            query_match: "all",
          },
          {
            key: "type",
            source_column: "type",
            label: "Type",
            role: "category",
            weight: 2,
            searchable: true,
            semantic: false,
            aliases: ["type"],
            filterable: true,
            data_type: "keyword",
            query_filter_mode: "preferred",
            query_match: "any",
          },
        ],
        synonyms: [],
        rules: {
          lexical_enabled: true,
          semantic_enabled: true,
          semantic_min_score: 20,
          semantic_high_confidence_score: 75,
          semantic_candidate_limit: 50,
          lexical_weight: 0.65,
          semantic_weight: 0.35,
        },
        active: true,
        public_search_enabled: true,
      },
      status: "active",
      config_version: 2,
      index_version: 4,
      document_count: 15,
    },
    {
      config: {
        category_id: "people",
        display_name: "People",
        description: "Search BONC people profiles",
        source: {
          type: "sqlserver",
          connection_env: "SEARCH_SOURCE_BONC_DEV",
          schema: "searchai",
          table: "vw_Search_People_v2",
          id_column: "DocumentId",
          max_records: 50000,
          filters: [],
        },
        fields: [
          {
            key: "full_name",
            source_column: "FullName",
            label: "Full Name",
            role: "title",
            weight: 4,
            searchable: true,
            semantic: false,
            aliases: ["name"],
            filterable: false,
            data_type: "text",
            query_filter_mode: "none",
            query_match: "all",
          },
          {
            key: "location",
            source_column: "Location",
            label: "Location",
            role: "location",
            weight: 2,
            searchable: true,
            semantic: false,
            aliases: ["city"],
            filterable: true,
            data_type: "keyword",
            query_filter_mode: "preferred",
            query_match: "any",
          },
        ],
        synonyms: [],
        rules: {
          lexical_enabled: true,
          semantic_enabled: true,
          semantic_min_score: 20,
          semantic_high_confidence_score: 75,
          semantic_candidate_limit: 50,
          lexical_weight: 0.65,
          semantic_weight: 0.35,
        },
        active: true,
        public_search_enabled: false,
      },
      status: "active",
      config_version: 3,
      index_version: 7,
      document_count: 120,
    },
    {
      config: {
        category_id: "articles",
        display_name: "Articles",
        description: "Search published articles",
        source: {
          type: "sqlserver",
          connection_env: "SEARCH_SOURCE_BONC_DEV",
          schema: "searchai",
          table: "vw_Search_Articles_v4",
          id_column: "ArticleId",
          max_records: 50000,
          filters: [],
        },
        fields: [
          {
            key: "title",
            source_column: "Title",
            label: "Title",
            role: "title",
            weight: 4,
            searchable: true,
            semantic: true,
            aliases: ["headline"],
            filterable: false,
            data_type: "text",
            query_filter_mode: "none",
            query_match: "all",
          },
          {
            key: "article_type",
            source_column: "ArticleType",
            label: "Article Type",
            role: "category",
            weight: 2,
            searchable: true,
            semantic: false,
            aliases: ["category"],
            filterable: true,
            data_type: "keyword",
            query_filter_mode: "preferred",
            query_match: "any",
          },
        ],
        synonyms: [],
        rules: {
          lexical_enabled: true,
          semantic_enabled: true,
          semantic_min_score: 20,
          semantic_high_confidence_score: 75,
          semantic_candidate_limit: 50,
          lexical_weight: 0.65,
          semantic_weight: 0.35,
        },
        active: true,
        public_search_enabled: true,
      },
      status: "active",
      config_version: 4,
      index_version: 9,
      document_count: 42,
    },
    {
      config: {
        category_id: "jobs",
        display_name: "Jobs",
        description: "Search open job postings",
        source: {
          type: "sqlserver",
          connection_env: "SEARCH_SOURCE_BONC_DEV",
          schema: "searchai",
          table: "vw_Search_Jobs_v2",
          id_column: "JobId",
          max_records: 50000,
          filters: [],
        },
        fields: [
          {
            key: "title",
            source_column: "Title",
            label: "Job Title",
            role: "title",
            weight: 4,
            searchable: true,
            semantic: true,
            aliases: ["role"],
            filterable: false,
            data_type: "text",
            query_filter_mode: "none",
            query_match: "all",
          },
          {
            key: "job_category",
            source_column: "JobCategory",
            label: "Job Category",
            role: "category",
            weight: 2.5,
            searchable: true,
            semantic: false,
            aliases: ["department"],
            filterable: true,
            data_type: "keyword",
            query_filter_mode: "preferred",
            query_match: "any",
          },
        ],
        synonyms: [],
        rules: {
          lexical_enabled: true,
          semantic_enabled: true,
          semantic_min_score: 20,
          semantic_high_confidence_score: 75,
          semantic_candidate_limit: 50,
          lexical_weight: 0.65,
          semantic_weight: 0.35,
        },
        active: true,
        public_search_enabled: true,
      },
      status: "active",
      config_version: 2,
      index_version: 5,
      document_count: 64,
    },
  ];
}

function makeSearchResponse(
  record: PlatformCategoryRecord,
  query: string,
): PlatformSearchResponse {
  const categoryId = record.config.category_id;
  return {
    query,
    category: categoryId,
    query_understanding: {
      normalised_query: query,
      query_type: "free_text",
      field_hints: {},
      matched_aliases: {},
      matched_values: {},
      matched_fields: {},
      constraints: [],
      lexical_query: query,
      expanded_lexical_query: query,
      synonym_expansions: [],
      unmatched_tokens: [],
      explanation: `Search plan for ${categoryId}`,
    },
    query_plan: {
      query_type: "free_text",
      matched_aliases: {},
      matched_values: {},
      constraints: [],
      unmatched_tokens: [],
      lexical_query: query,
      expanded_lexical_query: query,
      synonym_expansions: [],
      semantic_query: query,
      filters_applied: false,
      explanation: `Execution plan for ${categoryId}`,
    },
    data: [
      {
        id: `${categoryId}-doc-1`,
        title: `${record.config.display_name} Result for ${query}`,
        fields: { [record.config.fields[0].key]: `${record.config.display_name} Match` },
        metadata: {},
        score: 88.4,
        lexical_score: 54.2,
        semantic_score: 34.2,
        matched_fields: [record.config.fields[0].key],
        category: categoryId,
      },
    ],
    total_count: 1,
    page: 1,
    page_size: 10,
    config_version: record.config_version,
    index_version: record.index_version,
  };
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  clearClientSessionState();
});

describe("Search Admin Engine Testing dropdown switching & async race protection", () => {
  it("handles all required dropdown transitions without leaking previous engine state or configuration", async () => {
    const categories = makeCategories();
    const byId = new Map(categories.map((item) => [item.config.category_id, item]));
    const recordedCategories: string[] = [];

    globalThis.fetch = (async (_input: RequestInfo | URL, init: RequestInit = {}) => {
      const payload = JSON.parse(String(init.body || "{}")) as {
        category: string;
        query: string;
      };
      recordedCategories.push(payload.category);
      const record = byId.get(payload.category);
      assert.ok(record, `Unexpected category requested: ${payload.category}`);
      return new Response(
        JSON.stringify(makeSearchResponse(record, payload.query)),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    }) as typeof fetch;

    const coordinator = new EngineRequestCoordinator("general_test");
    let ctx = createInitialTestingContext("general_test");

    // Seed initial general_test results, filters, pagination & expanded raw JSON
    const initialToken = coordinator.begin("general_test");
    const initialResult = await runPlatformAdminSearch({
      query: "python",
      category: "general_test",
      signal: initialToken.signal,
    });
    assert.equal(coordinator.isCurrent(initialToken), true);
    ctx = {
      ...ctx,
      searchFilters: [{ field: "type", operator: "eq", value: "guide" }],
      searchResult: initialResult,
      searchDurationMs: 42,
      testPage: 2,
      showQueryPlanJson: true,
      expandedDocRawIds: { "general_test-doc-1": true },
    };

    const transitions: Array<{
      from: string;
      to: string;
      expectedDisplayName: string;
      expectedFilterKey: string;
    }> = [
      {
        from: "general_test",
        to: "people",
        expectedDisplayName: "People",
        expectedFilterKey: "location",
      },
      {
        from: "people",
        to: "articles",
        expectedDisplayName: "Articles",
        expectedFilterKey: "article_type",
      },
      {
        from: "articles",
        to: "jobs",
        expectedDisplayName: "Jobs",
        expectedFilterKey: "job_category",
      },
      {
        from: "jobs",
        to: "general_test",
        expectedDisplayName: "General Search",
        expectedFilterKey: "type",
      },
      {
        from: "general_test",
        to: "articles",
        expectedDisplayName: "Articles",
        expectedFilterKey: "article_type",
      },
      {
        from: "articles",
        to: "general_test",
        expectedDisplayName: "General Search",
        expectedFilterKey: "type",
      },
    ];

    for (const step of transitions) {
      assert.equal(ctx.selectedCategory, step.from);
      const previousResult = ctx.searchResult;

      // Switch via dropdown
      coordinator.invalidate();
      coordinator.setActiveCategory(step.to);
      ctx = transitionTestingEngine(ctx, step.to);

      // Verify state reset & immediate config resolution
      assert.equal(ctx.selectedCategory, step.to);
      assert.deepEqual(ctx.searchFilters, []);
      assert.equal(ctx.searchResult, null);
      assert.equal(ctx.searchDurationMs, null);
      assert.equal(ctx.searching, false);
      assert.equal(ctx.testPage, 1);
      assert.equal(ctx.showQueryPlanJson, false);
      assert.deepEqual(ctx.expandedDocRawIds, {});

      // Previous engine's results must never pass active-engine render guard
      assert.equal(isSearchResultForActiveEngine(previousResult, step.to), false);

      const activeRecord = resolveSelectedEngineRecord(categories, ctx.selectedCategory);
      assert.ok(activeRecord);
      assert.equal(activeRecord.config.category_id, step.to);
      assert.equal(activeRecord.config.display_name, step.expectedDisplayName);
      assert.deepEqual(
        activeRecord.config.fields.filter((f) => f.filterable).map((f) => f.key),
        [step.expectedFilterKey],
      );

      // Refreshing categories while switched must preserve the user's dropdown choice
      // even if an older initialCategoryId ("general_test") is still supplied.
      assert.equal(
        resolveCategoryAfterRefresh({
          categories,
          currentSelectedCategory: ctx.selectedCategory,
          initialCategoryId: "general_test",
          userClearedSelection: false,
        }),
        step.to,
      );

      // Execute search against the newly selected engine
      const token = coordinator.begin(step.to);
      const response = await runPlatformAdminSearch({
        query: "python",
        category: step.to,
        signal: token.signal,
      });
      assert.equal(coordinator.isCurrent(token), true);
      assert.equal(isSearchResultForActiveEngine(response, step.to), true);
      assert.equal(response.category, step.to);
      assert.equal(response.config_version, activeRecord.config_version);
      assert.equal(response.index_version, activeRecord.index_version);
      assert.equal(response.data[0].id, `${step.to}-doc-1`);
      ctx = { ...ctx, searchResult: response };
    }

    assert.deepEqual(recordedCategories, [
      "general_test",
      "people",
      "articles",
      "jobs",
      "general_test",
      "articles",
      "general_test",
    ]);
  });

  it("preserves user dropdown selection on refresh and handles initial load / cleared selection cleanly", () => {
    const categories = makeCategories();

    // Initial load with no current selection uses initialCategoryId
    assert.equal(
      resolveCategoryAfterRefresh({
        categories,
        currentSelectedCategory: "",
        initialCategoryId: "articles",
        userClearedSelection: false,
      }),
      "articles",
    );

    // Once user selects another engine, refresh NEVER snaps back to initialCategoryId
    assert.equal(
      resolveCategoryAfterRefresh({
        categories,
        currentSelectedCategory: "jobs",
        initialCategoryId: "general_test",
        userClearedSelection: false,
      }),
      "jobs",
    );

    // Explicit clear ("Select a configured search engine") is respected
    assert.equal(
      resolveCategoryAfterRefresh({
        categories,
        currentSelectedCategory: "",
        initialCategoryId: "general_test",
        userClearedSelection: true,
      }),
      "",
    );

    // If previously selected engine disappeared from backend registry, falls back cleanly
    assert.equal(
      resolveCategoryAfterRefresh({
        categories,
        currentSelectedCategory: "deleted_engine",
        initialCategoryId: "people",
        userClearedSelection: false,
      }),
      "people",
    );
  });

  it("aborts pending requests on switch and prevents a slow previous-engine response or error from overwriting the newly selected engine", async () => {
    const categories = makeCategories();
    const byId = new Map(categories.map((item) => [item.config.category_id, item]));
    const coordinator = new EngineRequestCoordinator("general_test");

    const deferredByCategory = new Map<string, Deferred<Response>>();
    const signalsByCategory = new Map<string, AbortSignal | undefined>();

    // Intentionally ignore AbortSignal inside mock fetch so we test BOTH
    // AbortSignal propagation AND late-settlement sequence guards!
    globalThis.fetch = ((_input: RequestInfo | URL, init: RequestInit = {}) => {
      const payload = JSON.parse(String(init.body || "{}")) as { category: string };
      signalsByCategory.set(payload.category, init.signal ?? undefined);
      const deferred = createDeferred<Response>();
      deferredByCategory.set(payload.category, deferred);
      return deferred.promise;
    }) as typeof fetch;

    let activeState = createInitialTestingContext("general_test");
    let activeError = "";

    const runSearch = async (category: string, query: string) => {
      const token = coordinator.begin(category);
      activeState = { ...activeState, searching: true };
      activeError = "";
      try {
        const result = await runPlatformAdminSearch({
          query,
          category,
          signal: token.signal,
        });
        if (
          !coordinator.isCurrent(token) ||
          !isSearchResultForActiveEngine(result, category)
        ) {
          return;
        }
        activeState = { ...activeState, searchResult: result };
      } catch (err) {
        if (!coordinator.isCurrent(token) || isAbortError(err)) {
          return;
        }
        activeState = { ...activeState, searchResult: null };
        activeError = err instanceof Error ? err.message : "failed";
      } finally {
        if (coordinator.isCurrent(token)) {
          activeState = { ...activeState, searching: false };
        }
      }
    };

    const flushMicrotasks = async () => {
      await Promise.resolve();
      await Promise.resolve();
    };

    // 1. Start a slow search on general_test
    const slowGeneralPromise = runSearch("general_test", "fastapi");
    assert.equal(activeState.searching, true);
    await flushMicrotasks();
    assert.equal(signalsByCategory.get("general_test")?.aborted, false);

    // 2. While general_test is still pending, user switches dropdown to people
    coordinator.invalidate();
    coordinator.setActiveCategory("people");
    activeState = transitionTestingEngine(activeState, "people");
    assert.equal(signalsByCategory.get("general_test")?.aborted, true);
    assert.equal(activeState.searching, false);

    // 3. User runs a fast search on people and it completes first
    const fastPeoplePromise = runSearch("people", "fastapi");
    assert.equal(activeState.searching, true);
    await flushMicrotasks();
    deferredByCategory.get("people")!.resolve(
      new Response(JSON.stringify(makeSearchResponse(byId.get("people")!, "fastapi")), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await fastPeoplePromise;
    assert.equal(activeState.searching, false);
    assert.equal(activeState.searchResult?.category, "people");
    assert.equal(activeState.searchResult?.data[0].id, "people-doc-1");

    // 4. Now the stale general_test request finally resolves late — MUST NOT overwrite people!
    deferredByCategory.get("general_test")!.resolve(
      new Response(
        JSON.stringify(makeSearchResponse(byId.get("general_test")!, "fastapi")),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    await slowGeneralPromise;
    assert.equal(activeState.selectedCategory, "people");
    assert.equal(activeState.searchResult?.category, "people");
    assert.equal(activeState.searchResult?.data[0].id, "people-doc-1");
    assert.equal(activeError, "");

    // 5. Repeat with a late FAILURE from people while articles is still in-flight:
    //    must neither flip searching=false early nor inject an error into articles!
    const slowPeopleFailPromise = runSearch("people", "backend");
    await flushMicrotasks();
    coordinator.invalidate();
    coordinator.setActiveCategory("articles");
    activeState = transitionTestingEngine(activeState, "articles");

    const pendingArticlesPromise = runSearch("articles", "backend");
    assert.equal(activeState.searching, true);
    await flushMicrotasks();

    deferredByCategory.get("people")!.reject(new Error("Upstream 500 on people"));
    await slowPeopleFailPromise;
    assert.equal(activeState.searching, true, "stale rejection must not clear active searching spinner");
    assert.equal(activeError, "", "stale rejection must not surface error under newly selected engine");

    deferredByCategory.get("articles")!.resolve(
      new Response(JSON.stringify(makeSearchResponse(byId.get("articles")!, "backend")), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await pendingArticlesPromise;
    assert.equal(activeState.searching, false);
    assert.equal(activeState.searchResult?.category, "articles");
    assert.equal(activeState.searchResult?.data[0].id, "articles-doc-1");
    assert.equal(activeError, "");
  });

  it("verifies App.tsx and PlatformPanel.tsx wiring guards against initialCategoryId snap-back and stale results", () => {
    const appSrc = fs.readFileSync(path.join(FRONTEND_SRC, "App.tsx"), "utf8");
    const panelSrc = fs.readFileSync(
      path.join(FRONTEND_SRC, "components", "platform-panel.tsx"),
      "utf8",
    );

    // App keeps focusCategoryId synchronized when the user switches engines via dropdown
    assert.equal(
      appSrc.includes("onSelectedCategoryChange={setFocusCategoryId}"),
      true,
      "App.tsx must synchronize focusCategoryId via onSelectedCategoryChange",
    );

    // PlatformPanel uses the request coordinator, refresh resolver, and active-engine render guard
    assert.equal(panelSrc.includes("EngineRequestCoordinator"), true);
    assert.equal(panelSrc.includes("resolveCategoryAfterRefresh"), true);
    assert.equal(panelSrc.includes("isSearchResultForActiveEngine"), true);
    assert.equal(panelSrc.includes("key={selectedCategory}"), true);

    // Ensure the legacy snap-back effect (with selectedCategory in initialCategoryId effect deps) is gone
    assert.equal(
      /if\s*\(\s*initialCategoryId\s*&&\s*initialCategoryId\s*!==\s*selectedCategory\s*\)/.test(
        panelSrc,
      ),
      false,
      "PlatformPanel must not re-introduce the initialCategoryId !== selectedCategory snap-back effect",
    );

    // Ensure Engines -> Test Engine flow is preserved
    assert.equal(panelSrc.includes('onSelectMode?.("testing", cfg.category_id)'), true);
  });
});
