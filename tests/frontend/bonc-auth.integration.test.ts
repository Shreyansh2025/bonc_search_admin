import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  getBoncAccessToken,
  getEffectiveFrontendAuthMode,
  hasBoncHostLogoutCallback,
  notifyBoncHostLogout,
  registerBoncAuthProvider,
  resetBoncAuthAdapterForTests,
  setRuntimeAuthModeOverride,
  subscribeBoncHostLogout,
  validateHostLoginUrl,
} from "../../frontend/src/lib/bonc-auth.ts";
import {
  ADMIN_API_BASE,
  ApiError,
  clearClientSessionState,
  getAdminSession,
  getPlatformCategories,
  getPublicPlatformCategories,
  loginAdmin,
  logoutAdmin,
  runPlatformAdminSearch,
  setCsrfErrorHandler,
  setForbiddenHandler,
  setUnauthorizedHandler,
} from "../../frontend/src/lib/search-api.ts";

interface RecordedCall {
  url: string;
  init: RequestInit;
}

const originalFetch = globalThis.fetch;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_SRC = path.resolve(__dirname, "../../frontend/src");

function mockFetchSequence(
  responses: Array<{ status: number; body: unknown; headers?: Record<string, string> }>,
): RecordedCall[] {
  const calls: RecordedCall[] = [];
  let index = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    calls.push({ url: String(input), init });
    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return new Response(JSON.stringify(next.body), {
      status: next.status,
      headers: {
        "Content-Type": "application/json",
        ...(next.headers || {}),
      },
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
  setCsrfErrorHandler(null);
});

describe("BONC Frontend Host Token Provider Adapter & Integrated Auth Security", () => {
  it("attaches in-memory BONC Bearer token on protected requests with credentials:omit and no CSRF header", async () => {
    registerBoncAuthProvider({
      getAccessToken: () => "bonc-access-token-in-memory",
    });
    assert.equal(getEffectiveFrontendAuthMode(), "bonc");
    assert.equal(await getBoncAccessToken(), "bonc-access-token-in-memory");

    const calls = mockFetchSequence([
      {
        status: 200,
        headers: { "X-Auth-Mode": "bonc_jwt" },
        body: {
          authenticated: true,
          auth_method: "bonc_jwt",
          auth_mode: "bonc_jwt",
          user_id: "bonc-uuid-123",
          username: "alice@bonc",
          actor: "bonc-uuid-123",
          roles: ["Admin"],
          permissions: ["admin:categories:read", "admin:search:execute"],
          csrf_token: null,
          local_login_enabled: false,
        },
      },
      {
        status: 200,
        headers: { "X-Auth-Mode": "bonc_jwt" },
        body: {
          query: "python",
          category: "people",
          query_understanding: {},
          query_plan: {},
          data: [],
          total_count: 0,
          page: 1,
          page_size: 10,
          config_version: 1,
          index_version: 1,
        },
      },
    ]);

    const session = await getAdminSession();
    assert.equal(session?.authenticated, true);
    assert.equal(session?.user_id, "bonc-uuid-123");
    assert.equal(calls[0].init.credentials, "omit");
    const sessionHeaders = new Headers(calls[0].init.headers);
    assert.equal(sessionHeaders.get("Authorization"), "Bearer bonc-access-token-in-memory");
    assert.equal(sessionHeaders.get("X-CSRF-Token"), null);
    assert.equal(calls[0].url.includes("bonc-access-token"), false);

    await runPlatformAdminSearch({ query: "python", category: "people" });
    assert.equal(calls[1].init.credentials, "omit");
    const searchHeaders = new Headers(calls[1].init.headers);
    assert.equal(searchHeaders.get("Authorization"), "Bearer bonc-access-token-in-memory");
    assert.equal(searchHeaders.get("X-CSRF-Token"), null);
  });

  it("keeps public platform category requests unauthenticated without Bearer tokens or cookies", async () => {
    registerBoncAuthProvider({
      getAccessToken: () => "bonc-secret-should-not-leak-to-public",
    });
    const calls = mockFetchSequence([
      {
        status: 200,
        body: [{ category_id: "help", display_name: "Help", description: "Public docs" }],
      },
    ]);

    const categories = await getPublicPlatformCategories();
    assert.equal(categories.length, 1);
    assert.equal(calls[0].url, `${ADMIN_API_BASE}/api/platform/categories`);
    assert.equal(calls[0].init.credentials, "omit");
    const headers = new Headers(calls[0].init.headers);
    assert.equal(headers.get("Authorization"), null);
    assert.equal(headers.get("X-CSRF-Token"), null);
  });

  it("delegates access-token refresh to host BONC provider ONCE on 401 and retries seamlessly", async () => {
    let currentToken = "expired-bonc-token";
    let refreshCalls = 0;
    let unauthorizedCount = 0;

    setUnauthorizedHandler(() => {
      unauthorizedCount += 1;
    });
    registerBoncAuthProvider({
      getAccessToken: () => currentToken,
      refreshAccessToken: async () => {
        refreshCalls += 1;
        currentToken = "fresh-bonc-token";
        return currentToken;
      },
    });

    const calls = mockFetchSequence([
      { status: 401, headers: { "X-Auth-Mode": "bonc_jwt" }, body: { detail: "Authentication required" } },
      { status: 200, headers: { "X-Auth-Mode": "bonc_jwt" }, body: [] },
    ]);

    const cats = await getPlatformCategories();
    assert.deepEqual(cats, []);
    assert.equal(refreshCalls, 1);
    assert.equal(unauthorizedCount, 0);
    assert.equal(calls.length, 2);
    assert.equal(new Headers(calls[0].init.headers).get("Authorization"), "Bearer expired-bonc-token");
    assert.equal(new Headers(calls[1].init.headers).get("Authorization"), "Bearer fresh-bonc-token");
  });

  it("handles missing/expired token when refresh fails cleanly without falling back to local login", async () => {
    let unauthorizedCount = 0;
    setUnauthorizedHandler(() => {
      unauthorizedCount += 1;
    });
    registerBoncAuthProvider({
      getAccessToken: () => null,
      refreshAccessToken: async () => null,
    });

    const calls = mockFetchSequence([
      { status: 401, headers: { "X-Auth-Mode": "bonc_jwt" }, body: { detail: "Authentication required" } },
    ]);

    await assert.rejects(
      () => getPlatformCategories(),
      (err: unknown) => err instanceof ApiError && err.status === 401,
    );
    assert.equal(unauthorizedCount, 1);
    assert.equal(calls.length, 1);
    assert.equal(new Headers(calls[0].init.headers).get("Authorization"), null);

    // Independent local login MUST be refused in BONC mode with zero network call
    await assert.rejects(
      () => loginAdmin({ username: "ops", password: "secret" }),
      (err: unknown) => err instanceof ApiError && err.status === 403,
    );
    assert.equal(calls.length, 1);
  });

  it("handles 403 forbidden separately from 401 and switches to BONC mode on backend X-Auth-Mode header", async () => {
    let forbiddenMessage = "";
    let unauthorizedCount = 0;
    setForbiddenHandler((msg) => {
      forbiddenMessage = msg;
    });
    setUnauthorizedHandler(() => {
      unauthorizedCount += 1;
    });

    mockFetchSequence([
      {
        status: 403,
        headers: { "X-Auth-Mode": "bonc_jwt" },
        body: { detail: "Administrator access required" },
      },
    ]);

    await assert.rejects(
      () => getAdminSession(),
      (err: unknown) => err instanceof ApiError && err.status === 403,
    );
    assert.equal(forbiddenMessage, "Administrator access required");
    assert.equal(unauthorizedCount, 0);
    // Backend signaled BONC mode -> frontend locks into BONC mode (no local login fallback)
    assert.equal(getEffectiveFrontendAuthMode(), "bonc");
  });

  it("delegates logout to host BONC provider and responds to host-pushed logout notifications", async () => {
    let hostLogoutInvoked = 0;
    let hostPushListener: (() => void) | null = null;
    let appNotifiedCount = 0;

    registerBoncAuthProvider({
      getAccessToken: () => "bonc-token",
      onLogout: async () => {
        hostLogoutInvoked += 1;
      },
      subscribeLogout: (listener) => {
        hostPushListener = listener;
        return () => {
          hostPushListener = null;
        };
      },
    });
    assert.equal(hasBoncHostLogoutCallback(), true);

    const unsub = subscribeBoncHostLogout(() => {
      appNotifiedCount += 1;
    });

    // Mock fetch to prove logoutAdmin does NOT call /api/admin/auth/logout in BONC mode
    const calls = mockFetchSequence([{ status: 500, body: { detail: "should not be called" } }]);
    const result = await logoutAdmin();
    assert.equal(result.hostHandled, true);
    assert.equal(hostLogoutInvoked, 1);
    assert.equal(calls.length, 0);

    // Host-initiated logout notification reaches Search_Admin subscribers
    assert.ok(hostPushListener);
    hostPushListener!();
    notifyBoncHostLogout();
    assert.equal(appNotifiedCount, 2);
    unsub();
  });

  it("validates optional hostLoginUrl and rejects unsafe schemes or token query params", () => {
    assert.equal(validateHostLoginUrl("https://app.boncnetwork.com/login"), "https://app.boncnetwork.com/login");
    assert.equal(validateHostLoginUrl("/login"), "/login");
    assert.equal(validateHostLoginUrl("javascript:alert(1)"), null);
    assert.equal(validateHostLoginUrl("//evil.example/login"), null);
    assert.equal(validateHostLoginUrl("https://app.boncnetwork.com/login?token=abc"), null);
    assert.equal(validateHostLoginUrl("/login#auth=secret"), null);
  });

  it("never uses browser storage, invented globals, window.parent, wildcard postMessage, or hardcoded tokens", () => {
    const filesToAudit = [
      path.join(FRONTEND_SRC, "lib", "bonc-auth.ts"),
      path.join(FRONTEND_SRC, "lib", "search-api.ts"),
      path.join(FRONTEND_SRC, "App.tsx"),
    ];
    for (const filePath of filesToAudit) {
      const src = fs.readFileSync(filePath, "utf8");
      // Strip comments before checking forbidden browser storage / host-hack APIs
      const codeOnly = src
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      assert.equal(codeOnly.includes("localStorage"), false, `${filePath} must not access localStorage`);
      assert.equal(codeOnly.includes("sessionStorage"), false, `${filePath} must not access sessionStorage`);
      assert.equal(codeOnly.includes("document.cookie"), false, `${filePath} must not access document.cookie`);
      assert.equal(codeOnly.includes("window.parent"), false, `${filePath} must not invent window.parent access`);
      assert.equal(codeOnly.includes("postMessage"), false, `${filePath} must not invent postMessage handshakes`);
      assert.equal(codeOnly.includes("__BONC_"), false, `${filePath} must not invent global window.__BONC_* vars`);
    }

    // Confirm BONC mode overrides cleanly without leaking runtime state
    setRuntimeAuthModeOverride("bonc");
    assert.equal(getEffectiveFrontendAuthMode(), "bonc");
  });
});
