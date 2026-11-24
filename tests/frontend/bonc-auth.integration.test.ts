import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  getBoncAccessToken,
  hasBoncHostLogoutCallback,
  hasInMemoryBoncAccessToken,
  notifyBoncHostLogout,
  registerBoncAuthProvider,
  resetBoncAuthAdapterForTests,
  setInMemoryBoncAccessToken,
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
  logoutAdmin,
  runPlatformAdminSearch,
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
});

describe("BONC-Only Frontend Authentication & Integrated Auth Security", () => {
  it("attaches in-memory BONC Bearer token on protected requests with credentials:omit and no CSRF header", async () => {
    registerBoncAuthProvider({
      getAccessToken: () => "bonc-access-token-in-memory",
    });
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

  it("handles missing/expired token when refresh fails cleanly", async () => {
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
  });

  it("handles 403 Basic user rejection separately from 401 and clears in-memory token", async () => {
    let forbiddenMessage = "";
    let unauthorizedCount = 0;
    setForbiddenHandler((msg) => {
      forbiddenMessage = msg;
    });
    setUnauthorizedHandler(() => {
      unauthorizedCount += 1;
    });

    setInMemoryBoncAccessToken("basic-bonc-user-token");
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
    assert.equal(hasInMemoryBoncAccessToken(), false);
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

    const calls = mockFetchSequence([{ status: 500, body: { detail: "should not be called" } }]);
    const result = await logoutAdmin();
    assert.equal(result.hostHandled, true);
    assert.equal(hostLogoutInvoked, 1);
    assert.equal(calls.length, 0);

    assert.ok(hostPushListener);
    hostPushListener!();
    notifyBoncHostLogout();
    assert.equal(appNotifiedCount, 2);
    unsub();
  });

  it("supports standalone in-memory BONC token auth and clears it on 401, 403, and logout", async () => {
    assert.equal(setInMemoryBoncAccessToken("standalone-bonc-jwt-token"), true);
    assert.equal(hasInMemoryBoncAccessToken(), true);
    assert.equal(await getBoncAccessToken(), "standalone-bonc-jwt-token");

    const calls = mockFetchSequence([
      {
        status: 200,
        headers: { "X-Auth-Mode": "bonc_jwt" },
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
        status: 403,
        headers: { "X-Auth-Mode": "bonc_jwt" },
        body: { detail: "Administrator access required" },
      },
      {
        status: 401,
        headers: { "X-Auth-Mode": "bonc_jwt" },
        body: { detail: "Authentication required" },
      },
    ]);

    const session = await getAdminSession();
    assert.equal(session?.authenticated, true);
    assert.equal(
      new Headers(calls[0].init.headers).get("Authorization"),
      "Bearer standalone-bonc-jwt-token",
    );
    assert.equal(calls[0].init.credentials, "omit");

    // Logout clears in-memory BONC token without calling any backend logout route
    const logoutRes = await logoutAdmin();
    assert.equal(logoutRes.hostHandled, false);
    assert.equal(hasInMemoryBoncAccessToken(), false);
    assert.equal(await getBoncAccessToken(), null);
    assert.equal(calls.length, 1);

    // 403 (Basic user) clears in-memory BONC token
    setInMemoryBoncAccessToken("basic-bonc-jwt-token");
    await assert.rejects(
      () => getAdminSession(),
      (err: unknown) => err instanceof ApiError && err.status === 403,
    );
    assert.equal(hasInMemoryBoncAccessToken(), false);

    // 401 (revoked/expired) clears in-memory BONC token
    setInMemoryBoncAccessToken("revoked-bonc-jwt-token");
    const unauth = await getAdminSession();
    assert.equal(unauth, null);
    assert.equal(hasInMemoryBoncAccessToken(), false);
  });

  it("validates optional hostLoginUrl and rejects unsafe schemes or token query params", () => {
    assert.equal(validateHostLoginUrl("https://app.boncnetwork.com/login"), "https://app.boncnetwork.com/login");
    assert.equal(validateHostLoginUrl("/login"), "/login");
    assert.equal(validateHostLoginUrl("javascript:alert(1)"), null);
    assert.equal(validateHostLoginUrl("//evil.example/login"), null);
    assert.equal(validateHostLoginUrl("https://app.boncnetwork.com/login?token=abc"), null);
    assert.equal(validateHostLoginUrl("/login#auth=secret"), null);
  });

  it("renders BONC-only auth interface with zero local username/password form, storage, CSRF, or mode switches", () => {
    const appSrc = fs.readFileSync(path.join(FRONTEND_SRC, "App.tsx"), "utf8");
    // BONC auth UI & existing admin dashboard navigation remain intact
    assert.equal(appSrc.includes("BONC AuthToken"), true);
    assert.equal(appSrc.includes("Verify BONC Token"), true);
    assert.equal(appSrc.includes("Administrator Access Required"), true);
    assert.equal(appSrc.includes("System Health"), true);
    assert.equal(appSrc.includes("Search Logs"), true);
    assert.equal(appSrc.includes("Data Sources"), true);

    // Zero legacy local username/password form or CSRF UI remains
    assert.equal(appSrc.includes("Admin Username"), false);
    assert.equal(appSrc.includes("current-password"), false);
    assert.equal(appSrc.includes("loginAdmin"), false);
    assert.equal(appSrc.includes("CSRF"), false);

    const filesToAudit = [
      path.join(FRONTEND_SRC, "lib", "bonc-auth.ts"),
      path.join(FRONTEND_SRC, "lib", "search-api.ts"),
      path.join(FRONTEND_SRC, "App.tsx"),
    ];
    for (const filePath of filesToAudit) {
      const src = fs.readFileSync(filePath, "utf8");
      const codeOnly = src
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      assert.equal(codeOnly.includes("localStorage"), false, `${filePath} must not access localStorage`);
      assert.equal(codeOnly.includes("sessionStorage"), false, `${filePath} must not access sessionStorage`);
      assert.equal(codeOnly.includes("document.cookie"), false, `${filePath} must not access document.cookie`);
      assert.equal(codeOnly.includes("window.parent"), false, `${filePath} must not invent window.parent access`);
      assert.equal(codeOnly.includes("postMessage"), false, `${filePath} must not invent postMessage handshakes`);
      assert.equal(codeOnly.includes("__BONC_"), false, `${filePath} must not invent global window.__BONC_* vars`);
      assert.equal(codeOnly.includes("VITE_AUTH_MODE"), false, `${filePath} must not check removed VITE_AUTH_MODE`);
      assert.equal(codeOnly.includes("X-CSRF-Token"), false, `${filePath} must not send X-CSRF-Token`);
      assert.equal(codeOnly.includes("/api/admin/auth/login"), false, `${filePath} must not call /api/admin/auth/login`);
      assert.equal(codeOnly.includes("/api/admin/auth/logout"), false, `${filePath} must not call /api/admin/auth/logout`);
    }
  });
});
