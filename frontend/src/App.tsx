import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import PlatformPanel, { type PlatformPanelMode } from "./components/platform-panel";
import SearchLogsPanel from "./components/search-logs-panel";
import SystemHealthPanel, { healthLabel } from "./components/system-health-panel";
import {
  getBoncHostLoginUrl,
  hasBoncHostLogoutCallback,
  hasExternalBoncHostProvider,
  hasInMemoryBoncAccessToken,
  setInMemoryBoncAccessToken,
  subscribeBoncHostLogout,
} from "./lib/bonc-auth";
import {
  ADMIN_API_BASE,
  ApiError,
  clearClientSessionState,
  getAdminSession,
  getPlatformCategories,
  logoutAdmin,
  setForbiddenHandler,
  setUnauthorizedHandler,
  type AdminSessionInfo,
  type HealthState,
  type PlatformCategoryRecord,
  type SystemHealthResponse,
} from "./lib/search-api";

type MainSection = "system-health" | "search-logs" | "data-sources";
type DataSourcesSubTab = "engines" | "testing" | "feedback";

function topbarPillClass(state: HealthState | "checking"): string {
  switch (state) {
    case "healthy":
      return "ready";
    case "degraded":
      return "pending";
    case "unhealthy":
      return "down";
    case "unavailable":
    case "disabled":
      return "unavailable";
    case "checking":
    default:
      return "pending";
  }
}

export default function App() {
  // Verified BONC JWT authentication state (in-memory Bearer AuthToken only)
  const [authStatus, setAuthStatus] = useState<
    "checking" | "authenticated" | "unauthenticated" | "forbidden" | "unavailable"
  >("checking");
  const [adminSession, setAdminSession] = useState<AdminSessionInfo | null>(null);
  const [boncTokenInput, setBoncTokenInput] = useState("");
  const [authError, setAuthError] = useState("");
  const [authNotice, setAuthNotice] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);

  // Three main admin sections
  const [activeSection, setActiveSection] = useState<MainSection>("system-health");
  const [dataSubTab, setDataSubTab] = useState<DataSourcesSubTab>("engines");
  const [focusCategoryId, setFocusCategoryId] = useState<string>("");
  const [openEditorNonce, setOpenEditorNonce] = useState(0);
  const [healthRefreshNonce, setHealthRefreshNonce] = useState(0);

  // Search Logs deep-link state from System Health
  const [logsInitialCategory, setLogsInitialCategory] = useState("");
  const [logsInitialFailedOnly, setLogsInitialFailedOnly] = useState(false);

  // Shared live health & categories state
  const [systemHealth, setSystemHealth] = useState<SystemHealthResponse | null>(null);
  const [systemHealthError, setSystemHealthError] = useState("");
  const [platformCategories, setPlatformCategories] = useState<
    PlatformCategoryRecord[]
  >([]);

  const clearProtectedData = useCallback(() => {
    setSystemHealth(null);
    setSystemHealthError("");
    setPlatformCategories([]);
  }, []);

  const refreshCategories = useCallback(async () => {
    try {
      const cats = await getPlatformCategories();
      setPlatformCategories(cats);
    } catch {
      // Errors are surfaced on active panels or via 401/403 handlers.
    }
  }, []);

  const checkSession = useCallback(
    async (options?: { explicitTokenCheck?: boolean }) => {
      setAuthStatus("checking");
      setAuthError("");
      try {
        const session = await getAdminSession();
        if (session?.authenticated) {
          setAdminSession(session);
          setAuthStatus("authenticated");
        } else {
          setAdminSession(null);
          clearProtectedData();
          setAuthStatus("unauthenticated");
          if (options?.explicitTokenCheck) {
            setAuthError(
              "BONC token was rejected (HTTP 401). It may be invalid, expired, or logged out.",
            );
          }
        }
      } catch (error) {
        setAdminSession(null);
        clearProtectedData();
        if (error instanceof ApiError && error.status === 403) {
          setAuthStatus("forbidden");
          setAuthError(error.message || "Administrator permissions are required.");
        } else if (error instanceof ApiError && error.status === 503) {
          setAuthStatus("unavailable");
          setAuthError(
            error.message ||
              "BONC authentication verification is not configured or unavailable.",
          );
        } else {
          setAuthStatus("unauthenticated");
          setAuthError(
            error instanceof Error
              ? error.message
              : "Unable to verify BONC authentication status.",
          );
        }
      }
    },
    [clearProtectedData],
  );

  const handleBoncTokenSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const rawToken = boncTokenInput.trim().replace(/^Bearer\s+/i, "");
    if (!rawToken) {
      setAuthError("Enter a valid BONC AuthToken.");
      return;
    }
    const stored = setInMemoryBoncAccessToken(rawToken);
    setBoncTokenInput("");
    if (!stored) {
      setAuthError("The supplied BONC AuthToken format is invalid.");
      return;
    }
    setAuthNotice("");
    await checkSession({ explicitTokenCheck: true });
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    setAuthError("");
    let hostHandled = false;
    try {
      const res = await logoutAdmin();
      hostHandled = res.hostHandled;
    } catch {
      // Clear local UI state even if the token was already revoked/expired.
    } finally {
      clearClientSessionState();
      setAdminSession(null);
      clearProtectedData();
      setAuthStatus("unauthenticated");
      setAuthNotice(
        hostHandled
          ? "Sign-out has been delegated to BONC."
          : "Search Admin view cleared. Sign out directly in BONC to end your BONC session.",
      );
      setLoggingOut(false);
    }
  };

  useEffect(() => {
    const unsubHostLogout = subscribeBoncHostLogout(() => {
      clearClientSessionState();
      setAdminSession(null);
      clearProtectedData();
      setAuthStatus("unauthenticated");
      setAuthError("");
      setAuthNotice("Your BONC session has ended. Sign in through BONC to continue.");
    });

    setUnauthorizedHandler(() => {
      clearClientSessionState();
      setAdminSession(null);
      clearProtectedData();
      setAuthStatus("unauthenticated");
      setAuthNotice(
        "Your BONC authentication token is missing, expired, or revoked. Reauthenticate in BONC.",
      );
    });
    setForbiddenHandler((message) => {
      setAdminSession(null);
      clearProtectedData();
      setAuthStatus("forbidden");
      setAuthError(message || "Administrator permissions are required.");
    });
    return () => {
      unsubHostLogout();
      setUnauthorizedHandler(null);
      setForbiddenHandler(null);
    };
  }, [clearProtectedData]);

  useEffect(() => {
    void checkSession();
  }, [checkSession]);

  useEffect(() => {
    if (authStatus === "authenticated") {
      void refreshCategories();
    }
  }, [authStatus, refreshCategories]);

  const handleHealthSnapshot = useCallback(
    (snapshot: SystemHealthResponse | null, errorMessage: string) => {
      setSystemHealth(snapshot);
      setSystemHealthError(errorMessage);
    },
    [],
  );

  const topbarHealthState: HealthState | "checking" = systemHealth
    ? systemHealth.status
    : systemHealthError
      ? "unavailable"
      : "checking";

  const topbarHealthLabel =
    topbarHealthState === "checking"
      ? "Checking Health"
      : healthLabel(topbarHealthState);

  const sectionMeta: Record<MainSection, { title: string; subtitle: string }> = {
    "system-health": {
      title: "System Health & Analytics",
      subtitle:
        "Live General Search Platform API, SQL Server, embedding model, category index health, Search KPIs, API 5xx monitoring, and feedback-derived relevance metrics.",
    },
    "search-logs": {
      title: "Search Logs & User Activity",
      subtitle:
        "Inspect persistent timestamped search history with full backend filtering, pagination, and per-user activity breakdowns.",
    },
    "data-sources": {
      title: "Data Sources & Configuration",
      subtitle:
        "Manage SQL connection profiles, schema discovery, field mappings, weights, synonyms, typed filters, sync, validation, configuration history, rollback, generic engine testing, and read-only feedback logs.",
    },
  };

  const handlePanelNavigate = (mode: PlatformPanelMode, categoryId?: string) => {
    if (categoryId) setFocusCategoryId(categoryId);
    setActiveSection("data-sources");
    if (mode === "engines") setDataSubTab("engines");
    else if (mode === "testing") setDataSubTab("testing");
    else if (mode === "feedback") setDataSubTab("feedback");
  };

  const handleConfigureCategoryFromHealth = (categoryId: string) => {
    setFocusCategoryId(categoryId);
    setActiveSection("data-sources");
    setDataSubTab("engines");
    setOpenEditorNonce((n) => n + 1);
  };

  const handleInspectSearchLogsFromHealth = (filters?: {
    category?: string;
    failedOnly?: boolean;
  }) => {
    setLogsInitialCategory(filters?.category || "");
    setLogsInitialFailedOnly(Boolean(filters?.failedOnly));
    setActiveSection("search-logs");
  };

  return (
    <div className="mod-shell">
      <header className="mod-topbar">
        <div className="mod-topbar-inner">
          <a
            className="mod-brand"
            href="#system-health"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection("system-health");
            }}
          >
            <span className="logo-word" aria-label="BONC">
              <span className="b">B</span>
              <span className="o">O</span>
              <span className="n">N</span>
              <span className="c">C</span>
            </span>
            <span className="brand-sub">Network · Search Admin</span>
          </a>

          {authStatus === "authenticated" && (
            <nav className="mod-tabs" aria-label="Search Admin Sections">
              <button
                type="button"
                className={`mod-tab ${activeSection === "system-health" ? "active" : ""}`}
                onClick={() => setActiveSection("system-health")}
              >
                System Health
              </button>
              <button
                type="button"
                className={`mod-tab ${activeSection === "search-logs" ? "active" : ""}`}
                onClick={() => setActiveSection("search-logs")}
              >
                Search Logs
              </button>
              <button
                type="button"
                className={`mod-tab ${activeSection === "data-sources" ? "active" : ""}`}
                onClick={() => setActiveSection("data-sources")}
              >
                Data Sources &amp; Configuration
              </button>
            </nav>
          )}

          <div className="mod-topbar-right">
            <div className="api-chip">
              <span className="api-dot" /> API <code>{ADMIN_API_BASE}</code>
            </div>
            {authStatus === "authenticated" && (
              <div className={`service-pill ${topbarPillClass(topbarHealthState)}`}>
                <span className="status-dot" />
                <span>{topbarHealthLabel}</span>
                <button
                  type="button"
                  className="icon-button"
                  onClick={() => {
                    setHealthRefreshNonce((n) => n + 1);
                    void refreshCategories();
                  }}
                  title="Refresh backend health"
                  aria-label="Refresh backend health"
                >
                  ↻
                </button>
              </div>
            )}
            {authStatus === "authenticated" && adminSession && (
              <div
                className="auth-session-pill"
                title={
                  adminSession.user_id
                    ? `BONC User ID: ${adminSession.user_id}`
                    : `Actor: ${adminSession.actor}`
                }
              >
                <span>
                  Signed in as <strong>{adminSession.username}</strong>
                </span>
                {hasBoncHostLogoutCallback() ? (
                  <button
                    type="button"
                    className="secondary-button auth-logout-btn"
                    onClick={() => void handleLogout()}
                    disabled={loggingOut}
                  >
                    {loggingOut ? "Signing out…" : "Sign out (BONC)"}
                  </button>
                ) : hasInMemoryBoncAccessToken() ? (
                  <button
                    type="button"
                    className="secondary-button auth-logout-btn"
                    onClick={() => void handleLogout()}
                    disabled={loggingOut}
                  >
                    {loggingOut ? "Signing out…" : "Sign out"}
                  </button>
                ) : (
                  <span className="badge badge-info">BONC Auth</span>
                )}
              </div>
            )}
          </div>
        </div>
      </header>

      {authStatus !== "authenticated" ? (
        <main className="mod-container">
          <div className="auth-gate-wrap">
            {authStatus === "checking" ? (
              <div className="loading-state">
                <span className="spinner dark" /> Verifying BONC administrator access…
              </div>
            ) : (
              <section className="panel auth-card" aria-label="BONC Authentication Required">
                <span className="section-kicker">
                  BONC SEARCH ADMIN · BONC AUTHENTICATION
                </span>
                <h1>
                  {authStatus === "forbidden"
                    ? "Administrator Access Required"
                    : authStatus === "unavailable"
                      ? "BONC Authentication Unavailable"
                      : "Sign in through BONC"}
                </h1>
                <p className="panel-intro" style={{ marginBottom: 0 }}>
                  {authStatus === "forbidden"
                    ? "Your BONC identity was verified, but your account does not hold the required Search Admin permissions."
                    : authStatus === "unavailable"
                      ? "BONC token verification is not currently configured or reachable on the backend."
                      : "Search Admin uses BONC as its single source of authentication. Provide your BONC AuthToken or launch Search Admin from an authenticated BONC Admin session."}
                </p>

                {authNotice && (
                  <div
                    className="success-message"
                    style={{ marginTop: 14, marginBottom: 0 }}
                  >
                    {authNotice}
                  </div>
                )}

                {authError && (
                  <div
                    className="inline-error"
                    style={{ marginTop: 14, marginBottom: 0 }}
                  >
                    <strong>Authentication status</strong>
                    <span>{authError}</span>
                  </div>
                )}

                {!hasExternalBoncHostProvider() && (
                  <form
                    className="auth-form"
                    onSubmit={(event) => void handleBoncTokenSubmit(event)}
                  >
                    <label className="setting-field">
                      <span>BONC AuthToken (in-memory only)</span>
                      <input
                        type="password"
                        name="bonc_token"
                        autoComplete="off"
                        spellCheck={false}
                        placeholder="Paste BONC AuthToken from BONC sign-in"
                        value={boncTokenInput}
                        onChange={(event) => setBoncTokenInput(event.target.value)}
                      />
                    </label>
                    <button
                      type="submit"
                      className="primary-button auth-submit-btn"
                      disabled={!boncTokenInput.trim()}
                    >
                      Verify BONC Token
                    </button>
                  </form>
                )}

                <div className="inline-pills" style={{ marginTop: 18 }}>
                  <button
                    type="button"
                    className={
                      hasExternalBoncHostProvider() ? "primary-button" : "secondary-button"
                    }
                    onClick={() => void checkSession()}
                  >
                    Retry Verification
                  </button>
                  {getBoncHostLoginUrl() && (
                    <a
                      className="secondary-button"
                      href={getBoncHostLoginUrl() || undefined}
                    >
                      Open BONC Sign In
                    </a>
                  )}
                </div>

                <small
                  className="settings-footnote"
                  style={{ display: "block", marginTop: 16 }}
                >
                  Search Admin verifies BONC AuthTokens strictly in memory via BONC&apos;s
                  getUserDetail service. Tokens are never persisted to browser storage or
                  cookies.
                </small>
              </section>
            )}
          </div>
        </main>
      ) : (
        <main className="mod-container">
          <section className="page-heading">
            <div>
              <div className="eyebrow">BONC SEARCH AI PLATFORM · ADMIN CONSOLE</div>
              <h1>{sectionMeta[activeSection].title}</h1>
              <p>{sectionMeta[activeSection].subtitle}</p>
            </div>
          </section>

          {activeSection === "system-health" && (
            <SystemHealthPanel
              categories={platformCategories}
              refreshNonce={healthRefreshNonce}
              onHealthSnapshot={handleHealthSnapshot}
              onCategoriesChanged={() => void refreshCategories()}
              onConfigureCategory={handleConfigureCategoryFromHealth}
              onInspectSearchLogs={handleInspectSearchLogsFromHealth}
            />
          )}

          {activeSection === "search-logs" && (
            <SearchLogsPanel
              categories={platformCategories}
              initialCategory={logsInitialCategory}
              initialFailedOnly={logsInitialFailedOnly}
            />
          )}

          {activeSection === "data-sources" && (
            <div className="ops-stack">
              <div
                className="sub-tabs"
                role="tablist"
                aria-label="Data Sources and Configuration Workspaces"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={dataSubTab === "engines"}
                  className={`sub-tab ${dataSubTab === "engines" ? "active" : ""}`}
                  onClick={() => setDataSubTab("engines")}
                >
                  Engines &amp; Data Sources ({platformCategories.length})
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={dataSubTab === "testing"}
                  className={`sub-tab ${dataSubTab === "testing" ? "active" : ""}`}
                  onClick={() => setDataSubTab("testing")}
                >
                  Engine Testing
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={dataSubTab === "feedback"}
                  className={`sub-tab ${dataSubTab === "feedback" ? "active" : ""}`}
                  onClick={() => setDataSubTab("feedback")}
                >
                  Feedback Log
                </button>
              </div>

              <PlatformPanel
                mode={dataSubTab}
                initialCategoryId={focusCategoryId}
                openEditorNonce={openEditorNonce}
                onSelectMode={handlePanelNavigate}
                onSelectedCategoryChange={setFocusCategoryId}
                onCategoriesUpdated={setPlatformCategories}
              />
            </div>
          )}

          <footer className="footer">
            <span>BONC Network · General Search Platform &amp; Search Admin Console</span>
            <span>System Health · Search Logs · Data Sources &amp; Configuration</span>
          </footer>
        </main>
      )}
    </div>
  );
}
