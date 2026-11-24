import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import PlatformPanel, { type PlatformPanelMode } from "./components/platform-panel";
import SearchLogsPanel from "./components/search-logs-panel";
import SystemHealthPanel, { healthLabel } from "./components/system-health-panel";
import {
  getBoncHostLoginUrl,
  getEffectiveFrontendAuthMode,
  hasBoncHostLogoutCallback,
  subscribeBoncHostLogout,
  subscribeFrontendAuthMode,
  type FrontendAuthMode,
} from "./lib/bonc-auth";
import {
  ADMIN_API_BASE,
  ApiError,
  clearClientSessionState,
  getAdminSession,
  getPlatformCategories,
  loginAdmin,
  logoutAdmin,
  setCsrfErrorHandler,
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
  // Authentication mode & verified session state (BONC host-integrated or explicit local dev)
  const [authMode, setAuthMode] = useState<FrontendAuthMode>(() =>
    getEffectiveFrontendAuthMode(),
  );
  const [authStatus, setAuthStatus] = useState<
    "checking" | "authenticated" | "unauthenticated" | "forbidden" | "unavailable"
  >("checking");
  const [adminSession, setAdminSession] = useState<AdminSessionInfo | null>(null);
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authNotice, setAuthNotice] = useState("");
  const [csrfNotice, setCsrfNotice] = useState("");
  const [loggingIn, setLoggingIn] = useState(false);
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
    setCsrfNotice("");
  }, []);

  const refreshCategories = useCallback(async () => {
    try {
      const cats = await getPlatformCategories();
      setPlatformCategories(cats);
    } catch {
      // Errors are surfaced on active panels or via 401 handler.
    }
  }, []);

  const checkSession = useCallback(async () => {
    setAuthStatus("checking");
    setAuthError("");
    setCsrfNotice("");
    try {
      const session = await getAdminSession();
      setAuthMode(getEffectiveFrontendAuthMode());
      if (session?.authenticated) {
        setAdminSession(session);
        setAuthStatus("authenticated");
      } else {
        setAdminSession(null);
        clearProtectedData();
        setAuthStatus("unauthenticated");
      }
    } catch (error) {
      setAuthMode(getEffectiveFrontendAuthMode());
      setAdminSession(null);
      clearProtectedData();
      if (error instanceof ApiError && error.status === 403) {
        setAuthStatus("forbidden");
        setAuthError(error.message || "Administrator permissions are required.");
      } else if (error instanceof ApiError && error.status === 503) {
        setAuthStatus("unavailable");
        setAuthError(
          error.message || "BONC authentication verification is not configured or unavailable.",
        );
      } else {
        setAuthStatus("unauthenticated");
        setAuthError(
          error instanceof Error
            ? error.message
            : "Unable to verify admin authentication status.",
        );
      }
    }
  }, [clearProtectedData]);

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (getEffectiveFrontendAuthMode() === "bonc") {
      setAuthError("Independent Search Admin login is disabled. Sign in through BONC.");
      return;
    }
    if (!loginUsername.trim() || !loginPassword) {
      setAuthError("Enter both username and password.");
      return;
    }
    setLoggingIn(true);
    setAuthError("");
    setAuthNotice("");
    setCsrfNotice("");
    try {
      const session = await loginAdmin({
        username: loginUsername,
        password: loginPassword,
      });
      setAdminSession(session);
      setLoginPassword("");
      setAuthStatus("authenticated");
    } catch (error) {
      setAuthMode(getEffectiveFrontendAuthMode());
      setAdminSession(null);
      setAuthStatus("unauthenticated");
      setAuthError(
        error instanceof Error ? error.message : "Authentication failed.",
      );
    } finally {
      setLoggingIn(false);
    }
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    setAuthError("");
    const currentMode = getEffectiveFrontendAuthMode();
    let hostHandled = false;
    try {
      const res = await logoutAdmin();
      hostHandled = res.hostHandled;
    } catch {
      // Clear local UI state even if the session was already revoked/expired.
    } finally {
      clearClientSessionState();
      setAdminSession(null);
      clearProtectedData();
      setAuthStatus("unauthenticated");
      setAuthNotice(
        currentMode === "bonc"
          ? hostHandled
            ? "Sign-out has been delegated to BONC."
            : "Search Admin view cleared. Sign out directly in BONC to end your BONC session."
          : "You have been signed out.",
      );
      setLoggingOut(false);
    }
  };

  useEffect(() => {
    const unsubMode = subscribeFrontendAuthMode((nextMode) => {
      setAuthMode(nextMode);
    });
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
        getEffectiveFrontendAuthMode() === "bonc"
          ? "Your BONC authentication token is missing or has expired. Reauthenticate in BONC."
          : "Your admin session has expired or been revoked. Please sign in again.",
      );
    });
    setForbiddenHandler((message) => {
      if (getEffectiveFrontendAuthMode() === "bonc") {
        setAdminSession(null);
        clearProtectedData();
        setAuthStatus("forbidden");
        setAuthError(message || "Administrator permissions are required.");
      }
    });
    setCsrfErrorHandler((message) => {
      setCsrfNotice(
        `${message}. Your session CSRF token may have rotated — refresh your session before retrying.`,
      );
    });
    return () => {
      unsubMode();
      unsubHostLogout();
      setUnauthorizedHandler(null);
      setForbiddenHandler(null);
      setCsrfErrorHandler(null);
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
                {authMode === "bonc" ? (
                  hasBoncHostLogoutCallback() ? (
                    <button
                      type="button"
                      className="secondary-button auth-logout-btn"
                      onClick={() => void handleLogout()}
                      disabled={loggingOut}
                    >
                      {loggingOut ? "Signing out…" : "Sign out (BONC)"}
                    </button>
                  ) : (
                    <span className="badge badge-info">BONC Auth</span>
                  )
                ) : (
                  <button
                    type="button"
                    className="secondary-button auth-logout-btn"
                    onClick={() => void handleLogout()}
                    disabled={loggingOut}
                  >
                    {loggingOut ? "Signing out…" : "Sign out"}
                  </button>
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
                <span className="spinner dark" />{" "}
                {authMode === "bonc"
                  ? "Verifying BONC administrator access…"
                  : "Verifying administrator session…"}
              </div>
            ) : authMode === "bonc" ? (
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
                      ? "Search Admin is configured for BONC authentication, but BONC token verification is not currently configured or reachable on the backend."
                      : "Search Admin uses BONC as its single source of authentication. Launch Search Admin from an authenticated BONC session with Administrator privileges."}
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

                <div className="inline-pills" style={{ marginTop: 18 }}>
                  <button
                    type="button"
                    className="primary-button"
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
                  Independent Search Admin username/password login is disabled in BONC mode.
                  Access tokens are consumed strictly in-memory via the approved BONC host
                  integration.
                </small>
              </section>
            ) : (
              <section className="panel auth-card" aria-label="Administrator Sign In">
                <span className="section-kicker">
                  BONC SEARCH ADMIN · LOCAL DEVELOPMENT AUTHENTICATION
                </span>
                <h1>Sign in to Search Admin</h1>
                <p className="panel-intro" style={{ marginBottom: 0 }}>
                  Authenticate with your local development administrator credentials to
                  access System Health, Search Logs, and Data Sources &amp; Configuration.
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
                    <strong>Sign-in notice</strong>
                    <span>{authError}</span>
                  </div>
                )}

                <form
                  className="auth-form"
                  onSubmit={(event) => void handleLogin(event)}
                >
                  <label className="setting-field">
                    <span>Admin Username</span>
                    <input
                      type="text"
                      name="username"
                      autoComplete="username"
                      value={loginUsername}
                      onChange={(event) => setLoginUsername(event.target.value)}
                      required
                      disabled={loggingIn}
                    />
                  </label>
                  <label className="setting-field">
                    <span>Password</span>
                    <input
                      type="password"
                      name="password"
                      autoComplete="current-password"
                      value={loginPassword}
                      onChange={(event) => setLoginPassword(event.target.value)}
                      required
                      disabled={loggingIn}
                    />
                  </label>
                  <button
                    type="submit"
                    className="primary-button auth-submit-btn"
                    disabled={loggingIn || !loginUsername.trim() || !loginPassword}
                  >
                    {loggingIn ? (
                      <>
                        <span className="spinner" /> Signing in…
                      </>
                    ) : (
                      "Sign in"
                    )}
                  </button>
                </form>

                <small
                  className="settings-footnote"
                  style={{ display: "block", marginTop: 16 }}
                >
                  Local development transition mode only. Staging and production require BONC
                  authentication with no fallback to local login.
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

          {csrfNotice && (
            <section className="notice notice-error" role="alert">
              <div className="notice-icon">!</div>
              <div style={{ flex: 1 }}>
                <strong>CSRF Verification Required (HTTP 403)</strong>
                <p>{csrfNotice}</p>
              </div>
              <div className="inline-pills">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => void checkSession()}
                >
                  Refresh Session
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setCsrfNotice("")}
                >
                  Dismiss
                </button>
              </div>
            </section>
          )}

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
