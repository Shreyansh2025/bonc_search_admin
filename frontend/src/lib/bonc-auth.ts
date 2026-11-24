/**
 * BONC Authentication Token Provider Adapter (In-Memory Only).
 *
 * Security & boundary guarantees:
 * - BONC is the ONLY supported Search Admin user authentication system.
 * - BONC owns user login, access tokens, refresh tokens, refresh flows, and logout/revocation.
 * - Search_Admin NEVER stores access or refresh tokens in localStorage, sessionStorage, cookies,
 *   URL query parameters, build artifacts, or logs.
 * - Search_Admin NEVER invents an unverified global browser variable (e.g. window.__BONC_TOKEN__),
 *   arbitrary window.parent access, or wildcard postMessage origin.
 * - Tokens are read either from a host-registered in-memory provider (`registerBoncAuthProvider`)
 *   or from the standalone in-memory BONC AuthToken input (`setInMemoryBoncAccessToken`).
 */

export interface BoncAuthTokenProvider {
  /** Return the current BONC-issued access token from host memory (never stored by Search_Admin). */
  getAccessToken: () => Promise<string | null> | string | null;
  /**
   * Optional host-owned token refresh hook invoked once when Search_Admin receives HTTP 401.
   * Search_Admin never holds a BONC refresh token or calls a competing refresh endpoint.
   */
  refreshAccessToken?: () => Promise<string | null> | string | null;
  /** Optional host-owned sign-out callback (BONC owns session/token revocation). */
  onLogout?: () => Promise<void> | void;
  /** Optional subscription allowing the host application to notify Search_Admin of logout. */
  subscribeLogout?: (listener: () => void) => () => void;
  /** Optional validated BONC sign-in URL (HTTP/HTTPS or relative path without tokens). */
  hostLoginUrl?: string;
}

let registeredHostProvider: BoncAuthTokenProvider | null = null;
let manualInMemoryToken: string | null = null;
let unsubscribeFromHost: (() => void) | null = null;

const logoutListeners = new Set<() => void>();

function normalizeToken(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  // Reject control characters or embedded whitespace that could corrupt Authorization headers.
  if (/[\s\x00-\x1f\x7f]/.test(trimmed)) return null;
  return trimmed;
}

export function validateHostLoginUrl(rawUrl: string | undefined): string | null {
  if (!rawUrl || typeof rawUrl !== "string") return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
    if (/[?#].*(token|auth|jwt)=/i.test(trimmed)) return null;
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    if (/[?#].*(token|auth|jwt)=/i.test(parsed.search + parsed.hash)) {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Register the approved BONC host in-memory token provider.
 * Pass `null` to unregister (primarily for teardown in automated tests).
 */
export function registerBoncAuthProvider(provider: BoncAuthTokenProvider | null): void {
  if (unsubscribeFromHost) {
    try {
      unsubscribeFromHost();
    } finally {
      unsubscribeFromHost = null;
    }
  }
  registeredHostProvider = provider;
  if (provider !== null) {
    // Host-managed token provider always supersedes any manual in-memory token.
    manualInMemoryToken = null;
  }
  if (provider?.subscribeLogout) {
    unsubscribeFromHost = provider.subscribeLogout(() => {
      notifyBoncHostLogout();
    });
  }
}

export function getBoncAuthProvider(): BoncAuthTokenProvider | null {
  return registeredHostProvider;
}

export function hasExternalBoncHostProvider(): boolean {
  return registeredHostProvider !== null;
}

/**
 * Store a BONC Bearer AuthToken strictly in JS memory for standalone usage
 * when Search Admin is not mounted inside a BONC host shell. Never persisted
 * to browser storage, cookies, or URLs.
 */
export function setInMemoryBoncAccessToken(rawToken: string | null): boolean {
  if (rawToken === null) {
    manualInMemoryToken = null;
    return false;
  }
  const normalized = normalizeToken(rawToken);
  if (!normalized) {
    manualInMemoryToken = null;
    return false;
  }
  manualInMemoryToken = normalized;
  return true;
}

export function clearInMemoryBoncAccessToken(): void {
  manualInMemoryToken = null;
}

export function hasInMemoryBoncAccessToken(): boolean {
  return manualInMemoryToken !== null;
}

export function hasBoncHostLogoutCallback(): boolean {
  return typeof registeredHostProvider?.onLogout === "function";
}

export function getBoncHostLoginUrl(): string | null {
  return validateHostLoginUrl(registeredHostProvider?.hostLoginUrl);
}

/** Obtain the current BONC access token strictly from in-memory host provider or session memory. */
export async function getBoncAccessToken(): Promise<string | null> {
  if (registeredHostProvider) {
    try {
      const token = await registeredHostProvider.getAccessToken();
      return normalizeToken(token);
    } catch {
      return null;
    }
  }
  return manualInMemoryToken;
}

/** Delegate access-token refresh to the host BONC application when supported. */
export async function refreshBoncAccessToken(): Promise<string | null> {
  if (!registeredHostProvider?.refreshAccessToken) return null;
  try {
    const token = await registeredHostProvider.refreshAccessToken();
    return normalizeToken(token);
  } catch {
    return null;
  }
}

/** Delegate sign-out to the host BONC application when a logout callback is provided. */
export async function invokeBoncHostLogout(): Promise<boolean> {
  if (!registeredHostProvider?.onLogout) {
    return false;
  }
  await registeredHostProvider.onLogout();
  return true;
}

/** Allow the host BONC application to notify Search_Admin immediately on user logout. */
export function notifyBoncHostLogout(): void {
  clearInMemoryBoncAccessToken();
  for (const listener of logoutListeners) {
    listener();
  }
}

export function subscribeBoncHostLogout(listener: () => void): () => void {
  logoutListeners.add(listener);
  return () => {
    logoutListeners.delete(listener);
  };
}

/** Reset in-memory adapter state (intended for automated tests). */
export function resetBoncAuthAdapterForTests(): void {
  registerBoncAuthProvider(null);
  manualInMemoryToken = null;
  logoutListeners.clear();
}
