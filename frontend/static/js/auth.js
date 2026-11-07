/**
 * Authentication and session service for DocVault.
 * Coordinates with the backend API, in-memory authState, and CSRF management.
 */

import { apiFetch, setCsrfToken } from "./api.js";
import { authState } from "./auth-state.js";

/**
 * Authenticate with the DocVault API.
 *
 * @param {string} username
 * @param {string} password
 * @returns {Promise<{ success: boolean, user?: object, error?: string, status?: number }>}
 */
export async function login(username, password) {
  const cleanUsername = String(username || "").trim();
  const cleanPassword = String(password || "");

  if (!cleanUsername || !cleanPassword) {
    return {
      success: false,
      status: 422,
      error: "Please enter both username and password.",
    };
  }

  try {
    const response = await apiFetch("/api/v1/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: cleanUsername,
        password: cleanPassword,
      }),
    });

    if (response.status === 200) {
      const data = await response.json();
      if (!data || !data.user || !data.csrf_token) {
        throw new Error("Malformed login response from server");
      }
      setCsrfToken(data.csrf_token);
      authState.setAuthenticated(data.user);
      return { success: true, user: data.user };
    }

    if (response.status === 401) {
      return {
        success: false,
        status: 401,
        error: "Invalid username or password.",
      };
    }

    if (response.status === 429) {
      return {
        success: false,
        status: 429,
        error: "Too many login attempts. Please wait a few moments before trying again.",
      };
    }

    if (response.status === 422) {
      return {
        success: false,
        status: 422,
        error: "Invalid credentials format.",
      };
    }

    return {
      success: false,
      status: response.status,
      error: "Authentication service returned an unexpected status. Please try again.",
    };
  } catch (error) {
    return {
      success: false,
      status: 0,
      error: "Unable to connect to DocVault server. Please verify network connectivity.",
    };
  }
}

/**
 * Invalidate the active session on both the backend and frontend.
 *
 * Only clears local authentication state and CSRF token after confirmed HTTP 204
 * (or HTTP 401 where the server confirms the session was already terminated).
 * On network errors or unexpected server responses (5xx, 403), local state is NOT
 * cleared, and the failure is reported to prevent false logout states.
 *
 * @returns {Promise<{ success: boolean, status: number, error?: string, reconciled?: boolean }>}
 */
export async function logout() {
  authState.setLoggingOut();

  try {
    const response = await apiFetch("/api/v1/auth/logout", {
      method: "POST",
    });

    if (response.status === 204) {
      // Confirmed revocation: server has set revoked_at in PostgreSQL
      // and issued Set-Cookie with Max-Age=0.
      setCsrfToken(null);
      authState.setAnonymous();
      return { success: true, status: 204 };
    }

    if (response.status === 401) {
      // Session was already expired or revoked on the server.
      // Reconcile: since the backend considers this session non-existent, clear client state.
      setCsrfToken(null);
      authState.setAnonymous();
      return {
        success: true,
        status: 401,
        reconciled: true,
      };
    }

    // Any other response (e.g. 403 CSRF mismatch, 500 Internal Server Error, 502/503)
    // The server did NOT confirm revocation; PostgreSQL session may still be active.
    // Revert state back to authenticated so the UI does NOT falsely report logout.
    authState.cancelLoggingOut();

    let detail = "Server rejected sign out.";
    try {
      const err = await response.json();
      if (err && typeof err.detail === "string") {
        detail = err.detail;
      }
    } catch {
      // Non-JSON response
    }

    return {
      success: false,
      status: response.status,
      error: `Sign out failed (${response.status}): ${detail}`,
    };
  } catch (err) {
    // Network failure (offline, timeout, connection drop)
    // Server state is untouched, session cookie remains intact.
    // Do NOT transition to anonymous; revert authState.
    authState.cancelLoggingOut();

    return {
      success: false,
      status: 0,
      error: "Network error during sign out. You remain signed in.",
    };
  }
}

/**
 * Restore an existing session on page load or refresh.
 *
 * 1. Calls POST /api/v1/auth/csrf to bootstrap fresh CSRF token for active session.
 * 2. If valid (200), fetches current user info via GET /api/v1/auth/me.
 * 3. Populates in-memory authState or resets to anonymous.
 *
 * @returns {Promise<{ authenticated: boolean, user?: object }>}
 */
export async function restoreSession() {
  authState.setInitializing();

  try {
    // Step 1: CSRF bootstrap check
    const csrfResp = await apiFetch("/api/v1/auth/csrf", {
      method: "POST",
    });

    if (csrfResp.status !== 200) {
      setCsrfToken(null);
      authState.setAnonymous();
      return { authenticated: false };
    }

    const csrfData = await csrfResp.json();
    if (!csrfData || typeof csrfData.csrf_token !== "string") {
      setCsrfToken(null);
      authState.setAnonymous();
      return { authenticated: false };
    }

    setCsrfToken(csrfData.csrf_token);

    // Step 2: Retrieve current user identity
    const userResp = await apiFetch("/api/v1/auth/me");
    if (userResp.status !== 200) {
      setCsrfToken(null);
      authState.setAnonymous();
      return { authenticated: false };
    }

    const userData = await userResp.json();
    authState.setAuthenticated(userData);
    return { authenticated: true, user: userData };
  } catch {
    setCsrfToken(null);
    authState.setAnonymous();
    return { authenticated: false };
  }
}

/**
 * Check backend API process health and database readiness.
 *
 * @returns {Promise<{ healthy: boolean, ready: boolean }>}
 */
export async function checkBackendStatus() {
  let healthy = false;
  let ready = false;

  try {
    const healthResp = await apiFetch("/health");
    healthy = healthResp.ok;
  } catch {
    healthy = false;
  }

  try {
    const readyResp = await apiFetch("/ready");
    ready = readyResp.ok;
  } catch {
    ready = false;
  }

  return { healthy, ready };
}
