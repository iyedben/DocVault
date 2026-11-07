/**
 * Core API client with automatic credentials, CSRF management, and error interception.
 * Operates strictly over same-origin endpoints with HttpOnly cookies.
 */

export const MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024; // 10 MiB backend limit

let csrfToken = null;
let onUnauthorizedHandler = null;
let onCsrfFailureHandler = null;
let csrfRefreshPromise = null;

/**
 * Configure the in-memory CSRF token.
 *
 * @param {string | null} token
 */
export function setCsrfToken(token) {
  csrfToken = token ? String(token) : null;
}

/**
 * Retrieve the current in-memory CSRF token.
 *
 * @returns {string | null}
 */
export function getCsrfToken() {
  return csrfToken;
}

/**
 * Register a callback for 401 Unauthorized responses.
 *
 * @param {(() => void) | null} handler
 */
export function setUnauthorizedHandler(handler) {
  onUnauthorizedHandler = handler;
}

/**
 * Register a callback for 403 CSRF validation failures.
 *
 * @param {((detail: string) => void) | null} handler
 */
export function setCsrfFailureHandler(handler) {
  onCsrfFailureHandler = handler;
}

/**
 * Refresh the CSRF token using a single-flight promise to avoid concurrent refresh collisions.
 *
 * @returns {Promise<string | null>}
 */
export async function refreshCsrfToken() {
  if (csrfRefreshPromise) {
    return csrfRefreshPromise;
  }

  csrfRefreshPromise = (async () => {
    try {
      const response = await fetch("/api/v1/auth/csrf", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
        },
      });

      if (response.ok) {
        const data = await response.json();
        if (data && typeof data.csrf_token === "string") {
          setCsrfToken(data.csrf_token);
          return data.csrf_token;
        }
      }
      return null;
    } catch {
      return null;
    } finally {
      csrfRefreshPromise = null;
    }
  })();

  return csrfRefreshPromise;
}

/**
 * Perform a secure fetch request with same-origin credentials.
 *
 * RETRY POLICY:
 * - State-changing requests (POST, PUT, PATCH, DELETE) are NEVER automatically retried.
 *   Automatic retries of mutating actions risk duplicate execution, replay issues,
 *   and race conditions.
 * - HTTP 403 handling:
 *   If the 403 response specifically contains {"detail": "CSRF validation failed"},
 *   the in-memory CSRF token is refreshed in the background via single-flight refreshCsrfToken()
 *   so the user's subsequent action will succeed, and onCsrfFailureHandler is notified.
 *   The 403 response is returned directly to the caller; NO automatic replay is performed.
 * - Generic HTTP 403 responses (e.g. "Administrator access required") are ordinary authorization
 *   denials and do NOT trigger CSRF token refresh, notification, or retries.
 * - HTTP 401 handling:
 *   Non-bootstrap 401 responses notify onUnauthorizedHandler to transition to anonymous state.
 *
 * @param {string} url
 * @param {RequestInit} [options={}]
 * @returns {Promise<Response>}
 */
export async function apiFetch(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});

  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  // Include CSRF token for mutating requests if available
  const isMutating = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  if (isMutating && csrfToken && !headers.has("X-CSRF-Token")) {
    headers.set("X-CSRF-Token", csrfToken);
  }

  const fetchOptions = {
    ...options,
    method,
    headers,
    credentials: "same-origin",
  };

  const response = await fetch(url, fetchOptions);

  // Handle 401 Unauthorized:
  // Do NOT recursively intercept authentication bootstrap or login calls.
  const isAuthBootstrap =
    url.includes("/api/v1/auth/login") || url.includes("/api/v1/auth/csrf");

  if (response.status === 401 && !isAuthBootstrap && onUnauthorizedHandler) {
    onUnauthorizedHandler();
  }

  // Handle 403 CSRF validation failures:
  // Strictly distinguish between CSRF rejection and ordinary permission denials.
  // Never automatically retry state-changing requests.
  if (response.status === 403) {
    // Clone response so original caller can still read the response body
    try {
      const cloned = response.clone();
      const errData = await cloned.json();
      if (errData && errData.detail === "CSRF validation failed") {
        // Synchronize token in background so subsequent user action succeeds
        refreshCsrfToken().catch(() => {});
        if (onCsrfFailureHandler) {
          onCsrfFailureHandler(errData.detail);
        }
      }
    } catch {
      // Non-JSON 403 or already consumed
    }
  }

  return response;
}

/**
 * Convenience alias for apiFetch.
 */
export const request = apiFetch;
