/**
 * Core API client with automatic credentials and CSRF handling.
 * Operates strictly over same-origin endpoints.
 */

export const MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024; // 10 MiB backend limit

let csrfToken = null;
let onUnauthorizedHandler = null;

/**
 * Configure the in-memory CSRF token.
 *
 * @param {string | null} token
 */
export function setCsrfToken(token) {
  csrfToken = token;
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
 * @param {() => void} handler
 */
export function setUnauthorizedHandler(handler) {
  onUnauthorizedHandler = handler;
}

/**
 * Perform a secure fetch request with same-origin credentials.
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

  if (response.status === 401 && onUnauthorizedHandler) {
    onUnauthorizedHandler();
  }

  return response;
}
