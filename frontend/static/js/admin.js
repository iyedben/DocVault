/**
 * DocVault Administration Service.
 * Manages administrative API interactions: user roster listing,
 * user provisioning, account status toggles, and role assignment.
 */

import { apiFetch } from "./api.js";

/**
 * Format an ISO date string into a user-friendly timestamp.
 *
 * @param {string | null | undefined} isoString
 * @returns {string} Formatted date string
 */
export function formatDateTime(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return String(isoString);
    return d.toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(isoString);
  }
}

/**
 * Validate a candidate username against DocVault backend requirements:
 * - 3 to 32 characters
 * - Starts with a lowercase letter or digit
 * - May contain lowercase letters, digits, dots, underscores, or hyphens
 *
 * @param {string} username
 * @returns {string | null} Error message or null if valid
 */
export function validateUsernamePolicy(username) {
  if (!username || typeof username !== "string") {
    return "Username is required.";
  }
  const trimmed = username.trim().toLowerCase();
  if (trimmed.length < 3 || trimmed.length > 32) {
    return "Username must be between 3 and 32 characters.";
  }
  const usernamePattern = /^[a-z0-9][a-z0-9_.-]{2,31}$/;
  if (!usernamePattern.test(trimmed)) {
    return "Username must start with a letter or digit and contain only lowercase letters, digits, dots, underscores, or hyphens.";
  }
  return null;
}

/**
 * Validate candidate password against DocVault backend complexity policy:
 * - 12 to 128 characters
 * - At least 3 categories: lowercase, uppercase, digits, symbols
 *
 * @param {string} password
 * @returns {string | null} Error message or null if valid
 */
export function validatePasswordPolicy(password) {
  if (!password || typeof password !== "string") {
    return "Password is required.";
  }
  if (password.length < 12 || password.length > 128) {
    return "Password must be between 12 and 128 characters.";
  }
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);
  const categories = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
  if (categories < 3) {
    return "Password must use at least 3 character categories (lowercase, uppercase, numbers, symbols).";
  }
  return null;
}

/**
 * Retrieve the complete user roster from the backend.
 *
 * @returns {Promise<{ success: boolean, users?: Array<object>, status?: number, error?: string }>}
 */
export async function listAdminUsers() {
  try {
    const response = await apiFetch("/api/v1/admin/users", {
      method: "GET",
    });

    if (response.ok) {
      const data = await response.json();
      return { success: true, users: Array.isArray(data) ? data : [] };
    }

    let detail = "Failed to load user roster.";
    try {
      const err = await response.json();
      if (err?.detail) {
        detail = typeof err.detail === "string" ? err.detail : "Failed to load user roster.";
      }
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error while connecting to administrator services.",
    };
  }
}

/**
 * Provision a new user account with assigned role and credentials.
 *
 * @param {{ username: string, password: string, role: "user" | "administrator" }} data
 * @returns {Promise<{ success: boolean, user?: object, status?: number, error?: string }>}
 */
export async function provisionAdminUser({ username, password, role }) {
  const usernameError = validateUsernamePolicy(username);
  if (usernameError) {
    return { success: false, status: 400, error: usernameError };
  }

  const passwordError = validatePasswordPolicy(password);
  if (passwordError) {
    return { success: false, status: 400, error: passwordError };
  }

  const normalizedRole = role === "administrator" ? "administrator" : "user";
  const normalizedUsername = username.trim().toLowerCase();

  try {
    const response = await apiFetch("/api/v1/admin/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: normalizedUsername,
        password,
        role: normalizedRole,
      }),
    });

    if (response.status === 201) {
      const data = await response.json();
      return { success: true, user: data };
    }

    let detail = "Failed to provision user.";
    try {
      const err = await response.json();
      if (err?.detail) {
        if (typeof err.detail === "string") {
          detail = err.detail;
        } else if (Array.isArray(err.detail) && err.detail.length > 0) {
          detail = err.detail.map((e) => e.msg || "Invalid input").join("; ");
        }
      }
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error while submitting provisioning request.",
    };
  }
}

/**
 * Update the active status of a user account.
 *
 * @param {string} userId
 * @param {boolean} isActive
 * @returns {Promise<{ success: boolean, user?: object, status?: number, error?: string }>}
 */
export async function setUserActiveStatus(userId, isActive) {
  if (!userId) {
    return { success: false, status: 400, error: "User ID is required." };
  }

  try {
    const response = await apiFetch(`/api/v1/admin/users/${encodeURIComponent(userId)}/status`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ is_active: Boolean(isActive) }),
    });

    if (response.ok) {
      const data = await response.json();
      return { success: true, user: data };
    }

    let detail = "Failed to update user status.";
    try {
      const err = await response.json();
      if (err?.detail) {
        detail = typeof err.detail === "string" ? err.detail : "Failed to update user status.";
      }
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error while updating user status.",
    };
  }
}

/**
 * Update the system role of a user account.
 *
 * @param {string} userId
 * @param {"user" | "administrator"} newRole
 * @returns {Promise<{ success: boolean, user?: object, status?: number, error?: string }>}
 */
export async function setUserRole(userId, newRole) {
  if (!userId) {
    return { success: false, status: 400, error: "User ID is required." };
  }

  const role = newRole === "administrator" ? "administrator" : "user";

  try {
    const response = await apiFetch(`/api/v1/admin/users/${encodeURIComponent(userId)}/role`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role }),
    });

    if (response.ok) {
      const data = await response.json();
      return { success: true, user: data };
    }

    let detail = "Failed to change user role.";
    try {
      const err = await response.json();
      if (err?.detail) {
        detail = typeof err.detail === "string" ? err.detail : "Failed to change user role.";
      }
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error while changing user role.",
    };
  }
}
