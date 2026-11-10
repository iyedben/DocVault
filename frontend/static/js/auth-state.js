/**
 * In-memory authentication state machine for DocVault.
 * Strictly avoids localStorage, sessionStorage, and JavaScript-managed cookies.
 */

export const AuthStatus = Object.freeze({
  INITIALIZING: "initializing",
  ANONYMOUS: "anonymous",
  AUTHENTICATED: "authenticated",
  LOGGING_OUT: "logging_out",
});

let currentStatus = AuthStatus.INITIALIZING;
let currentUser = null; // { id, username, role, isActive, createdAt, updatedAt }
const listeners = new Set();

/**
 * Notify all registered state change listeners.
 */
function notifyListeners() {
  const snapshot = {
    status: currentStatus,
    user: currentUser ? { ...currentUser } : null,
    isAuthenticated: currentStatus === AuthStatus.AUTHENTICATED && !!currentUser,
    isAdmin: currentStatus === AuthStatus.AUTHENTICATED && currentUser?.role === "administrator",
  };
  for (const listener of listeners) {
    try {
      listener(snapshot);
    } catch (err) {
      console.error("Error in auth state listener:", err);
    }
  }
}

export const authState = {
  /**
   * Get the current authentication lifecycle status.
   * @returns {"initializing" | "anonymous" | "authenticated" | "logging_out"}
   */
  getStatus() {
    return currentStatus;
  },

  /**
   * Get a copy of the current authenticated user object, or null.
   * @returns {{ id: string, username: string, role: string, isActive: boolean } | null}
   */
  getUser() {
    return currentUser ? { ...currentUser } : null;
  },

  /**
   * Get the user's role ("user" | "administrator" | null).
   * @returns {string | null}
   */
  getRole() {
    return currentUser?.role || null;
  },

  /**
   * Check if the user is authenticated in memory.
   * @returns {boolean}
   */
  isAuthenticated() {
    return currentStatus === AuthStatus.AUTHENTICATED && !!currentUser;
  },

  /**
   * Check if the current authenticated user has administrator privileges.
   * @returns {boolean}
   */
  isAdmin() {
    return this.isAuthenticated() && currentUser?.role === "administrator";
  },

  /**
   * Transition to authenticated state with safe user metadata.
   * @param {{ id: string, username: string, role: string, is_active?: boolean, isActive?: boolean }} user
   */
  setAuthenticated(user) {
    if (!user || !user.id || !user.username || !user.role) {
      throw new Error("Invalid user metadata provided to authState.setAuthenticated");
    }
    currentUser = {
      id: String(user.id),
      username: String(user.username),
      role: String(user.role),
      isActive: user.is_active ?? user.isActive ?? true,
    };
    currentStatus = AuthStatus.AUTHENTICATED;
    notifyListeners();
  },

  /**
   * Transition to anonymous state and clear in-memory user details.
   */
  setAnonymous() {
    currentUser = null;
    currentStatus = AuthStatus.ANONYMOUS;
    notifyListeners();
  },

  /**
   * Transition to logging_out state while logout request is inflight.
   */
  setLoggingOut() {
    currentStatus = AuthStatus.LOGGING_OUT;
    notifyListeners();
  },

  /**
   * Cancel in-flight logout and restore authenticated status if user is present.
   * Prevents UI from falling into false anonymous state when logout fails.
   */
  cancelLoggingOut() {
    if (currentUser) {
      currentStatus = AuthStatus.AUTHENTICATED;
    } else {
      currentStatus = AuthStatus.ANONYMOUS;
    }
    notifyListeners();
  },

  /**
   * Transition to initializing state on startup/session restoration.
   */
  setInitializing() {
    currentUser = null;
    currentStatus = AuthStatus.INITIALIZING;
    notifyListeners();
  },

  /**
   * Register a callback for authentication state changes.
   * @param {(state: { status: string, user: object | null, isAuthenticated: boolean, isAdmin: boolean }) => void} callback
   * @returns {() => void} Unsubscribe function
   */
  onStateChange(callback) {
    listeners.add(callback);
    return () => listeners.delete(callback);
  },
};
