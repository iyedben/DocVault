/**
 * DocVault Single-Page Application Main Entry Point.
 * Coordinates application initialization, session restoration,
 * reactive navigation, and global error handling.
 */

import { renderNavbar, renderSidebar } from "./components/navbar.js";
import { showAlert } from "./components/alerts.js";
import { navigateTo } from "./router.js";
import { authState } from "./auth-state.js";
import { restoreSession } from "./auth.js";
import { setUnauthorizedHandler, setCsrfFailureHandler } from "./api.js";

/**
 * Initialize the DocVault application and restore active session.
 */
async function init() {
  const navbarContainer = document.getElementById("main-navbar");
  const sidebarContainer = document.getElementById("app-sidebar");

  // Initial mount of navbar and sidebar
  if (navbarContainer) {
    renderNavbar(navbarContainer, (view) => {
      window.location.hash = view;
      navigateTo(view);
    });
  }

  if (sidebarContainer) {
    renderSidebar(sidebarContainer, (view) => {
      window.location.hash = view;
      navigateTo(view);
    });
  }

  // Reactive UI update on auth state change
  authState.onStateChange((state) => {
    if (navbarContainer) {
      renderNavbar(navbarContainer, (view) => {
        window.location.hash = view;
        navigateTo(view);
      });
    }

    if (sidebarContainer) {
      renderSidebar(sidebarContainer, (view) => {
        window.location.hash = view;
        navigateTo(view);
      });
    }

    if (!state.isAuthenticated) {
      navigateTo("login");
    } else {
      const currentHash = window.location.hash.replace("#", "");
      if (!currentHash || currentHash === "login") {
        window.location.hash = "dashboard";
        navigateTo("dashboard");
      } else {
        navigateTo(currentHash);
      }
    }
  });

  // Global 401 Unauthorized handler for expired or revoked sessions
  setUnauthorizedHandler(() => {
    if (authState.isAuthenticated()) {
      authState.setAnonymous();
      showAlert("Your session has expired. Please sign in again.", "warning", 6000);
      window.location.hash = "login";
      navigateTo("login");
    }
  });

  // Global 403 CSRF failure notification
  setCsrfFailureHandler(() => {
    showAlert("Security token refreshed. Please submit your request again.", "warning", 5000);
  });

  // Handle URL hash navigation
  window.addEventListener("hashchange", () => {
    const hash = window.location.hash.replace("#", "") || "dashboard";
    navigateTo(hash);
  });

  // Session restoration on startup
  try {
    const sessionResult = await restoreSession();
    if (sessionResult.authenticated) {
      const initialView = window.location.hash.replace("#", "") || "dashboard";
      navigateTo(initialView === "login" ? "dashboard" : initialView);
    } else {
      window.location.hash = "login";
      navigateTo("login");
    }
  } catch {
    authState.setAnonymous();
    window.location.hash = "login";
    navigateTo("login");
  }
}

// Start application after DOM content is loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
