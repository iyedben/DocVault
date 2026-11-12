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

  // Unified navigation handler to prevent duplicate dispatching
  const handleNav = (view) => {
    if (window.location.hash === `#${view}`) {
      navigateTo(view);
    } else {
      window.location.hash = view;
    }
  };

  // Initial mount of navbar and sidebar
  if (navbarContainer) {
    renderNavbar(navbarContainer, handleNav);
  }

  if (sidebarContainer) {
    renderSidebar(sidebarContainer, handleNav);
  }

  // Reactive UI update on auth state change
  authState.onStateChange((state) => {
    if (navbarContainer) {
      renderNavbar(navbarContainer, handleNav);
    }

    if (sidebarContainer) {
      renderSidebar(sidebarContainer, handleNav);
    }

    // Do not alter routes or redirect while session restoration is in-flight
    if (state.status === "initializing") {
      return;
    }

    if (!state.isAuthenticated) {
      if (window.location.hash !== "#login") {
        window.location.hash = "login";
      }
      navigateTo("login");
    } else {
      const currentHash = window.location.hash.replace("#", "");
      if (!currentHash || currentHash === "login") {
        if (window.location.hash !== "#dashboard") {
          window.location.hash = "dashboard";
        }
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
      if (window.location.hash !== "#login") {
        window.location.hash = "login";
      }
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
      const target = initialView === "login" ? "dashboard" : initialView;
      if (window.location.hash !== `#${target}`) {
        window.location.hash = target;
      }
      navigateTo(target);
    } else {
      if (window.location.hash !== "#login") {
        window.location.hash = "login";
      }
      navigateTo("login");
    }
  } catch {
    authState.setAnonymous();
    if (window.location.hash !== "#login") {
      window.location.hash = "login";
    }
    navigateTo("login");
  }
}

// Start application after DOM content is loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
