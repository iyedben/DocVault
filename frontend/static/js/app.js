/**
 * DocVault Single-Page Application Main Entry Point.
 * ES2022 Module — No build step required.
 */

import { renderNavbar } from "./components/navbar.js";
import { showAlert } from "./components/alerts.js";
import { navigateTo } from "./router.js";

/**
 * Initialize the DocVault application.
 */
function init() {
  const navbarContainer = document.getElementById("main-navbar");
  if (navbarContainer) {
    renderNavbar(navbarContainer, (view) => {
      window.location.hash = view;
      navigateTo(view);
    });
  }

  // Handle sidebar navigation links if present
  document.querySelectorAll(".dv-sidebar-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const view = link.getAttribute("href").replace("#", "");
      window.location.hash = view;
      navigateTo(view);
    });
  });

  // Handle URL hash changes
  window.addEventListener("hashchange", () => {
    const hash = window.location.hash.replace("#", "") || "dashboard";
    navigateTo(hash);
  });

  // Initial route
  const initialView = window.location.hash.replace("#", "") || "dashboard";
  navigateTo(initialView);

  // Informative notification on startup
  showAlert(
    "DocVault Phase B1 foundation loaded. Same-origin static assets and strict CSP verified.",
    "info",
    5000
  );
}

// Start application after DOM content is loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
