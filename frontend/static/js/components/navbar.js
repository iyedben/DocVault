/**
 * Navigation bar and sidebar components with dynamic role-aware rendering.
 */

import { createElement, createSvgIcon, clearElement } from "../utils/dom.js";
import { authState } from "../auth-state.js";
import { logout } from "../auth.js";
import { showAlert } from "./alerts.js";

// Shield SVG path for the DocVault brand icon
const SHIELD_PATH =
  "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 16l-4-4 1.41-1.41L11 14.17l6.59-6.59L19 9l-8 8z";

const LOGOUT_ICON =
  "M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z";

const USER_ICON =
  "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z";

/**
 * Safely execute logout, reporting failures without falling into a false anonymous state.
 *
 * @param {HTMLButtonElement} btn
 * @param {(viewName: string) => void} onNavigate
 */
async function executeLogout(btn, onNavigate) {
  btn.disabled = true;
  try {
    const res = await logout();
    if (res.success) {
      const msg = res.reconciled
        ? "Session was already expired on the server. You are signed out."
        : "You have been signed out successfully.";
      showAlert(msg, "info", 4000);
      onNavigate("login");
    } else {
      showAlert(res.error || "Sign out failed. Please try again.", "danger", 6000);
      btn.disabled = false;
    }
  } catch (err) {
    showAlert("Sign out error: " + (err?.message || "Unknown error"), "danger", 6000);
    btn.disabled = false;
  }
}

/**
 * Render the top navigation bar according to authentication and role state.
 *
 * @param {HTMLElement} container
 * @param {(viewName: string) => void} onNavigate
 */
export function renderNavbar(container, onNavigate) {
  clearElement(container);

  const brandIcon = createSvgIcon(SHIELD_PATH, "dv-brand-icon", 22);

  const brandText = createElement(
    "span",
    {},
    "Doc",
    createElement("span", { className: "dv-brand-vault" }, "Vault")
  );

  const brandLink = createElement(
    "a",
    {
      className: "dv-brand",
      href: authState.isAuthenticated() ? "#dashboard" : "#login",
      onclick: (e) => {
        e.preventDefault();
        onNavigate(authState.isAuthenticated() ? "dashboard" : "login");
      },
    },
    brandIcon,
    brandText
  );

  const isAuth = authState.isAuthenticated();
  const isAdmin = authState.isAdmin();
  const user = authState.getUser();

  // Navigation Links (only for authenticated sessions)
  let navCollapseContent = [];

  if (isAuth) {
    const navLinks = [
      { id: "dashboard", label: "Dashboard" },
      { id: "documents", label: "Documents" },
      ...(isAdmin ? [{ id: "admin", label: "Administration" }] : []),
      { id: "settings", label: "Settings" },
    ];

    const currentHash = window.location.hash.replace("#", "") || "dashboard";

    const navItems = navLinks.map((item) =>
      createElement(
        "li",
        { className: "nav-item" },
        createElement(
          "a",
          {
            id: `nav-${item.id}`,
            className: `dv-nav-link ${currentHash === item.id ? "active" : ""}`,
            href: `#${item.id}`,
            onclick: (e) => {
              e.preventDefault();
              onNavigate(item.id);
            },
          },
          item.label
        )
      )
    );

    const navList = createElement(
      "ul",
      { className: "navbar-nav me-auto mb-2 mb-lg-0 gap-1" },
      ...navItems
    );

    // User Profile Pill & Logout Button
    const userRoleBadge = createElement(
      "span",
      {
        className: `badge ${isAdmin ? "text-bg-warning" : "text-bg-secondary"} text-uppercase ms-1 dv-role-badge`,
      },
      user?.role || "user"
    );

    const userPill = createElement(
      "div",
      { className: "d-flex align-items-center gap-1 text-light small px-2 py-1 rounded bg-secondary bg-opacity-25" },
      createSvgIcon(USER_ICON, "text-white-50", 16),
      createElement("span", { className: "fw-medium" }, user?.username || ""),
      userRoleBadge
    );

    const logoutBtn = createElement(
      "button",
      {
        type: "button",
        id: "btn-navbar-logout",
        className: "btn btn-outline-danger btn-sm d-flex align-items-center gap-1",
        title: "Sign out of your session",
        "aria-label": "Sign out of your session",
        onclick: () => executeLogout(logoutBtn, onNavigate),
      },
      createSvgIcon(LOGOUT_ICON, "", 16),
      createElement("span", {}, "Sign Out")
    );

    const userControls = createElement(
      "div",
      { className: "d-flex align-items-center gap-3 ms-lg-3 mt-2 mt-lg-0" },
      userPill,
      logoutBtn
    );

    navCollapseContent = [navList, userControls];
  } else {
    // Anonymous status badge
    const anonBadge = createElement(
      "div",
      { className: "ms-auto d-flex align-items-center gap-2 text-white-50 small" },
      createElement("span", { className: "badge rounded-pill text-bg-secondary" }, "Secure Session"),
      createElement("span", { className: "d-none d-md-inline" }, "Academic DevSecOps")
    );
    navCollapseContent = [anonBadge];
  }

  const navCollapse = createElement(
    "div",
    { className: "collapse navbar-collapse", id: "mainNavbarNav" },
    ...navCollapseContent
  );

  const toggleBtn = createElement(
    "button",
    {
      className: "navbar-toggler border-secondary",
      type: "button",
      "data-bs-toggle": "collapse",
      "data-bs-target": "#mainNavbarNav",
      "aria-controls": "mainNavbarNav",
      "aria-expanded": "false",
      "aria-label": "Toggle navigation",
    },
    createElement("span", { className: "navbar-toggler-icon" })
  );

  const navContainer = createElement(
    "div",
    { className: "container-fluid px-3 px-lg-4" },
    createElement("div", { className: "d-flex align-items-center" }, brandLink),
    ...(isAuth ? [toggleBtn] : []),
    navCollapse
  );

  container.appendChild(navContainer);
}

/**
 * Render the desktop sidebar according to authentication and role state.
 *
 * @param {HTMLElement} sidebarEl
 * @param {(viewName: string) => void} onNavigate
 */
export function renderSidebar(sidebarEl, onNavigate) {
  clearElement(sidebarEl);

  if (!authState.isAuthenticated()) {
    sidebarEl.classList.add("d-none");
    return;
  }

  sidebarEl.classList.remove("d-none");

  const isAdmin = authState.isAdmin();
  const currentHash = window.location.hash.replace("#", "") || "dashboard";

  // Workspace Section
  const workspaceHeader = createElement(
    "div",
    { className: "text-uppercase small fw-bold text-muted px-3 mb-2" },
    "Workspace"
  );

  const sideDashboard = createElement(
    "a",
    {
      href: "#dashboard",
      id: "side-dashboard",
      className: `dv-sidebar-link ${currentHash === "dashboard" ? "active" : ""}`,
      onclick: (e) => {
        e.preventDefault();
        onNavigate("dashboard");
      },
    },
    createElement("span", {}, "Dashboard")
  );

  const sideDocuments = createElement(
    "a",
    {
      href: "#documents",
      id: "side-documents",
      className: `dv-sidebar-link ${currentHash === "documents" ? "active" : ""}`,
      onclick: (e) => {
        e.preventDefault();
        onNavigate("documents");
      },
    },
    createElement("span", {}, "Documents")
  );

  sidebarEl.appendChild(workspaceHeader);
  sidebarEl.appendChild(sideDashboard);
  sidebarEl.appendChild(sideDocuments);

  // Administration Section (Admin only)
  if (isAdmin) {
    const adminHeader = createElement(
      "div",
      { className: "text-uppercase small fw-bold text-muted px-3 mt-4 mb-2" },
      "Administration"
    );

    const sideAdmin = createElement(
      "a",
      {
        href: "#admin",
        id: "side-admin",
        className: `dv-sidebar-link ${currentHash === "admin" ? "active" : ""}`,
        onclick: (e) => {
          e.preventDefault();
          onNavigate("admin");
        },
      },
      createElement("span", {}, "User Management")
    );

    sidebarEl.appendChild(adminHeader);
    sidebarEl.appendChild(sideAdmin);
  }

  // Security Section
  const securityHeader = createElement(
    "div",
    { className: "text-uppercase small fw-bold text-muted px-3 mt-4 mb-2" },
    "Account"
  );

  const sideSettings = createElement(
    "a",
    {
      href: "#settings",
      id: "side-settings",
      className: `dv-sidebar-link ${currentHash === "settings" ? "active" : ""}`,
      onclick: (e) => {
        e.preventDefault();
        onNavigate("settings");
      },
    },
    createElement("span", {}, "Security Settings")
  );

  sidebarEl.appendChild(securityHeader);
  sidebarEl.appendChild(sideSettings);

  // Footer / Logout
  const sidebarLogoutBtn = createElement(
    "button",
    {
      type: "button",
      id: "btn-sidebar-logout",
      className: "btn btn-outline-secondary btn-sm w-100 d-flex align-items-center justify-content-center gap-2",
      title: "Sign out of your session",
      "aria-label": "Sign out of your session",
      onclick: () => executeLogout(sidebarLogoutBtn, onNavigate),
    },
    createSvgIcon(LOGOUT_ICON, "", 16),
    createElement("span", {}, "Sign Out")
  );

  const sideFooter = createElement(
    "div",
    { className: "mt-auto px-2 py-3 border-top" },
    sidebarLogoutBtn
  );

  sidebarEl.appendChild(sideFooter);
}

/**
 * Update the active navigation link visually across navbar and sidebar.
 *
 * @param {string} viewName
 */
export function setActiveNavLink(viewName) {
  document.querySelectorAll(".dv-nav-link, .dv-sidebar-link").forEach((link) => {
    link.classList.remove("active");
  });

  const activeTop = document.getElementById(`nav-${viewName}`);
  if (activeTop) {
    activeTop.classList.add("active");
  }

  const activeSide = document.getElementById(`side-${viewName}`);
  if (activeSide) {
    activeSide.classList.add("active");
  }
}
