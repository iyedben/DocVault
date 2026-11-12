/**
 * Client-side view router for the DocVault single-page application.
 * Enforces authentication guards and role-aware view rendering.
 */

import { createElement, clearElement } from "./utils/dom.js";
import { setActiveNavLink } from "./components/navbar.js";
import { checkBackendStatus } from "./auth.js";
import { authState, AuthStatus } from "./auth-state.js";
import { showLoading } from "./components/loading.js";
import { renderLoginView } from "./views/login.js";
import { renderDocumentsView } from "./views/documents.js";
import { renderSettingsView } from "./views/settings.js";
import { renderAdminView } from "./views/admin.js";
import { showAlert } from "./components/alerts.js";

/**
 * Render the authenticated DocVault Dashboard.
 *
 * @param {HTMLElement} container
 */
async function renderDashboardView(container) {
  showLoading(container, "Verifying backend services...");

  const status = await checkBackendStatus();
  const user = authState.getUser();

  clearElement(container);

  // User Welcome Banner Card
  const welcomeCard = createElement(
    "div",
    { className: "dv-card bg-primary bg-opacity-10 border-primary border-opacity-25 mb-4" },
    createElement(
      "div",
      { className: "dv-card-body d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3" },
      createElement(
        "div",
        {},
        createElement(
          "h4",
          { className: "fw-bold text-primary mb-1" },
          `Welcome back, ${user?.username || "User"}`
        ),
        createElement(
          "p",
          { className: "text-muted small mb-0" },
          "DocVault Secure Document Management Platform • Active Server Session"
        )
      ),
      createElement(
        "div",
        { className: "d-flex align-items-center gap-2" },
        createElement(
          "span",
          {
            className: `badge ${user?.role === "administrator" ? "text-bg-warning" : "text-bg-primary"} text-uppercase px-3 py-2 fw-semibold`,
          },
          `Role: ${user?.role || "user"}`
        ),
        createElement(
          "span",
          { className: "badge text-bg-success px-3 py-2 fw-semibold" },
          "Session Active"
        )
      )
    )
  );

  // Platform Status & Security Controls Card
  const statusHeader = createElement(
    "div",
    { className: "dv-card-header" },
    createElement("h5", { className: "mb-0 fw-semibold" }, "Platform Status & Security Architecture"),
    createElement(
      "span",
      { className: `badge ${status.healthy && status.ready ? "text-bg-success" : "text-bg-danger"}` },
      status.healthy && status.ready ? "All Systems Operational" : "Degraded Service"
    )
  );

  const statusRows = [
    { label: "API Process Liveness (/health)", val: status.healthy ? "HTTP 200 OK — Healthy" : "Offline" },
    { label: "PostgreSQL Database Readiness (/ready)", val: status.ready ? "HTTP 200 OK — Ready" : "Unavailable" },
    { label: "Authentication & Password Hashing", val: "Argon2id with per-user salt and memory-hard cost" },
    { label: "Session Security & Cookie", val: "PostgreSQL-backed opaque token; HttpOnly; SameSite=Lax (Path: /api/v1)" },
    { label: "Synchronizer CSRF Protection", val: "SHA-256 token digest in database; in-memory rotation on state changes" },
    { label: "Content Security Policy (CSP)", val: "Strict: default-src 'self'; script-src 'self'; style-src 'self' (Zero inline)" },
    { label: "Container Isolation", val: "Non-root UID 10001; Read-only rootfs; Dropped capabilities; Loopback-only binding" },
  ];

  const tableBody = createElement(
    "tbody",
    {},
    ...statusRows.map((r) =>
      createElement(
        "tr",
        {},
        createElement("td", { className: "fw-medium text-muted dv-status-label-col" }, r.label),
        createElement("td", { className: "fw-semibold" }, r.val)
      )
    )
  );

  const statusTable = createElement(
    "table",
    { className: "table dv-table mb-0" },
    tableBody
  );

  const statusCard = createElement(
    "div",
    { className: "dv-card" },
    statusHeader,
    createElement("div", { className: "table-responsive" }, statusTable)
  );

  // Phase B Roadmap Card
  const roadmapHeader = createElement(
    "div",
    { className: "dv-card-header" },
    createElement("h5", { className: "mb-0 fw-semibold" }, "Phase B Implementation Roadmap"),
    createElement("span", { className: "dv-badge-phase" }, "Phase B7 Active")
  );

  const roadmapItems = [
    { phase: "B1", title: "Frontend Foundation & Static Serving", desc: "Vanilla JS ES2022 modules, Bootstrap 5.3 vendored, FastAPI static mounting, and strict CSP verification.", status: "Verified" },
    { phase: "B2", title: "Authentication & Session Integration", desc: "Interactive login view, CSRF bootstrap, session restoration, role-aware navigation, and secure logout.", status: "Verified" },
    { phase: "B3", title: "Document Workspace & Upload", desc: "Interactive document table, drag-and-drop PDF upload modal with 10 MiB client validation, and direct download.", status: "Verified" },
    { phase: "B4", title: "Document Sharing & User Lookup", desc: "Granular document access management with debounced user lookup, share grants, access revocation, and self-share prevention.", status: "Verified" },
    { phase: "B5", title: "Self-Service Security Settings", desc: "In-session password change with Argon2id verification, validation feedback, and multi-session revocation.", status: "Verified" },
    { phase: "B6", title: "Role-Gated Administration Panel", desc: "Admin user provisioning, account activation/deactivation, and role lifecycle management.", status: "Verified" },
    { phase: "B7", title: "Frontend Polish & Security Audit", desc: "WCAG accessibility hardening, focus trap/restoration, DOM XSS prevention, and mobile responsiveness.", status: "Active" },
  ];

  const roadmapCards = roadmapItems.map((item) =>
    createElement(
      "div",
      { className: "col-12 col-lg-6" },
      createElement(
        "div",
        { className: "p-3 border rounded-3 bg-light h-100 d-flex flex-column dv-roadmap-item" },
        createElement(
          "div",
          { className: "d-flex justify-content-between align-items-center mb-2" },
          createElement("span", { className: "badge text-bg-primary fw-bold" }, item.phase),
          createElement(
            "span",
            { className: `badge ${item.status.includes("Verified") ? "text-bg-success" : "text-bg-primary"}` },
            item.status
          )
        ),
        createElement("h6", { className: "fw-bold mb-1" }, item.title),
        createElement("p", { className: "small text-muted mb-0 flex-grow-1" }, item.desc)
      )
    )
  );

  const roadmapGrid = createElement(
    "div",
    { className: "row g-3" },
    ...roadmapCards
  );

  const roadmapCard = createElement(
    "div",
    { className: "dv-card" },
    roadmapHeader,
    createElement("div", { className: "dv-card-body" }, roadmapGrid)
  );

  container.appendChild(welcomeCard);
  container.appendChild(statusCard);
  container.appendChild(roadmapCard);
}

/**
 * Render placeholder view for planned future modules.
 *
 * @param {HTMLElement} container
 * @param {string} title
 * @param {string} phase
 * @param {string} description
 */
function renderPlaceholderView(container, title, phase, description) {
  clearElement(container);

  const card = createElement(
    "div",
    { className: "dv-card text-center py-5 px-4" },
    createElement(
      "div",
      { className: "mb-3" },
      createElement("span", { className: "dv-badge-phase" }, phase)
    ),
    createElement("h4", { className: "fw-bold mb-2" }, title),
    createElement(
      "p",
      { className: "text-muted mx-auto mb-4 dv-constrained-text" },
      description
    ),
    createElement(
      "div",
      { className: "d-flex justify-content-center gap-2" },
      createElement(
        "button",
        {
          type: "button",
          className: "btn btn-outline-primary btn-sm",
          onclick: () => navigateTo("dashboard"),
        },
        "Return to Dashboard"
      )
    )
  );

  container.appendChild(card);
}

const routes = {
  login: renderLoginView,
  dashboard: renderDashboardView,
  documents: renderDocumentsView,
  admin: (container, navigateTo) => {
    if (!authState.isAdmin()) {
      showAlert("Administrator access required for Administration Console.", "warning", 5000);
      navigateTo("dashboard");
      return;
    }
    renderAdminView(container, navigateTo);
  },
  settings: renderSettingsView,
};

let renderedRoute = null;
let renderedAuthStatus = null;
let renderedUserId = null;
let renderedUserRole = null;

/**
 * Invalidate the currently rendered route cache.
 * Called on explicit logout, session expiration, or auth state transitions.
 */
export function resetRouterState() {
  renderedRoute = null;
  renderedAuthStatus = null;
  renderedUserId = null;
  renderedUserRole = null;
}

// Automatically invalidate route cache on any authentication state transition
authState.onStateChange((state) => {
  if (
    state.status !== renderedAuthStatus ||
    (state.user?.id || null) !== renderedUserId ||
    (state.user?.role || null) !== renderedUserRole
  ) {
    resetRouterState();
  }
});

/**
 * Navigate to a named view, enforcing authentication and role guards.
 * Implements state-aware route idempotency to prevent destructive re-rendering
 * when the requested route and authentication context have not changed.
 *
 * @param {string} viewName
 */
export async function navigateTo(viewName) {
  const container = document.getElementById("main-content");
  if (!container) {
    return;
  }

  const authStatus = authState.getStatus();

  // Loading / Initializing state
  if (authStatus === AuthStatus.INITIALIZING) {
    if (renderedRoute !== "loading" || !container.querySelector(".spinner-border")) {
      showLoading(container, "Verifying secure session...");
      renderedRoute = "loading";
      renderedAuthStatus = authStatus;
      renderedUserId = null;
      renderedUserRole = null;
    }
    return;
  }

  // Unauthenticated / Anonymous guard
  if (!authState.isAuthenticated()) {
    setActiveNavLink("login");

    // Idempotency: if login view is already rendered with anonymous status and DOM elements are present
    if (
      renderedRoute === "login" &&
      renderedAuthStatus === authStatus &&
      container.querySelector("#login-form")
    ) {
      return;
    }

    renderedRoute = "login";
    renderedAuthStatus = authStatus;
    renderedUserId = null;
    renderedUserRole = null;

    renderLoginView(container, navigateTo);
    return;
  }

  // Authenticated: route to destination (or fallback to dashboard)
  let targetView = viewName;
  if (targetView === "login" || !routes[targetView]) {
    targetView = "dashboard";
    if (window.location.hash !== "#dashboard") {
      window.location.hash = "dashboard";
    }
  }

  // Admin route guard
  if (targetView === "admin" && !authState.isAdmin()) {
    showAlert("Administrator access required.", "warning", 4000);
    targetView = "dashboard";
    if (window.location.hash !== "#dashboard") {
      window.location.hash = "dashboard";
    }
  }

  setActiveNavLink(targetView);

  const user = authState.getUser();
  const userId = user?.id || null;
  const userRole = user?.role || null;

  // Idempotency: if targetView is already rendered under identical auth context & user identity
  if (
    renderedRoute === targetView &&
    renderedAuthStatus === authStatus &&
    renderedUserId === userId &&
    renderedUserRole === userRole &&
    container.firstElementChild
  ) {
    return;
  }

  renderedRoute = targetView;
  renderedAuthStatus = authStatus;
  renderedUserId = userId;
  renderedUserRole = userRole;

  const handler = routes[targetView];
  try {
    await handler(container, navigateTo);
  } catch (err) {
    renderedRoute = null;
    throw err;
  }
}
