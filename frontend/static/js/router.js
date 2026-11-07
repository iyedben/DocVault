/**
 * Client-side view router for the single-page application shell.
 */

import { createElement, clearElement } from "./utils/dom.js";
import { setActiveNavLink } from "./components/navbar.js";
import { checkBackendStatus } from "./auth.js";
import { showLoading } from "./components/loading.js";

/**
 * Render the Phase B1 Foundation Dashboard.
 *
 * @param {HTMLElement} container
 */
async function renderDashboardView(container) {
  showLoading(container, "Verifying backend services...");

  const status = await checkBackendStatus();

  clearElement(container);

  // Status Banner Card
  const statusHeader = createElement(
    "div",
    { className: "dv-card-header" },
    createElement("h5", { className: "mb-0 fw-semibold" }, "Platform Status & Integration"),
    createElement(
      "span",
      { className: `badge ${status.healthy ? "text-bg-success" : "text-bg-danger"}` },
      status.healthy ? "Services Active" : "Service Offline"
    )
  );

  const statusRows = [
    { label: "API Process Liveness (/health)", val: status.healthy ? "HTTP 200 OK — Healthy" : "Offline" },
    { label: "PostgreSQL Database Readiness (/ready)", val: status.ready ? "HTTP 200 OK — Ready" : "Unavailable" },
    { label: "Content Security Policy (CSP)", val: "Strict: default-src 'self'; script-src 'self'; style-src 'self'" },
    { label: "HTTP Security Headers", val: "X-Frame-Options: DENY, nosniff, Referrer-Policy, Permissions-Policy" },
    { label: "Vendor Dependencies", val: "Bootstrap 5.3.3 (100% locally vendored, zero CDN requests)" },
  ];

  const tableBody = createElement(
    "tbody",
    {},
    ...statusRows.map((r) =>
      createElement(
        "tr",
        {},
        createElement("td", { className: "fw-medium text-muted w-50" }, r.label),
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
    statusTable
  );

  // Phase B Roadmap Card
  const roadmapHeader = createElement(
    "div",
    { className: "dv-card-header" },
    createElement("h5", { className: "mb-0 fw-semibold" }, "Phase B Implementation Roadmap"),
    createElement("span", { className: "dv-badge-phase" }, "Phase B1 Complete")
  );

  const roadmapItems = [
    { phase: "B1", title: "Frontend Foundation & Static Serving", desc: "Vanilla JS ES2022 modules, Bootstrap 5.3 vendored, FastAPI static mounting, and strict CSP verification.", status: "Active / Completed" },
    { phase: "B2", title: "Authentication & CSRF Integration", desc: "Interactive login view, POST /api/v1/auth/csrf bootstrap, session error handling, and logout flow.", status: "Planned" },
    { phase: "B3", title: "Document Workspace & Upload", desc: "Interactive document table, drag-and-drop PDF upload modal with 10 MiB client validation, and direct download.", status: "Planned" },
    { phase: "B4", title: "Document Sharing & User Lookup", desc: "Granular access management with debounced GET /api/v1/users/lookup and permission controls.", status: "Planned" },
    { phase: "B5", title: "Self-Service Security Settings", desc: "In-session password change with Argon2id current password verification and other-session revocation.", status: "Planned" },
    { phase: "B6", title: "Role-Gated Administration Panel", desc: "Admin user provisioning, account activation/deactivation, and security event auditing.", status: "Planned" },
  ];

  const roadmapCards = roadmapItems.map((item) =>
    createElement(
      "div",
      { className: "col-md-6 mb-3" },
      createElement(
        "div",
        { className: "p-3 border rounded-3 bg-light h-100 d-flex flex-column" },
        createElement(
          "div",
          { className: "d-flex justify-content-between align-items-center mb-2" },
          createElement("span", { className: "badge text-bg-primary fw-bold" }, item.phase),
          createElement(
            "span",
            { className: `badge ${item.status.startsWith("Active") ? "text-bg-success" : "text-bg-secondary"}` },
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

  const roadmapBody = createElement(
    "div",
    { className: "dv-card-body" },
    createElement(
      "div",
      { className: "alert alert-info py-2 px-3 small mb-3" },
      "Notice: In Phase B1, authentication and document workspaces are intentionally unmounted to establish a verified, test-covered frontend architecture and security baseline first."
    ),
    roadmapGrid
  );

  const roadmapCard = createElement(
    "div",
    { className: "dv-card" },
    roadmapHeader,
    roadmapBody
  );

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
  dashboard: renderDashboardView,
  documents: (c) =>
    renderPlaceholderView(
      c,
      "Document Workspace",
      "Phase B3",
      "Document upload, download, metadata viewing, and deletion will be connected during Phase B3 after user authentication is established."
    ),
  admin: (c) =>
    renderPlaceholderView(
      c,
      "Administration Console",
      "Phase B6",
      "User provisioning, account management, and role-based access control will be connected during Phase B6 for authorized administrators."
    ),
  settings: (c) =>
    renderPlaceholderView(
      c,
      "Security Settings",
      "Phase B5",
      "Self-service password update with automatic multi-session revocation will be connected during Phase B5."
    ),
};

/**
 * Navigate to a named view.
 *
 * @param {string} viewName
 */
export function navigateTo(viewName) {
  const handler = routes[viewName] || routes.dashboard;
  const container = document.getElementById("main-content");
  if (!container) {
    return;
  }

  setActiveNavLink(viewName);
  handler(container);
}
