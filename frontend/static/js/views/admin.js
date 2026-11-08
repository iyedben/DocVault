/**
 * Administration Console view for DocVault.
 * Safe DOM construction for user roster listing, searching, filtering,
 * user provisioning, status toggles (activate/deactivate), role assignment,
 * and security audit architecture review.
 */

import { createElement, createSvgIcon, clearElement, trapFocus } from "../utils/dom.js";
import { authState } from "../auth-state.js";
import { showAlert } from "../components/alerts.js";
import { showLoading } from "../components/loading.js";
import {
  listAdminUsers,
  provisionAdminUser,
  setUserActiveStatus,
  setUserRole,
  formatDateTime,
  validateUsernamePolicy,
  validatePasswordPolicy,
} from "../admin.js";

// SVG Icon Path Constants
const ICON_REFRESH =
  "M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z";

const ICON_USER_PLUS =
  "M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm-9-2V7H4v3H1v2h3v3h2v-3h3v-2H6zm9 4c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z";

const ICON_USER =
  "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z";

const ICON_SHIELD =
  "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 16l-4-4 1.41-1.41L11 14.17l6.59-6.59L19 9l-8 8z";

const ICON_SHIELD_ALERT =
  "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm1 14h-2v-2h2v2zm0-4h-2V7h2v4z";

const ICON_SEARCH =
  "M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z";

const ICON_EYE =
  "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z";

const ICON_EYE_SLASH =
  "M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.44-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z";

const ICON_INFO =
  "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z";

/**
 * Render the Role-Gated Administration Console view.
 *
 * @param {HTMLElement} container
 * @param {(viewName: string) => void} onNavigate
 */
export async function renderAdminView(container, onNavigate) {
  // 1. Strict client-side role guard
  if (!authState.isAdmin()) {
    showAlert("Administrator access required for Administration Console.", "warning", 5000);
    onNavigate("dashboard");
    return;
  }

  clearElement(container);

  let allUsers = [];
  let filterStatus = "all"; // "all" | "active" | "deactivated"
  let filterRole = "all"; // "all" | "administrator" | "user"
  let searchQuery = "";

  // 2. View Header
  const header = createElement(
    "div",
    { className: "d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3 mb-4" },
    createElement(
      "div",
      {},
      createElement(
        "div",
        { className: "d-flex align-items-center gap-2 mb-1" },
        createElement("h3", { className: "fw-bold mb-0" }, "Administration Console"),
        createElement("span", { className: "badge text-bg-warning text-uppercase px-2 py-1 small fw-semibold" }, "Admin Only")
      ),
      createElement(
        "p",
        { className: "text-muted small mb-0" },
        "Manage DocVault user accounts, lifecycle status, system roles, and platform permissions."
      )
    ),
    createElement(
      "div",
      { className: "d-flex align-items-center gap-2" },
      createElement(
        "button",
        {
          type: "button",
          className: "btn btn-outline-secondary btn-sm d-flex align-items-center gap-1",
          id: "btn-refresh-admin-users",
          title: "Refresh user roster",
          onclick: () => loadUserRoster(),
        },
        createSvgIcon(ICON_REFRESH, "", 16),
        createElement("span", {}, "Refresh")
      ),
      createElement(
        "button",
        {
          type: "button",
          className: "btn btn-primary btn-sm d-flex align-items-center gap-1",
          id: "btn-open-provision-modal",
          title: "Provision a new user account",
          onclick: () => openProvisionModal(),
        },
        createSvgIcon(ICON_USER_PLUS, "", 16),
        createElement("span", { className: "fw-medium" }, "Provision User")
      )
    )
  );

  // 3. Platform Stats Cards Container
  const statsContainer = createElement("div", { className: "row g-3 mb-4", id: "admin-stats-row" });

  function renderStatsCards(users) {
    clearElement(statsContainer);

    const totalCount = users.length;
    const activeCount = users.filter((u) => u.is_active).length;
    const adminCount = users.filter((u) => u.role === "administrator").length;
    const userCount = users.filter((u) => u.role === "user").length;

    const statDefinitions = [
      { label: "Total Accounts", value: totalCount, badgeClass: "text-bg-light border", borderClass: "border-primary border-opacity-25" },
      { label: "Active Accounts", value: activeCount, badgeClass: "text-bg-success", borderClass: "border-success border-opacity-25" },
      { label: "Administrators", value: adminCount, badgeClass: "text-bg-warning", borderClass: "border-warning border-opacity-25" },
      { label: "Standard Users", value: userCount, badgeClass: "text-bg-info text-white", borderClass: "border-info border-opacity-25" },
    ];

    for (const stat of statDefinitions) {
      const col = createElement(
        "div",
        { className: "col-6 col-md-3" },
        createElement(
          "div",
          { className: `dv-card p-3 h-100 ${stat.borderClass}` },
          createElement("span", { className: "text-muted small fw-medium text-uppercase d-block mb-1" }, stat.label),
          createElement(
            "div",
            { className: "d-flex align-items-center justify-content-between" },
            createElement("span", { className: "h3 fw-bold mb-0" }, String(stat.value)),
            createElement("span", { className: `badge ${stat.badgeClass} px-2 py-1` }, `${Math.round((stat.value / (totalCount || 1)) * 100)}%`)
          )
        )
      );
      statsContainer.appendChild(col);
    }
  }

  // 4. Search and Filter Toolbar
  const searchInput = createElement("input", {
    type: "search",
    className: "form-control form-control-sm ps-5",
    placeholder: "Search by username...",
    id: "admin-user-search",
    "aria-label": "Search users by username",
    oninput: (e) => {
      searchQuery = e.target.value.trim().toLowerCase();
      applyFiltersAndRender();
    },
  });

  const searchBox = createElement(
    "div",
    { className: "position-relative flex-grow-1 dv-search-wrapper" },
    createElement(
      "span",
      { className: "position-absolute top-50 start-0 translate-middle-y ps-3 text-muted pointer-events-none" },
      createSvgIcon(ICON_SEARCH, "", 16)
    ),
    searchInput
  );

  // Status Filter Buttons
  const statusFilterAll = createFilterButton("All Status", "all", filterStatus, (val) => {
    filterStatus = val;
    updateFilterButtonStates();
    applyFiltersAndRender();
  });

  const statusFilterActive = createFilterButton("Active", "active", filterStatus, (val) => {
    filterStatus = val;
    updateFilterButtonStates();
    applyFiltersAndRender();
  });

  const statusFilterDeactivated = createFilterButton("Deactivated", "deactivated", filterStatus, (val) => {
    filterStatus = val;
    updateFilterButtonStates();
    applyFiltersAndRender();
  });

  const statusButtonGroup = createElement(
    "div",
    { className: "btn-group btn-group-sm", role: "group", "aria-label": "Filter by account status" },
    statusFilterAll,
    statusFilterActive,
    statusFilterDeactivated
  );

  // Role Filter Buttons
  const roleFilterAll = createFilterButton("All Roles", "all", filterRole, (val) => {
    filterRole = val;
    updateFilterButtonStates();
    applyFiltersAndRender();
  });

  const roleFilterAdmin = createFilterButton("Admins", "administrator", filterRole, (val) => {
    filterRole = val;
    updateFilterButtonStates();
    applyFiltersAndRender();
  });

  const roleFilterUser = createFilterButton("Users", "user", filterRole, (val) => {
    filterRole = val;
    updateFilterButtonStates();
    applyFiltersAndRender();
  });

  const roleButtonGroup = createElement(
    "div",
    { className: "btn-group btn-group-sm", role: "group", "aria-label": "Filter by system role" },
    roleFilterAll,
    roleFilterAdmin,
    roleFilterUser
  );

  function createFilterButton(label, value, currentVal, onClick) {
    return createElement(
      "button",
      {
        type: "button",
        className: `btn ${value === currentVal ? "btn-primary" : "btn-outline-secondary"}`,
        dataset: { filterValue: value },
        onclick: () => onClick(value),
      },
      label
    );
  }

  function updateFilterButtonStates() {
    for (const btn of statusButtonGroup.querySelectorAll("button")) {
      const val = btn.dataset.filterValue;
      btn.className = `btn ${val === filterStatus ? "btn-primary" : "btn-outline-secondary"}`;
    }
    for (const btn of roleButtonGroup.querySelectorAll("button")) {
      const val = btn.dataset.filterValue;
      btn.className = `btn ${val === filterRole ? "btn-primary" : "btn-outline-secondary"}`;
    }
  }

  const toolbar = createElement(
    "div",
    { className: "d-flex flex-column flex-md-row justify-content-between align-items-stretch align-items-md-center gap-3 p-3 bg-light border-bottom rounded-top" },
    searchBox,
    createElement(
      "div",
      { className: "d-flex flex-wrap align-items-center gap-2" },
      statusButtonGroup,
      roleButtonGroup
    )
  );

  // 5. User Roster Table Container
  const tableContainer = createElement("div", { className: "table-responsive" });
  const rosterCard = createElement(
    "div",
    { className: "dv-card mb-4" },
    toolbar,
    tableContainer
  );

  // 6. Security Audit Architecture Info Panel
  const auditPanel = createElement(
    "div",
    { className: "dv-card bg-light border p-4 mb-4" },
    createElement(
      "div",
      { className: "d-flex align-items-start gap-3" },
      createElement(
        "div",
        { className: "p-2 rounded bg-primary bg-opacity-10 text-primary flex-shrink-0" },
        createSvgIcon(ICON_SHIELD, "", 24)
      ),
      createElement(
        "div",
        {},
        createElement("h5", { className: "fw-bold mb-1" }, "Security Audit Logging Architecture"),
        createElement(
          "p",
          { className: "text-muted small mb-2" },
          "DocVault enforces real-time structured security auditing across all authentication, document, and administrative operations."
        ),
        createElement(
          "ul",
          { className: "text-muted small mb-2 ps-3" },
          createElement("li", { className: "mb-1" }, "Structured JSON events with strict allow-listed fields (timestamp, event, outcome, actor_id, target_id, source_ip, reason)."),
          createElement("li", { className: "mb-1" }, "Streamed directly to container standard output (docvault.security) in adherence to twelve-factor and DevSecOps principles."),
          createElement("li", { className: "mb-1" }, "Immutable architecture: audit records are collected by container log drivers and external SIEM collectors rather than queried via database endpoints to prevent unauthorized tampering or deletion."),
          createElement("li", {}, "Monitored administrative events: user creation, account activation, account deactivation, and role promotions/demotions.")
        ),
        createElement(
          "div",
          { className: "d-flex align-items-center gap-2" },
          createElement("span", { className: "badge text-bg-success px-2 py-1" }, "Audit Stream Active"),
          createElement("span", { className: "text-muted small" }, "Stream destination: container stdout (JSON)")
        )
      )
    )
  );

  // Append sections to container
  container.appendChild(header);
  container.appendChild(statsContainer);
  container.appendChild(rosterCard);
  container.appendChild(auditPanel);

  // 7. Load User Roster Data
  async function loadUserRoster() {
    clearElement(tableContainer);
    showLoading(tableContainer, "Loading DocVault user roster...");

    const res = await listAdminUsers();
    if (!res.success) {
      clearElement(tableContainer);
      const errorCard = createElement(
        "div",
        { className: "p-4 text-center text-muted" },
        createSvgIcon(ICON_SHIELD_ALERT, "text-danger mb-2", 32),
        createElement("h6", { className: "fw-bold text-dark mb-1" }, "Failed to Load Users"),
        createElement("p", { className: "small mb-3" }, res.error || "Could not retrieve user roster."),
        createElement(
          "button",
          {
            type: "button",
            className: "btn btn-outline-primary btn-sm",
            onclick: () => loadUserRoster(),
          },
          "Retry"
        )
      );
      tableContainer.appendChild(errorCard);
      return;
    }

    allUsers = res.users || [];
    renderStatsCards(allUsers);
    applyFiltersAndRender();
  }

  // 8. Filter and Render User Table
  function applyFiltersAndRender() {
    let filtered = [...allUsers];

    // Status filter
    if (filterStatus === "active") {
      filtered = filtered.filter((u) => u.is_active);
    } else if (filterStatus === "deactivated") {
      filtered = filtered.filter((u) => !u.is_active);
    }

    // Role filter
    if (filterRole === "administrator") {
      filtered = filtered.filter((u) => u.role === "administrator");
    } else if (filterRole === "user") {
      filtered = filtered.filter((u) => u.role === "user");
    }

    // Search query
    if (searchQuery) {
      filtered = filtered.filter((u) => u.username.toLowerCase().includes(searchQuery));
    }

    clearElement(tableContainer);

    if (filtered.length === 0) {
      const emptyState = createElement(
        "div",
        { className: "text-center py-5 px-3" },
        createSvgIcon(ICON_USER, "text-muted mb-2", 36),
        createElement("h6", { className: "fw-bold text-dark mb-1" }, "No Users Found"),
        createElement(
          "p",
          { className: "text-muted small mb-0" },
          allUsers.length === 0
            ? "No user accounts exist in the system."
            : "No users match your selected search or filter criteria."
        )
      );
      tableContainer.appendChild(emptyState);
      return;
    }

    const table = createElement(
      "table",
      { className: "table table-hover dv-table dv-admin-table align-middle mb-0" },
      createElement(
        "thead",
        { className: "table-light" },
        createElement(
          "tr",
          {},
          createElement("th", { scope: "col", className: "ps-4 py-3" }, "User"),
          createElement("th", { scope: "col", className: "py-3" }, "Role"),
          createElement("th", { scope: "col", className: "py-3" }, "Status"),
          createElement("th", { scope: "col", className: "py-3" }, "Registered"),
          createElement("th", { scope: "col", className: "text-end pe-4 py-3" }, "Actions")
        )
      )
    );

    const tbody = createElement("tbody", {});
    const currentUser = authState.getUser();

    for (const u of filtered) {
      const isSelf = currentUser && currentUser.id === u.id;

      // User avatar initial
      const initial = (u.username[0] || "U").toUpperCase();
      const avatar = createElement(
        "div",
        { className: "dv-user-badge-icon" },
        initial
      );

      const usernameSpan = createElement(
        "span",
        { className: "fw-semibold text-dark" },
        u.username
      );

      const userCellContent = [avatar, usernameSpan];
      if (isSelf) {
        userCellContent.push(
          createElement("span", { className: "badge bg-secondary-subtle text-secondary border small px-2 py-0" }, "You")
        );
      }

      const userCell = createElement(
        "td",
        { className: "ps-4 py-3" },
        createElement(
          "div",
          { className: "d-flex align-items-center gap-2" },
          ...userCellContent
        )
      );

      // Role badge
      const roleCell = createElement(
        "td",
        { className: "py-3" },
        createElement(
          "span",
          {
            className: `badge ${
              u.role === "administrator"
                ? "text-bg-warning fw-semibold"
                : "text-bg-primary fw-medium"
            } text-uppercase px-2 py-1 small`,
          },
          u.role
        )
      );

      // Status badge
      const statusCell = createElement(
        "td",
        { className: "py-3" },
        createElement(
          "span",
          {
            className: `badge ${
              u.is_active ? "text-bg-success" : "text-bg-secondary"
            } px-2 py-1 small fw-medium`,
          },
          u.is_active ? "Active" : "Deactivated"
        )
      );

      // Registration date
      const dateCell = createElement(
        "td",
        { className: "py-3 text-muted small" },
        formatDateTime(u.created_at)
      );

      // Action buttons
      const actionGroup = createElement("div", { className: "d-flex justify-content-end align-items-center gap-2 pe-3" });

      // 1. Status Toggle Button (Activate / Deactivate)
      const toggleStatusBtn = createElement(
        "button",
        {
          type: "button",
          className: `btn btn-sm ${u.is_active ? "btn-outline-danger" : "btn-outline-success"}`,
          title: u.is_active ? "Deactivate this account" : "Reactivate this account",
          onclick: () => confirmStatusChange(u),
        },
        u.is_active ? "Deactivate" : "Activate"
      );
      actionGroup.appendChild(toggleStatusBtn);

      // 2. Role Toggle Button (Promote to Admin / Demote to User)
      const nextRole = u.role === "administrator" ? "user" : "administrator";
      const toggleRoleBtn = createElement(
        "button",
        {
          type: "button",
          className: `btn btn-sm ${u.role === "administrator" ? "btn-outline-secondary" : "btn-outline-primary"}`,
          title: u.role === "administrator" ? "Demote to standard user" : "Promote to administrator",
          onclick: () => confirmRoleChange(u, nextRole),
        },
        u.role === "administrator" ? "Demote" : "Promote"
      );
      actionGroup.appendChild(toggleRoleBtn);

      const actionCell = createElement(
        "td",
        { className: "text-end py-3" },
        actionGroup
      );

      const row = createElement("tr", {}, userCell, roleCell, statusCell, dateCell, actionCell);
      tbody.appendChild(row);
    }

    table.appendChild(tbody);
    tableContainer.appendChild(table);
  }

  // ---------------------------------------------------------------------------
  // Modal: Provision New User
  // ---------------------------------------------------------------------------
  function openProvisionModal() {
    const previouslyFocused = document.activeElement;
    const modalBackdrop = createElement("div", {
      className: "dv-modal-backdrop",
      onclick: (e) => {
        if (e.target === modalBackdrop) closeModal();
      },
    });

    const modalTitle = createElement(
      "h5",
      { className: "fw-bold mb-0", id: "provision-modal-title" },
      "Provision User Account"
    );

    const closeBtn = createElement("button", {
      type: "button",
      className: "btn-close",
      "aria-label": "Close",
      onclick: closeModal,
    });

    const modalHeader = createElement(
      "div",
      { className: "modal-header d-flex justify-content-between align-items-center p-3 border-bottom" },
      modalTitle,
      closeBtn
    );

    // Form inputs
    const usernameInput = createElement("input", {
      type: "text",
      id: "provision-username",
      className: "form-control",
      placeholder: "e.g. jdoe",
      autocomplete: "off",
      required: true,
      oninput: () => updateFormValidation(),
    });

    const usernameHelp = createElement(
      "div",
      { className: "form-text small text-muted" },
      "3–32 lowercase letters, digits, dots, underscores, or hyphens."
    );

    const roleSelect = createElement(
      "select",
      { id: "provision-role", className: "form-select" },
      createElement("option", { value: "user" }, "Standard User"),
      createElement("option", { value: "administrator" }, "Administrator")
    );

    const passwordInput = createElement("input", {
      type: "password",
      id: "provision-password",
      className: "form-control pe-5",
      placeholder: "Enter temporary password",
      autocomplete: "new-password",
      required: true,
      oninput: () => updateFormValidation(),
    });

    let isPasswordVisible = false;
    const togglePasswordBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-link position-absolute end-0 top-50 translate-middle-y pe-3 text-decoration-none border-0 shadow-none text-muted",
        "aria-label": "Show password",
        onclick: () => {
          isPasswordVisible = !isPasswordVisible;
          passwordInput.type = isPasswordVisible ? "text" : "password";
          togglePasswordBtn.setAttribute("aria-label", isPasswordVisible ? "Hide password" : "Show password");
          clearElement(togglePasswordBtn);
          togglePasswordBtn.appendChild(createSvgIcon(isPasswordVisible ? ICON_EYE_SLASH : ICON_EYE, "", 18));
        },
      },
      createSvgIcon(ICON_EYE, "", 18)
    );

    const passwordWrapper = createElement(
      "div",
      { className: "position-relative" },
      passwordInput,
      togglePasswordBtn
    );

    // Policy checklist indicators
    const checkLength = createElement("li", { className: "text-muted" }, "12 to 128 characters");
    const checkCategories = createElement("li", { className: "text-muted" }, "At least 3 categories (lowercase, uppercase, numbers, symbols)");

    const policyChecklist = createElement(
      "ul",
      { className: "small text-muted list-unstyled mb-0 mt-1 ps-1" },
      checkLength,
      checkCategories
    );

    function updateFormValidation() {
      const pass = passwordInput.value;
      const lenOk = pass.length >= 12 && pass.length <= 128;
      const cats = [
        /[a-z]/.test(pass),
        /[A-Z]/.test(pass),
        /[0-9]/.test(pass),
        /[^a-zA-Z0-9]/.test(pass),
      ].filter(Boolean).length;
      const catOk = cats >= 3;

      checkLength.className = lenOk ? "text-success fw-medium" : "text-muted";
      checkCategories.className = catOk ? "text-success fw-medium" : "text-muted";

      const userErr = validateUsernamePolicy(usernameInput.value);
      const passErr = validatePasswordPolicy(pass);
      submitBtn.disabled = Boolean(userErr || passErr);
    }

    // Modal Error Alert Area
    const modalAlertArea = createElement("div", { className: "mt-3 d-none" });

    function setModalError(msg) {
      clearElement(modalAlertArea);
      if (!msg) {
        modalAlertArea.classList.add("d-none");
        return;
      }
      modalAlertArea.classList.remove("d-none");
      modalAlertArea.appendChild(
        createElement(
          "div",
          { className: "alert alert-danger py-2 px-3 small mb-0", role: "alert" },
          msg
        )
      );
    }

    const cancelBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-secondary btn-sm",
        onclick: closeModal,
      },
      "Cancel"
    );

    const submitBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-primary btn-sm d-flex align-items-center gap-1",
        id: "btn-submit-provision-user",
        disabled: true,
        onclick: async () => {
          const username = usernameInput.value.trim().toLowerCase();
          const password = passwordInput.value;
          const role = roleSelect.value;

          const uErr = validateUsernamePolicy(username);
          if (uErr) {
            setModalError(uErr);
            return;
          }

          const pErr = validatePasswordPolicy(password);
          if (pErr) {
            setModalError(pErr);
            return;
          }

          submitBtn.disabled = true;
          cancelBtn.disabled = true;
          closeBtn.disabled = true;
          submitBtn.textContent = "Provisioning...";
          setModalError("");

          const res = await provisionAdminUser({ username, password, role });
          if (res.success) {
            closeModal();
            showAlert(`User "${username}" provisioned successfully with role "${role}".`, "success", 4000);
            await loadUserRoster();
          } else {
            setModalError(res.error || "Failed to provision user.");
            submitBtn.disabled = false;
            cancelBtn.disabled = false;
            closeBtn.disabled = false;
            submitBtn.textContent = "Provision User";
          }
        },
      },
      "Provision User"
    );

    const modalBody = createElement(
      "div",
      { className: "modal-body p-4" },
      createElement(
        "div",
        { className: "mb-3" },
        createElement("label", { className: "form-label fw-semibold small mb-1", htmlFor: "provision-username" }, "Username"),
        usernameInput,
        usernameHelp
      ),
      createElement(
        "div",
        { className: "mb-3" },
        createElement("label", { className: "form-label fw-semibold small mb-1", htmlFor: "provision-role" }, "System Role"),
        roleSelect
      ),
      createElement(
        "div",
        { className: "mb-3" },
        createElement("label", { className: "form-label fw-semibold small mb-1", htmlFor: "provision-password" }, "Initial Password"),
        passwordWrapper,
        policyChecklist
      ),
      modalAlertArea
    );

    const modalFooter = createElement(
      "div",
      { className: "modal-footer p-3 border-top d-flex justify-content-end gap-2" },
      cancelBtn,
      submitBtn
    );

    const modalDialog = createElement(
      "div",
      {
        className: "dv-modal-dialog",
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "provision-modal-title",
      },
      modalHeader,
      modalBody,
      modalFooter
    );

    modalBackdrop.appendChild(modalDialog);
    document.body.appendChild(modalBackdrop);

    const releaseFocusTrap = trapFocus(modalDialog);

    function onKeyDown(e) {
      if (e.key === "Escape") closeModal();
    }
    document.addEventListener("keydown", onKeyDown);

    function closeModal() {
      releaseFocusTrap();
      document.removeEventListener("keydown", onKeyDown);
      if (modalBackdrop.parentNode) {
        modalBackdrop.parentNode.removeChild(modalBackdrop);
      }
      if (previouslyFocused && typeof previouslyFocused.focus === "function") {
        previouslyFocused.focus();
      }
    }

    usernameInput.focus();
  }

  // ---------------------------------------------------------------------------
  // Modal: Confirm Sensitive Action (Status Change or Role Change)
  // ---------------------------------------------------------------------------
  function confirmStatusChange(targetUser) {
    const isDeactivating = targetUser.is_active;
    const currentUser = authState.getUser();
    const isSelf = currentUser && currentUser.id === targetUser.id;

    const actionTitle = isDeactivating ? "Deactivate Account" : "Reactivate Account";
    const btnVariant = isDeactivating ? "btn-danger" : "btn-success";
    const btnLabel = isDeactivating ? "Deactivate" : "Reactivate";

    let warningText = `Are you sure you want to ${isDeactivating ? "deactivate" : "reactivate"} account "${targetUser.username}"?`;
    if (isDeactivating) {
      if (isSelf) {
        warningText = `CAUTION: You are about to deactivate your own account (${targetUser.username}). This will immediately terminate your active session and sign you out of DocVault. Proceed only if intended.`;
      } else {
        warningText += " All active sessions for this account will be immediately revoked.";
      }
    }

    openConfirmationModal({
      title: actionTitle,
      bodyText: warningText,
      confirmBtnLabel: btnLabel,
      confirmBtnVariant: btnVariant,
      onConfirm: async () => {
        const res = await setUserActiveStatus(targetUser.id, !isDeactivating);
        if (res.success) {
          if (isSelf && isDeactivating) {
            // Self-deactivation clears server cookie; transition authState to anonymous and redirect
            authState.setAnonymous();
            showAlert("Your account has been deactivated. You have been signed out.", "info", 5000);
            onNavigate("login");
            return;
          }
          showAlert(`Account "${targetUser.username}" has been ${isDeactivating ? "deactivated" : "reactivated"}.`, "success", 4000);
          await loadUserRoster();
        } else {
          showAlert(res.error || "Failed to update account status.", "danger", 5000);
        }
      },
    });
  }

  function confirmRoleChange(targetUser, newRole) {
    const currentUser = authState.getUser();
    const isSelf = currentUser && currentUser.id === targetUser.id;
    const isPromoting = newRole === "administrator";

    const actionTitle = isPromoting ? "Promote to Administrator" : "Demote to Standard User";
    const btnVariant = isPromoting ? "btn-primary" : "btn-warning";
    const btnLabel = isPromoting ? "Promote" : "Demote";

    let warningText = `Are you sure you want to change "${targetUser.username}"'s role to "${newRole}"?`;
    if (!isPromoting && isSelf) {
      warningText = `CAUTION: You are about to remove administrator privileges from your own account (${targetUser.username}). You will lose access to the Administration Console upon demotion.`;
    }

    openConfirmationModal({
      title: actionTitle,
      bodyText: warningText,
      confirmBtnLabel: btnLabel,
      confirmBtnVariant: btnVariant,
      onConfirm: async () => {
        const res = await setUserRole(targetUser.id, newRole);
        if (res.success) {
          if (isSelf && !isPromoting) {
            // Self-demotion: update current authState and navigate to dashboard
            const updatedUser = { ...currentUser, role: "user" };
            authState.setAuthenticated(updatedUser);
            showAlert("You have demoted your account to Standard User. Administrator console is no longer accessible.", "warning", 5000);
            onNavigate("dashboard");
            return;
          }
          showAlert(`Role for "${targetUser.username}" changed to "${newRole}".`, "success", 4000);
          await loadUserRoster();
        } else {
          showAlert(res.error || "Failed to change user role.", "danger", 5000);
        }
      },
    });
  }

  function openConfirmationModal({ title, bodyText, confirmBtnLabel, confirmBtnVariant, onConfirm }) {
    const previouslyFocused = document.activeElement;
    const modalBackdrop = createElement("div", {
      className: "dv-modal-backdrop",
      onclick: (e) => {
        if (e.target === modalBackdrop) closeModal();
      },
    });

    const modalTitle = createElement("h5", { className: "fw-bold mb-0", id: "confirm-modal-title" }, title);
    const closeBtn = createElement("button", {
      type: "button",
      className: "btn-close",
      "aria-label": "Close",
      onclick: closeModal,
    });

    const modalHeader = createElement(
      "div",
      { className: "modal-header d-flex justify-content-between align-items-center p-3 border-bottom" },
      modalTitle,
      closeBtn
    );

    const messagePara = createElement("p", { className: "mb-0 text-dark" }, bodyText);

    const cancelBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-secondary btn-sm",
        onclick: closeModal,
      },
      "Cancel"
    );

    const confirmBtn = createElement(
      "button",
      {
        type: "button",
        className: `btn ${confirmBtnVariant} btn-sm`,
        onclick: async () => {
          confirmBtn.disabled = true;
          cancelBtn.disabled = true;
          closeBtn.disabled = true;
          confirmBtn.textContent = "Processing...";
          try {
            await onConfirm();
          } finally {
            closeModal();
          }
        },
      },
      confirmBtnLabel
    );

    const modalFooter = createElement(
      "div",
      { className: "modal-footer p-3 border-top d-flex justify-content-end gap-2" },
      cancelBtn,
      confirmBtn
    );

    const modalDialog = createElement(
      "div",
      {
        className: "dv-modal-dialog",
        role: "dialog",
        "aria-modal": "true",
        "aria-labelledby": "confirm-modal-title",
      },
      modalHeader,
      createElement("div", { className: "modal-body p-4" }, messagePara),
      modalFooter
    );

    modalBackdrop.appendChild(modalDialog);
    document.body.appendChild(modalBackdrop);

    const releaseFocusTrap = trapFocus(modalDialog);

    function onKeyDown(e) {
      if (e.key === "Escape") closeModal();
    }
    document.addEventListener("keydown", onKeyDown);

    function closeModal() {
      releaseFocusTrap();
      document.removeEventListener("keydown", onKeyDown);
      if (modalBackdrop.parentNode) {
        modalBackdrop.parentNode.removeChild(modalBackdrop);
      }
      if (previouslyFocused && typeof previouslyFocused.focus === "function") {
        previouslyFocused.focus();
      }
    }

    cancelBtn.focus();
  }

  // Initial load
  await loadUserRoster();
}
