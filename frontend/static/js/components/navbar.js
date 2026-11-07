/**
 * Navigation bar and header component.
 */

import { createElement, createSvgIcon } from "../utils/dom.js";

// Shield SVG path for the DocVault brand icon
const SHIELD_PATH =
  "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 16l-4-4 1.41-1.41L11 14.17l6.59-6.59L19 9l-8 8z";

/**
 * Initialize and mount the top navigation bar.
 *
 * @param {HTMLElement} container
 * @param {(viewName: string) => void} onNavigate
 */
export function renderNavbar(container, onNavigate) {
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
      href: "#",
      onclick: (e) => {
        e.preventDefault();
        onNavigate("dashboard");
      },
    },
    brandIcon,
    brandText
  );

  const phaseBadge = createElement(
    "span",
    { className: "dv-badge-phase ms-2" },
    "Phase B1 Foundation"
  );

  const navLinks = [
    { id: "dashboard", label: "Dashboard" },
    { id: "documents", label: "Documents" },
    { id: "admin", label: "Administration" },
    { id: "settings", label: "Settings" },
  ];

  const navItems = navLinks.map((item) =>
    createElement(
      "li",
      { className: "nav-item" },
      createElement(
        "a",
        {
          id: `nav-${item.id}`,
          className: `dv-nav-link ${item.id === "dashboard" ? "active" : ""}`,
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

  const apiStatus = createElement(
    "div",
    { className: "d-flex align-items-center gap-2 text-white-50 small" },
    createElement("span", {
      className: "badge rounded-pill text-bg-success",
      title: "Backend connected",
    }, "API Online"),
    createElement("span", { className: "d-none d-md-inline" }, "Academic DevSecOps")
  );

  const navCollapse = createElement(
    "div",
    { className: "collapse navbar-collapse", id: "mainNavbarNav" },
    navList,
    apiStatus
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
    createElement(
      "div",
      { className: "d-flex align-items-center" },
      brandLink,
      phaseBadge
    ),
    toggleBtn,
    navCollapse
  );

  container.appendChild(navContainer);
}

/**
 * Update the active navigation link visually.
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
