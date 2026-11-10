/**
 * Global alert and notification banner component.
 */

import { createElement, clearElement } from "../utils/dom.js";

/**
 * Display an alert banner in the global notification area.
 *
 * @param {string} message
 * @param {"info" | "success" | "warning" | "danger"} [type="info"]
 * @param {number} [timeoutMs=6000]
 */
export function showAlert(message, type = "info", timeoutMs = 6000) {
  const container = document.getElementById("notification-area");
  if (!container) {
    return;
  }

  const alertClassMap = {
    info: "alert-primary",
    success: "alert-success",
    warning: "alert-warning",
    danger: "alert-danger",
  };

  const bsClass = alertClassMap[type] || "alert-info";

  const closeBtn = createElement("button", {
    type: "button",
    className: "btn-close",
    "aria-label": "Close",
    onclick: () => alertEl.remove(),
  });

  const messageSpan = createElement("span", { className: "flex-grow-1" }, message);

  const alertEl = createElement(
    "div",
    {
      className: `alert ${bsClass} alert-dismissible fade show dv-alert shadow-sm`,
      role: "alert",
    },
    messageSpan,
    closeBtn
  );

  container.appendChild(alertEl);

  if (timeoutMs > 0) {
    setTimeout(() => {
      if (alertEl.parentNode) {
        alertEl.classList.remove("show");
        setTimeout(() => alertEl.remove(), 150);
      }
    }, timeoutMs);
  }
}

/**
 * Remove all active alerts.
 */
export function clearAlerts() {
  const container = document.getElementById("notification-area");
  if (container) {
    clearElement(container);
  }
}
