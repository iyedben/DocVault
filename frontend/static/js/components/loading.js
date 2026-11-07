/**
 * Loading state indicator component.
 */

import { createElement, clearElement } from "../utils/dom.js";

/**
 * Display a loading spinner in the target container.
 *
 * @param {HTMLElement} container
 * @param {string} [message="Loading..."]
 * @returns {HTMLElement} The created loading element.
 */
export function showLoading(container, message = "Loading...") {
  clearElement(container);

  const spinner = createElement("div", {
    className: "dv-spinner",
    role: "status",
    "aria-hidden": "true",
  });

  const label = createElement(
    "span",
    { className: "text-muted small fw-medium" },
    message
  );

  const wrapper = createElement(
    "div",
    {
      className: "dv-loading-overlay",
      "aria-live": "polite",
    },
    spinner,
    label
  );

  container.appendChild(wrapper);
  return wrapper;
}
