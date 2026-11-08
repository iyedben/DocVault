/**
 * Safe DOM manipulation utilities.
 * Strictly avoids innerHTML with dynamic or untrusted values to prevent DOM XSS.
 * Provides accessible focus trapping and attribute normalization.
 */

/**
 * Create an HTML element with safe attributes and children.
 *
 * @param {string} tag
 * @param {Record<string, string | boolean | Function>} [attributes={}]
 * @param {...(Node | string | number | null | undefined)} children
 * @returns {HTMLElement}
 */
export function createElement(tag, attributes = {}, ...children) {
  const element = document.createElement(tag);

  for (const [key, value] of Object.entries(attributes)) {
    if (value === null || value === undefined || value === false) {
      continue;
    }
    if (key === "className") {
      element.className = String(value);
    } else if (key === "htmlFor") {
      // Normalize htmlFor to standard 'for' attribute for accessible form labels
      element.setAttribute("for", String(value));
    } else if (key.startsWith("on") && typeof value === "function") {
      const eventName = key.slice(2).toLowerCase();
      element.addEventListener(eventName, value);
    } else if (key === "dataset" && typeof value === "object") {
      for (const [dataKey, dataValue] of Object.entries(value)) {
        element.dataset[dataKey] = String(dataValue);
      }
    } else if (key === "href" || key === "src") {
      // Disallow dangerous URL schemes (javascript:, data:, vbscript:)
      const valStr = String(value).trim();
      if (!/^(javascript|data|vbscript):/i.test(valStr)) {
        element.setAttribute(key, valStr);
      }
    } else if (value === true) {
      element.setAttribute(key, "");
    } else {
      element.setAttribute(key, String(value));
    }
  }

  for (const child of children) {
    if (child === null || child === undefined) {
      continue;
    }
    if (child instanceof Node) {
      element.appendChild(child);
    } else {
      element.appendChild(document.createTextNode(String(child)));
    }
  }

  return element;
}

/**
 * Remove all child nodes from an element.
 *
 * @param {HTMLElement} element
 */
export function clearElement(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

/**
 * Create an accessible SVG element.
 *
 * @param {string} pathD
 * @param {string} [className=""]
 * @param {number} [size=20]
 * @returns {SVGElement}
 */
export function createSvgIcon(pathD, className = "", size = 20) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("aria-hidden", "true");
  if (className) {
    svg.setAttribute("class", className);
  }

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", pathD);
  path.setAttribute("fill", "currentColor");
  svg.appendChild(path);

  return svg;
}

/**
 * Trap keyboard focus within a container element for accessible modal dialogs.
 * Prevents focus from escaping behind the modal overlay into inactive page elements.
 *
 * @param {HTMLElement} container
 * @returns {() => void} Unbind cleanup function
 */
export function trapFocus(container) {
  const focusableSelector =
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function handleKeyDown(e) {
    if (e.key !== "Tab") return;

    const focusables = Array.from(container.querySelectorAll(focusableSelector)).filter(
      (el) => el.offsetParent !== null || el === document.activeElement
    );
    if (focusables.length === 0) {
      e.preventDefault();
      return;
    }

    const first = focusables[0];
    const last = focusables[focusables.length - 1];

    if (e.shiftKey) {
      if (document.activeElement === first || !container.contains(document.activeElement)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last || !container.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  container.addEventListener("keydown", handleKeyDown);
  return () => container.removeEventListener("keydown", handleKeyDown);
}
