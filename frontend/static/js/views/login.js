/**
 * Login view component for DocVault.
 * Safe DOM construction with accessible forms, password visibility toggle,
 * client validation, and safe error reporting.
 */

import { createElement, createSvgIcon, clearElement } from "../utils/dom.js";
import { login } from "../auth.js";
import { showAlert } from "../components/alerts.js";

const ICON_EYE =
  "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z";

const ICON_EYE_SLASH =
  "M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.44-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z";

const ICON_LOCK =
  "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z";

/**
 * Render the Login view inside the container.
 *
 * @param {HTMLElement} container
 * @param {(view: string) => void} onNavigate
 */
export function renderLoginView(container, onNavigate) {
  clearElement(container);

  // Error Alert Container
  const errorAlertContainer = createElement("div", {
    id: "login-error-container",
    role: "alert",
    "aria-live": "assertive",
    className: "mb-3",
  });

  function displayError(msg) {
    clearElement(errorAlertContainer);
    if (!msg) return;

    const alertEl = createElement(
      "div",
      { className: "alert alert-danger py-2 px-3 small d-flex align-items-center gap-2 mb-0" },
      createSvgIcon(
        "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z",
        "text-danger flex-shrink-0",
        18
      ),
      createElement("span", { className: "flex-grow-1" }, msg)
    );
    errorAlertContainer.appendChild(alertEl);
  }

  // Username Input
  const usernameLabel = createElement(
    "label",
    { for: "login-username", className: "form-label fw-semibold small text-muted mb-1" },
    "Username"
  );

  const usernameInput = createElement("input", {
    type: "text",
    id: "login-username",
    name: "username",
    className: "form-control",
    placeholder: "Enter your username",
    autocomplete: "username",
    autocapitalize: "none",
    spellcheck: "false",
    required: true,
  });

  // Password Input with Visibility Toggle
  const passwordLabel = createElement(
    "label",
    { for: "login-password", className: "form-label fw-semibold small text-muted mb-1" },
    "Password"
  );

  const passwordInput = createElement("input", {
    type: "password",
    id: "login-password",
    name: "password",
    className: "form-control pe-5",
    placeholder: "Enter your password",
    autocomplete: "current-password",
    required: true,
  });

  let passwordVisible = false;
  const toggleIcon = createSvgIcon(ICON_EYE, "text-muted", 18);

  const togglePasswordBtn = createElement(
    "button",
    {
      type: "button",
      className: "btn btn-link position-absolute end-0 top-50 translate-middle-y pe-3 text-decoration-none border-0 shadow-none",
      "aria-label": "Show password",
      onclick: () => {
        passwordVisible = !passwordVisible;
        passwordInput.type = passwordVisible ? "text" : "password";
        togglePasswordBtn.setAttribute(
          "aria-label",
          passwordVisible ? "Hide password" : "Show password"
        );
        clearElement(togglePasswordBtn);
        togglePasswordBtn.appendChild(
          createSvgIcon(passwordVisible ? ICON_EYE_SLASH : ICON_EYE, "text-muted", 18)
        );
        passwordInput.focus();
      },
    },
    toggleIcon
  );

  const passwordFieldWrapper = createElement(
    "div",
    { className: "position-relative" },
    passwordInput,
    togglePasswordBtn
  );

  // Submit Button
  const submitBtn = createElement(
    "button",
    {
      type: "submit",
      className: "btn btn-primary w-100 py-2 fw-semibold d-flex align-items-center justify-content-center gap-2",
      id: "login-submit-btn",
    },
    "Sign In"
  );

  // Form submission handler
  const form = createElement(
    "form",
    {
      id: "login-form",
      noValidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        displayError("");

        const usernameVal = usernameInput.value.trim();
        const passwordVal = passwordInput.value;

        // Client-side validation
        if (!usernameVal || !passwordVal) {
          displayError("Please enter both username and password.");
          if (!usernameVal) {
            usernameInput.focus();
          } else {
            passwordInput.focus();
          }
          return;
        }

        // Set loading state
        submitBtn.disabled = true;
        usernameInput.disabled = true;
        passwordInput.disabled = true;
        clearElement(submitBtn);

        const spinner = createElement("span", {
          className: "spinner-border spinner-border-sm",
          role: "status",
          "aria-hidden": "true",
        });
        submitBtn.appendChild(spinner);
        submitBtn.appendChild(document.createTextNode(" Signing In..."));

        try {
          const result = await login(usernameVal, passwordVal);

          if (result.success) {
            showAlert(`Welcome, ${result.user.username}! Session established.`, "success", 4000);
            window.location.hash = "dashboard";
            onNavigate("dashboard");
            return;
          }

          // Error case: restore inputs and notify
          displayError(result.error || "Authentication failed. Please verify credentials.");
          passwordInput.value = "";
        } catch {
          displayError("An unexpected system error occurred. Please try again.");
          passwordInput.value = "";
        } finally {
          submitBtn.disabled = false;
          usernameInput.disabled = false;
          passwordInput.disabled = false;
          clearElement(submitBtn);
          submitBtn.appendChild(document.createTextNode("Sign In"));
        }
      },
    },
    createElement("div", { className: "mb-3" }, usernameLabel, usernameInput),
    createElement("div", { className: "mb-4" }, passwordLabel, passwordFieldWrapper),
    submitBtn
  );

  // Security Note Card
  const securityNotice = createElement(
    "div",
    { className: "mt-4 pt-3 border-top text-center" },
    createElement(
      "p",
      { className: "small text-muted mb-0" },
      createSvgIcon(ICON_LOCK, "me-1 text-primary align-text-bottom", 14),
      "Protected by Argon2id, opaque server sessions, and strict SameSite cookies."
    )
  );

  // Card Structure
  const cardHeader = createElement(
    "div",
    { className: "text-center mb-4" },
    createElement(
      "div",
      { className: "d-inline-flex p-3 rounded-circle bg-primary bg-opacity-10 text-primary mb-3" },
      createSvgIcon(ICON_LOCK, "", 32)
    ),
    createElement("h4", { className: "fw-bold mb-1" }, "DocVault Portal"),
    createElement(
      "p",
      { className: "text-muted small mb-0" },
      "Sign in with your authorized credentials"
    )
  );

  const cardBody = createElement(
    "div",
    { className: "dv-card-body p-4 p-md-5" },
    cardHeader,
    errorAlertContainer,
    form,
    securityNotice
  );

  const card = createElement(
    "div",
    { className: "dv-card dv-login-card shadow-sm mx-auto" },
    cardBody
  );

  const wrapper = createElement(
    "div",
    { className: "dv-login-wrapper py-5 px-3" },
    card
  );

  container.appendChild(wrapper);

  // Set initial focus if no other element in the container is already focused
  if (
    !document.activeElement ||
    document.activeElement === document.body ||
    !container.contains(document.activeElement)
  ) {
    usernameInput.focus();
  }
}
