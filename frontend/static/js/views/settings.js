/**
 * Account & Security Settings view for DocVault.
 * Safe DOM construction for profile summary, password change form,
 * client validation, password visibility toggles, and multi-session feedback.
 */

import { createElement, createSvgIcon, clearElement } from "../utils/dom.js";
import { authState } from "../auth-state.js";
import { changePassword } from "../auth.js";
import { showAlert } from "../components/alerts.js";

// SVG Icons
const ICON_SHIELD_LOCK =
  "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 6c1.66 0 3 1.34 3 3v2h1c.55 0 1 .45 1 1v4c0 .55-.45 1-1 1H8c-.55 0-1-.45-1-1v-4c0-.55.45-1 1-1h1v-2c0-1.66 1.34-3 3-3zm0 2c-.55 0-1 .45-1 1v2h2v-2c0-.55-.45-1-1-1z";

const ICON_USER =
  "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z";

const ICON_KEY =
  "M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z";

const ICON_EYE =
  "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z";

const ICON_EYE_SLASH =
  "M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.44-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z";

const ICON_CHECK =
  "M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z";

const ICON_INFO =
  "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z";

/**
 * Validate password complexity in compliance with DocVault backend policy.
 *
 * Requirements:
 * - 12 to 128 characters
 * - At least 3 categories: lowercase, uppercase, numbers, symbols
 * - Must differ from current password
 *
 * @param {string} newPass
 * @param {string} currentPass
 * @returns {string | null} Error message or null if valid
 */
function validatePasswordPolicy(newPass, currentPass) {
  if (newPass.length < 12 || newPass.length > 128) {
    return "New password must be between 12 and 128 characters.";
  }

  const hasLower = /[a-z]/.test(newPass);
  const hasUpper = /[A-Z]/.test(newPass);
  const hasDigit = /[0-9]/.test(newPass);
  const hasSpecial = /[^a-zA-Z0-9]/.test(newPass);

  const categories = [hasLower, hasUpper, hasDigit, hasSpecial].filter(Boolean).length;
  if (categories < 3) {
    return "New password must use at least 3 character categories (lowercase, uppercase, numbers, symbols).";
  }

  if (currentPass && newPass === currentPass) {
    return "New password must be different from current password.";
  }

  return null;
}

/**
 * Helper to build an accessible password input field with visibility toggle.
 *
 * @param {string} id
 * @param {string} labelText
 * @param {string} autocomplete
 * @returns {{ container: HTMLElement, input: HTMLInputElement, reset: () => void }}
 */
function createPasswordField(id, labelText, autocomplete) {
  const label = createElement(
    "label",
    { className: "form-label fw-semibold small mb-1", htmlFor: id },
    labelText
  );

  const input = createElement("input", {
    type: "password",
    id,
    name: id,
    className: "form-control pe-5",
    placeholder: `Enter ${labelText.toLowerCase()}`,
    autocomplete,
    required: true,
  });

  let isVisible = false;
  const toggleBtn = createElement(
    "button",
    {
      type: "button",
      className:
        "btn btn-link position-absolute end-0 top-50 translate-middle-y pe-3 text-decoration-none border-0 shadow-none text-muted",
      "aria-label": `Show ${labelText.toLowerCase()}`,
      onclick: () => {
        isVisible = !isVisible;
        input.type = isVisible ? "text" : "password";
        toggleBtn.setAttribute(
          "aria-label",
          isVisible ? `Hide ${labelText.toLowerCase()}` : `Show ${labelText.toLowerCase()}`
        );
        clearElement(toggleBtn);
        toggleBtn.appendChild(
          createSvgIcon(isVisible ? ICON_EYE_SLASH : ICON_EYE, "text-muted", 18)
        );
        input.focus();
      },
    },
    createSvgIcon(ICON_EYE, "text-muted", 18)
  );

  const wrapper = createElement("div", { className: "position-relative" }, input, toggleBtn);

  const container = createElement("div", { className: "mb-3" }, label, wrapper);

  function reset() {
    input.value = "";
    if (isVisible) {
      isVisible = false;
      input.type = "password";
      toggleBtn.setAttribute("aria-label", `Show ${labelText.toLowerCase()}`);
      clearElement(toggleBtn);
      toggleBtn.appendChild(createSvgIcon(ICON_EYE, "text-muted", 18));
    }
  }

  return { container, input, reset };
}

/**
 * Render the Account & Security Settings view.
 *
 * @param {HTMLElement} container
 */
export async function renderSettingsView(container) {
  clearElement(container);

  const user = authState.getUser();
  const isAdmin = authState.isAdmin();

  // 1. View Header
  const header = createElement(
    "div",
    { className: "mb-4" },
    createElement("h3", { className: "fw-bold mb-1" }, "Security Settings"),
    createElement(
      "p",
      { className: "text-muted small mb-0" },
      "Manage your credentials, active session security, and account authentication policies."
    )
  );

  // 2. Profile Summary Card
  const userInitial = (user?.username || "?").charAt(0).toUpperCase();

  const profileAvatar = createElement(
    "div",
    { className: "dv-profile-avatar" },
    userInitial
  );

  const profileInfo = createElement(
    "div",
    { className: "flex-grow-1" },
    createElement(
      "div",
      { className: "d-flex flex-wrap align-items-center gap-2 mb-1" },
      createElement("h5", { className: "fw-bold mb-0 text-dark" }, user?.username || "Authenticated User"),
      createElement(
        "span",
        {
          className: `badge ${isAdmin ? "text-bg-warning text-dark" : "text-bg-primary"} text-uppercase px-2 py-1 small`,
        },
        user?.role || "user"
      ),
      createElement("span", { className: "badge text-bg-success px-2 py-1 small" }, "Session Active")
    ),
    createElement(
      "p",
      { className: "text-muted small mb-0" },
      `DocVault Account ID: ${user?.id || "N/A"}`
    )
  );

  const profileCard = createElement(
    "div",
    { className: "dv-card p-4 mb-4" },
    createElement(
      "div",
      { className: "d-flex align-items-center gap-3" },
      profileAvatar,
      profileInfo
    )
  );

  // 3. Password Change Section
  const formAlertArea = createElement("div", {
    className: "mb-3 d-none",
    role: "alert",
    "aria-live": "assertive",
    id: "settings-alert-area",
  });

  function setAlert(msg, type = "danger") {
    clearElement(formAlertArea);
    if (!msg) {
      formAlertArea.classList.add("d-none");
      return;
    }
    formAlertArea.className = `alert alert-${type} py-2 px-3 small d-flex align-items-center gap-2 mb-3`;
    formAlertArea.appendChild(
      createSvgIcon(type === "success" ? ICON_CHECK : ICON_INFO, `text-${type} flex-shrink-0`, 18)
    );
    formAlertArea.appendChild(createElement("span", { className: "flex-grow-1" }, msg));
    formAlertArea.classList.remove("d-none");
  }

  // Password fields
  const currentPassField = createPasswordField(
    "settings-current-password",
    "Current Password",
    "current-password"
  );
  const newPassField = createPasswordField(
    "settings-new-password",
    "New Password",
    "new-password"
  );
  const confirmPassField = createPasswordField(
    "settings-confirm-password",
    "Confirm New Password",
    "new-password"
  );

  // Password Policy Checklist Hint Card
  const policyCard = createElement(
    "div",
    { className: "p-3 mb-3 border rounded bg-light" },
    createElement(
      "h6",
      { className: "fw-semibold small mb-2 d-flex align-items-center gap-1 text-secondary" },
      createSvgIcon(ICON_SHIELD_LOCK, "text-primary", 16),
      createElement("span", {}, "Password Requirements")
    ),
    createElement(
      "ul",
      { className: "small text-muted mb-0 ps-3" },
      createElement("li", {}, "Between 12 and 128 characters in length"),
      createElement("li", {}, "At least 3 categories: lowercase, uppercase, numbers, symbols"),
      createElement("li", {}, "Must be different from your current password")
    )
  );

  // Multi-session revocation notice
  const sessionNotice = createElement(
    "div",
    { className: "alert alert-info py-2 px-3 small d-flex align-items-start gap-2 mb-3" },
    createSvgIcon(ICON_INFO, "text-info flex-shrink-0 mt-1", 16),
    createElement(
      "div",
      { className: "small text-muted" },
      createElement("strong", { className: "text-dark d-block mb-1" }, "Automatic Session Invalidation"),
      "For your security, changing your password will automatically terminate all other active sessions across browsers and devices. Your current session will remain active with an updated security token."
    )
  );

  // Submit & Reset Buttons
  const submitBtn = createElement(
    "button",
    {
      type: "submit",
      className: "btn btn-primary btn-sm d-inline-flex align-items-center gap-1",
      id: "btn-change-password",
    },
    createSvgIcon(ICON_KEY, "", 16),
    createElement("span", { className: "fw-medium" }, "Update Password")
  );

  const resetBtn = createElement(
    "button",
    {
      type: "button",
      className: "btn btn-outline-secondary btn-sm",
      onclick: () => {
        currentPassField.reset();
        newPassField.reset();
        confirmPassField.reset();
        setAlert("");
      },
    },
    "Clear Form"
  );

  const formButtons = createElement(
    "div",
    { className: "d-flex align-items-center gap-2 pt-2" },
    submitBtn,
    resetBtn
  );

  // Form Container
  const form = createElement(
    "form",
    {
      id: "settings-password-form",
      noValidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        setAlert("");

        const currentPass = currentPassField.input.value;
        const newPass = newPassField.input.value;
        const confirmPass = confirmPassField.input.value;

        // 1. Required field checks
        if (!currentPass) {
          setAlert("Please enter your current password.", "danger");
          currentPassField.input.focus();
          return;
        }

        if (!newPass) {
          setAlert("Please enter a new password.", "danger");
          newPassField.input.focus();
          return;
        }

        if (!confirmPass) {
          setAlert("Please confirm your new password.", "danger");
          confirmPassField.input.focus();
          return;
        }

        // 2. Confirmation mismatch check
        if (newPass !== confirmPass) {
          setAlert("New password and confirmation do not match.", "danger");
          confirmPassField.input.focus();
          return;
        }

        // 3. Password policy validation check
        const policyErr = validatePasswordPolicy(newPass, currentPass);
        if (policyErr) {
          setAlert(policyErr, "danger");
          newPassField.input.focus();
          return;
        }

        // 4. Double-submit protection
        submitBtn.disabled = true;
        resetBtn.disabled = true;
        submitBtn.textContent = "Updating Password...";

        try {
          const result = await changePassword(currentPass, newPass);

          if (result.success) {
            setAlert(
              "Password changed successfully. All other active sessions have been terminated.",
              "success"
            );
            showAlert("Password changed successfully.", "success", 4000);
            currentPassField.reset();
            newPassField.reset();
            confirmPassField.reset();
          } else {
            setAlert(
              result.error || "Failed to change password. Please check your current password.",
              "danger"
            );
          }
        } finally {
          submitBtn.disabled = false;
          resetBtn.disabled = false;
          clearElement(submitBtn);
          submitBtn.appendChild(createSvgIcon(ICON_KEY, "", 16));
          submitBtn.appendChild(createElement("span", { className: "fw-medium" }, "Update Password"));
        }
      },
    },
    formAlertArea,
    currentPassField.container,
    newPassField.container,
    confirmPassField.container,
    policyCard,
    sessionNotice,
    formButtons
  );

  const passwordCard = createElement(
    "div",
    { className: "dv-card" },
    createElement(
      "div",
      { className: "dv-card-header" },
      createElement("h5", { className: "mb-0 fw-semibold" }, "Change Password")
    ),
    createElement("div", { className: "dv-card-body p-4" }, form)
  );

  container.appendChild(header);
  container.appendChild(profileCard);
  container.appendChild(passwordCard);
}
