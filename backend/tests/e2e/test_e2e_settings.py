"""E2E Test Scenario E: Account Security Settings & Password Management."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from playwright.sync_api import Browser, Page, expect


def test_settings_identity_and_role_display(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Settings view displays the authenticated user's username and role badge."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.wait_for_selector("#nav-settings", state="visible")
    page.click("#nav-settings")
    page.wait_for_selector("#settings-password-form", state="visible")

    # Verify identity card
    expect(page.locator("#main-content")).to_contain_text(user["username"])
    expect(page.locator("#main-content")).to_contain_text("user", ignore_case=True)


def test_password_visibility_toggles(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Password visibility toggle buttons correctly switch input type between password and text."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.wait_for_selector("#nav-settings", state="visible")
    page.click("#nav-settings")
    page.wait_for_selector("#settings-password-form", state="visible")

    current_pass_input = page.locator("#settings-current-password")
    expect(current_pass_input).to_have_attribute("type", "password")

    # Click the toggle button inside the field wrapper
    toggle_btn = current_pass_input.locator("..").locator("button")
    toggle_btn.click()
    expect(current_pass_input).to_have_attribute("type", "text")

    toggle_btn.click()
    expect(current_pass_input).to_have_attribute("type", "password")


def test_password_policy_validation_errors(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Submitting invalid password forms displays clear validation feedback without network submission."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.wait_for_selector("#nav-settings", state="visible")
    page.click("#nav-settings")
    page.wait_for_selector("#settings-password-form", state="visible")

    # 1. New password too short (< 12 characters)
    page.fill("#settings-current-password", user["password"])
    page.fill("#settings-new-password", "Short1!")
    page.fill("#settings-confirm-password", "Short1!")
    page.click("#btn-change-password")

    alert_area = page.locator("#settings-alert-area")
    expect(alert_area).to_be_visible()
    expect(alert_area).to_contain_text("between 12 and 128 characters")

    # 2. Confirmation mismatch
    page.fill("#settings-new-password", "ValidNewPass123!Aa")
    page.fill("#settings-confirm-password", "DifferentPass123!Aa")
    page.click("#btn-change-password")

    expect(alert_area).to_be_visible()
    expect(alert_area).to_contain_text("do not match")

    # 3. New password identical to current password
    page.fill("#settings-new-password", user["password"])
    page.fill("#settings-confirm-password", user["password"])
    page.click("#btn-change-password")

    expect(alert_area).to_be_visible()
    expect(alert_area).to_contain_text("different from current password")


def test_password_change_lifecycle_and_multi_session_revocation(
    browser: Browser,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
) -> None:
    """Changing password updates credentials, invalidates other active sessions, and updates login."""
    initial_password = "InitialPassword123!Aa"
    new_password = "UpdatedPassword456!Bb"
    user = user_factory(role="user", password=initial_password)

    # Context 1: User logs in and will change password
    ctx1 = browser.new_context()
    page1 = ctx1.new_page()
    page1.goto(f"{base_url}/#login")
    page1.fill("#login-username", user["username"])
    page1.fill("#login-password", initial_password)
    page1.click("#login-submit-btn")
    page1.wait_for_selector("#nav-dashboard", state="visible")

    # Context 2: Same user logs in on a second device/browser
    ctx2 = browser.new_context()
    page2 = ctx2.new_page()
    page2.goto(f"{base_url}/#login")
    page2.fill("#login-username", user["username"])
    page2.fill("#login-password", initial_password)
    page2.click("#login-submit-btn")
    page2.wait_for_selector("#nav-dashboard", state="visible")

    # In Context 1: Navigate to Settings and change password
    page1.click("#nav-settings")
    page1.wait_for_selector("#settings-password-form", state="visible")
    page1.fill("#settings-current-password", initial_password)
    page1.fill("#settings-new-password", new_password)
    page1.fill("#settings-confirm-password", new_password)
    page1.click("#btn-change-password")

    # Context 1 should see success banner
    alert_area = page1.locator("#settings-alert-area")
    expect(alert_area).to_be_visible(timeout=8000)
    expect(alert_area).to_contain_text("Password changed successfully")

    # Context 2: Attempts to access a protected view -> session invalidated, redirect to login
    page2.click("#nav-documents")
    page2.wait_for_selector("#login-form", state="visible", timeout=10000)
    expect(page2.locator("#notification-area")).to_contain_text("Your session has expired")

    # In Context 2: Attempting to sign in with OLD password fails
    page2.fill("#login-username", user["username"])
    page2.fill("#login-password", initial_password)
    page2.click("#login-submit-btn")
    expect(page2.locator("#login-error-container")).to_be_visible()
    expect(page2.locator("#login-error-container")).to_contain_text("Invalid username or password")

    # In Context 2: Signing in with NEW password succeeds
    page2.fill("#login-password", new_password)
    page2.click("#login-submit-btn")
    page2.wait_for_selector("#nav-dashboard", state="visible", timeout=10000)
    expect(page2.locator("#main-content")).to_contain_text(f"Welcome back, {user['username']}")

    ctx1.close()
    ctx2.close()
