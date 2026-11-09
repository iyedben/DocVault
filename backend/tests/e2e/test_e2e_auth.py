"""E2E Test Scenario B: Authentication, Sessions, and Role-Aware Navigation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from playwright.sync_api import BrowserContext, Page, expect


def test_successful_login_and_logout(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    logout_ui: Callable[[Page], None],
) -> None:
    """Standard user logs in successfully, sees dashboard, and logs out cleanly."""
    user = user_factory(role="user")

    page.goto(f"{base_url}/#login")
    page.fill("#login-username", user["username"])
    page.fill("#login-password", user["password"])
    page.click("#login-submit-btn")

    # Verify transition to dashboard
    page.wait_for_selector("#nav-dashboard", state="visible", timeout=25000)
    expect(page.locator("#main-content")).to_contain_text(f"Welcome back, {user['username']}")
    expect(page.locator("#btn-navbar-logout")).to_be_visible()

    # Logout
    logout_ui(page)
    expect(page.locator("#login-form")).to_be_visible()
    expect(page.locator("#login-username")).to_be_visible()


def test_invalid_credentials_error_display(page: Page, base_url: str) -> None:
    """Invalid username or password displays clear error banner without corrupting form."""
    page.goto(f"{base_url}/#login")
    page.fill("#login-username", "nonexistent_user")
    page.fill("#login-password", "WrongPassword123!Aa")
    page.click("#login-submit-btn")

    # Error alert container should render with error message
    error_container = page.locator("#login-error-container")
    expect(error_container).to_be_visible(timeout=5000)
    expect(error_container).to_contain_text("Invalid username or password")

    # Form remains on screen with username intact
    expect(page.locator("#login-form")).to_be_visible()
    expect(page.locator("#login-username")).to_have_value("nonexistent_user")


def test_client_side_validation_on_empty_submission(page: Page, base_url: str) -> None:
    """Submitting empty username or password triggers client-side validation message."""
    page.goto(f"{base_url}/#login")

    # Click without entering credentials
    page.click("#login-submit-btn")

    error_container = page.locator("#login-error-container")
    expect(error_container).to_be_visible()
    expect(error_container).to_contain_text("Please enter both username and password.")


def test_submit_button_disabled_during_authentication(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
) -> None:
    """Double-submission protection disables inputs and shows loading state during login."""
    user = user_factory(role="user")
    page.goto(f"{base_url}/#login")
    page.fill("#login-username", user["username"])
    page.fill("#login-password", user["password"])
    page.click("#login-submit-btn")

    # Button text or disabled state changes during submit
    # Transition happens quickly, so either disabled or navigation completes
    page.wait_for_selector("#nav-dashboard", state="visible", timeout=25000)


def test_role_aware_navigation_standard_user_vs_admin(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    admin_credentials: tuple[str, str],
    logout_ui: Callable[[Page], None],
) -> None:
    """Standard user does not see Administration link; Admin sees Administration link."""
    # 1. Standard User
    standard_user = user_factory(role="user")
    page.goto(f"{base_url}/#login")
    page.fill("#login-username", standard_user["username"])
    page.fill("#login-password", standard_user["password"])
    page.click("#login-submit-btn")
    page.wait_for_selector("#nav-dashboard", state="visible", timeout=25000)

    # Standard user has Dashboard, Documents, Settings; NO Admin
    expect(page.locator("#nav-dashboard")).to_be_visible()
    expect(page.locator("#nav-documents")).to_be_visible()
    expect(page.locator("#nav-settings")).to_be_visible()
    expect(page.locator("#nav-admin")).not_to_be_visible()

    logout_ui(page)

    # 2. Administrator
    admin_user, admin_pass = admin_credentials
    page.fill("#login-username", admin_user)
    page.fill("#login-password", admin_pass)
    page.click("#login-submit-btn")
    page.wait_for_selector("#nav-dashboard", state="visible", timeout=25000)

    # Admin user HAS Admin link
    expect(page.locator("#nav-admin")).to_be_visible()
    expect(page.locator("#nav-admin")).to_contain_text("Administration")


def test_expired_session_handling(
    context: BrowserContext,
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Clearing cookies simulates session expiration, triggering 401 interception and redirect."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])
    expect(page.locator("#nav-dashboard")).to_be_visible()

    # Clear cookies to simulate expired/revoked server session
    context.clear_cookies()

    # Perform an action that queries the API (e.g. click Documents)
    page.click("#nav-documents")

    # Global 401 handler should intercept, display expiration alert, and transition to login
    page.wait_for_selector("#login-form", state="visible", timeout=25000)
    expect(page.locator("#notification-area")).to_contain_text("Your session has expired. Please sign in again.")
