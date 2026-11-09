"""E2E Test Scenario A: Application Startup, SPA Routing, and Route Guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from playwright.sync_api import Page, expect


def test_initial_load_renders_login_page(page: Page, base_url: str) -> None:
    """Opening the root URL renders the unauthenticated login view cleanly."""
    page.goto(base_url)

    # Verify document title
    expect(page).to_have_title("DocVault — Secure Document Management Platform")

    # Verify brand elements
    brand = page.locator("a.dv-brand")
    expect(brand).to_be_visible()
    expect(brand).to_contain_text("DocVault")

    # Verify login form controls
    expect(page.locator("#login-username")).to_be_visible()
    expect(page.locator("#login-password")).to_be_visible()
    expect(page.locator("#login-submit-btn")).to_be_visible()
    expect(page.locator("#login-submit-btn")).to_contain_text("Sign In")


def test_repeated_reloads_maintain_stability(page: Page, base_url: str) -> None:
    """Repeated page reloads cleanly re-render without errors or state corruption."""
    page.goto(base_url)
    expect(page.locator("#login-form")).to_be_visible()

    for _ in range(3):
        page.reload()
        page.wait_for_selector("#login-username", state="visible")
        expect(page.locator("#login-submit-btn")).to_be_visible()


def test_unauthenticated_protected_route_access_redirects_to_login(
    page: Page, base_url: str
) -> None:
    """Direct URL navigation to protected SPA hashes redirects anonymous users to login."""
    protected_hashes = ["#dashboard", "#documents", "#settings", "#admin"]

    for target_hash in protected_hashes:
        page.goto(f"{base_url}/{target_hash}")
        # Must show login form and not show protected navigation or content
        page.wait_for_selector("#login-form", state="visible", timeout=5000)
        expect(page.locator("#nav-dashboard")).not_to_be_visible()
        expect(page.locator("#nav-documents")).not_to_be_visible()
        expect(page.locator("#nav-settings")).not_to_be_visible()
        expect(page.locator("#nav-admin")).not_to_be_visible()


def test_session_restoration_after_reload(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Authenticated user session is cleanly restored across page reloads without re-authenticating."""
    test_user = user_factory(role="user")

    # Sign in
    login_ui(page, test_user["username"], test_user["password"])
    expect(page.locator("#nav-dashboard")).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text(f"Welcome back, {test_user['username']}")

    # Reload the page
    page.reload()

    # Verify session restored and user remains on dashboard
    page.wait_for_selector("#nav-dashboard", state="visible", timeout=10000)
    expect(page.locator("#login-form")).not_to_be_visible()
    expect(page.locator("#main-content")).to_contain_text(f"Welcome back, {test_user['username']}")


def test_authenticated_view_navigation(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Authenticated user can navigate cleanly between supported views via navigation links."""
    test_user = user_factory(role="user")
    login_ui(page, test_user["username"], test_user["password"])

    # 1. Documents view
    page.click("#nav-documents")
    page.wait_for_selector("#documents-table-container", state="visible", timeout=5000)
    expect(page.locator("#btn-open-upload-modal")).to_be_visible()
    expect(page.locator("#docs-search-input")).to_be_visible()

    # 2. Settings view
    page.click("#nav-settings")
    page.wait_for_selector("#settings-password-form", state="visible", timeout=5000)
    expect(page.locator("#settings-current-password")).to_be_visible()
    expect(page.locator("#btn-change-password")).to_be_visible()

    # 3. Return to Dashboard view
    page.click("#nav-dashboard")
    page.wait_for_selector("#main-content", state="visible", timeout=5000)
    expect(page.locator("#main-content")).to_contain_text(f"Welcome back, {test_user['username']}")
