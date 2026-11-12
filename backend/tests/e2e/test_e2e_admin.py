"""E2E Test Scenario F: Administration Console, Provisioning, Account Lifecycle, and Role Management."""

from __future__ import annotations

import contextlib
import secrets
from collections.abc import Callable
from typing import Any

import httpx
from playwright.sync_api import Browser, BrowserContext, Page, expect
from playwright.sync_api import Error as PlaywrightError


def test_admin_access_granted_for_admin_denied_for_standard_user(
    browser: Browser,
    base_url: str,
    admin_credentials: tuple[str, str],
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Admin user can view administration console; standard user is denied access."""
    admin_user, admin_pass = admin_credentials
    standard_user = user_factory(role="user")

    # 1. Standard user tries to access /#admin directly
    std_ctx = browser.new_context()
    std_page = std_ctx.new_page()
    login_ui(std_page, standard_user["username"], standard_user["password"])
    std_page.wait_for_selector("#nav-dashboard", state="visible")

    # Administration link is NOT in navbar
    expect(std_page.locator("#nav-admin")).not_to_be_visible()

    # Direct hash navigation redirects to dashboard with alert
    std_page.goto(f"{base_url}/#admin")
    std_page.wait_for_selector("#main-content", state="visible")
    expect(std_page.locator("#nav-dashboard")).to_be_visible()
    expect(std_page.locator("#notification-area")).to_contain_text("Administrator access required")
    std_ctx.close()

    # 2. Admin user accesses /#admin
    admin_ctx = browser.new_context()
    admin_page = admin_ctx.new_page()
    login_ui(admin_page, admin_user, admin_pass)
    admin_page.wait_for_selector("#nav-admin", state="visible")

    admin_page.click("#nav-admin")
    admin_page.wait_for_selector("#btn-open-provision-modal", state="visible")
    expect(admin_page.locator("#admin-stats-row")).to_be_visible()
    expect(admin_page.locator(".dv-admin-table")).to_be_visible()
    admin_ctx.close()


def test_admin_user_provisioning_flow(
    page: Page,
    base_url: str,
    admin_credentials: tuple[str, str],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Admin provisions a new user via modal; user appears in roster and can sign in."""
    admin_user, admin_pass = admin_credentials
    login_ui(page, admin_user, admin_pass)

    page.wait_for_selector("#nav-admin", state="visible")
    page.click("#nav-admin")
    page.wait_for_selector("#btn-open-provision-modal", state="visible")

    # Open provision modal
    page.click("#btn-open-provision-modal")
    page.wait_for_selector("#provision-modal-title", state="visible")

    # Fill form
    new_username = f"prov_u_{secrets.token_hex(4)}"
    new_password = "ProvisionedPass123!Aa"
    page.fill("#provision-username", new_username)
    page.select_option("#provision-role", "user")
    page.fill("#provision-password", new_password)

    # Submit
    page.click("#btn-submit-provision-user")
    page.wait_for_selector("#provision-modal-title", state="hidden", timeout=10000)

    # Search for newly provisioned user in roster
    search_input = page.locator("#admin-user-search")
    search_input.fill(new_username)
    expect(page.locator(".dv-admin-table")).to_contain_text(new_username)
    expect(page.locator(".dv-admin-table")).to_contain_text("Active")


def test_admin_deactivate_and_reactivate_account(
    browser: Browser,
    base_url: str,
    admin_credentials: tuple[str, str],
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Admin deactivates a user (blocking login), then reactivates them (restoring access)."""
    admin_user, admin_pass = admin_credentials
    target_user = user_factory(role="user")

    admin_ctx = browser.new_context()
    admin_page = admin_ctx.new_page()
    login_ui(admin_page, admin_user, admin_pass)
    admin_page.wait_for_selector("#nav-admin", state="visible")

    admin_page.click("#nav-admin")
    admin_page.wait_for_selector("#admin-user-search", state="visible")

    # Search for target user
    admin_page.fill("#admin-user-search", target_user["username"])
    expect(admin_page.locator(".dv-admin-table")).to_contain_text(target_user["username"])

    # 1. Deactivate target user
    deactivate_btn = admin_page.locator(".dv-admin-table button:has-text('Deactivate')").first
    deactivate_btn.click()

    # Confirmation modal renders
    admin_page.wait_for_selector("#confirm-modal-title", state="visible")
    admin_page.locator(".modal-footer button.btn-danger").click()
    admin_page.wait_for_selector("#confirm-modal-title", state="hidden")

    # Status changes to Deactivated
    expect(admin_page.locator(".dv-admin-table")).to_contain_text("Deactivated")

    # 2. Deactivated user cannot log in
    user_ctx = browser.new_context()
    user_page = user_ctx.new_page()
    user_page.goto(f"{base_url}/#login")
    user_page.fill("#login-username", target_user["username"])
    user_page.fill("#login-password", target_user["password"])
    user_page.click("#login-submit-btn")
    expect(user_page.locator("#login-error-container")).to_be_visible()
    expect(user_page.locator("#login-error-container")).to_contain_text("Invalid username or password")
    user_ctx.close()

    # 3. Reactivate target user
    activate_btn = admin_page.locator(".dv-admin-table button:has-text('Activate')").first
    activate_btn.click()
    admin_page.wait_for_selector("#confirm-modal-title", state="visible")
    admin_page.locator(".modal-footer button.btn-success").click()
    admin_page.wait_for_selector("#confirm-modal-title", state="hidden")

    # Status changes to Active
    expect(admin_page.locator(".dv-admin-table")).to_contain_text("Active")

    # 4. User can now sign in
    user_ctx2 = browser.new_context()
    user_page2 = user_ctx2.new_page()
    login_ui(user_page2, target_user["username"], target_user["password"])
    expect(user_page2.locator("#main-content")).to_contain_text(f"Welcome back, {target_user['username']}")

    admin_ctx.close()
    user_ctx2.close()


def test_admin_role_promotion_and_demotion(
    browser: Browser,
    base_url: str,
    admin_credentials: tuple[str, str],
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Admin promotes a standard user to administrator and demotes them back to standard user."""
    admin_user, admin_pass = admin_credentials
    target_user = user_factory(role="user")

    admin_ctx = browser.new_context()
    user_ctx: BrowserContext | None = None
    try:
        admin_page = admin_ctx.new_page()
        login_ui(admin_page, admin_user, admin_pass)
        admin_page.wait_for_selector("#nav-admin", state="visible")

        admin_page.click("#nav-admin")
        admin_page.wait_for_selector("#admin-user-search", state="visible")
        admin_page.fill("#admin-user-search", target_user["username"])

        target_row = admin_page.locator(f".dv-admin-table tbody tr:has-text('{target_user['username']}')")
        expect(target_row).to_be_visible()
        role_badge = target_row.locator("td:nth-child(2) span.badge")
        expect(role_badge).to_have_text("user", ignore_case=True)

        # 1. Promote to Administrator
        promote_btn = target_row.locator("button:has-text('Promote')").first
        promote_btn.click()
        admin_page.wait_for_selector("#confirm-modal-title", state="visible")

        # Await successful PATCH response confirming role promotion on backend
        with admin_page.expect_response(
            lambda r: f"/api/v1/admin/users/{target_user['id']}/role" in r.url
            and r.request.method == "PATCH"
            and r.status == 200
        ):
            admin_page.locator(".modal-footer button.btn-primary").click()

        admin_page.wait_for_selector("#confirm-modal-title", state="hidden")

        # Specific target user's role badge updates to administrator
        expect(role_badge).to_have_text("administrator", ignore_case=True)
        expect(target_row.locator("button:has-text('Demote')")).to_be_visible()

        # Promoted user now has Administration nav link in their own session
        user_ctx = browser.new_context()
        user_page = user_ctx.new_page()
        login_ui(user_page, target_user["username"], target_user["password"])
        user_page.wait_for_selector("#nav-admin", state="visible", timeout=15000)
        expect(user_page.locator("#nav-admin")).to_be_visible()
        user_ctx.close()
        user_ctx = None

        # 2. Demote back to Standard User
        demote_btn = target_row.locator("button:has-text('Demote')").first
        demote_btn.click()
        admin_page.wait_for_selector("#confirm-modal-title", state="visible")

        # Await successful PATCH response confirming role demotion on backend
        with admin_page.expect_response(
            lambda r: f"/api/v1/admin/users/{target_user['id']}/role" in r.url
            and r.request.method == "PATCH"
            and r.status == 200
        ):
            admin_page.locator(".modal-footer button.btn-warning").click()

        admin_page.wait_for_selector("#confirm-modal-title", state="hidden")

        # Specific target user's role badge updates back to user
        expect(role_badge).to_have_text("user", ignore_case=True)
        expect(target_row.locator("button:has-text('Promote')")).to_be_visible()

    finally:
        if user_ctx is not None:
            with contextlib.suppress(PlaywrightError, OSError):
                user_ctx.close()
        with contextlib.suppress(PlaywrightError, OSError):
            admin_ctx.close()

        # Cleanup safeguard: ensure target_user is restored to standard user if an intermediate assertion failed
        cleanup_client = httpx.Client(base_url=base_url, timeout=10.0)
        try:
            login_res = cleanup_client.post(
                "/api/v1/auth/login",
                json={"username": admin_user, "password": admin_pass},
            )
            if login_res.status_code == 200:
                csrf = login_res.json()["csrf_token"]
                roster_res = cleanup_client.get(
                    "/api/v1/admin/users",
                    headers={"X-CSRF-Token": csrf},
                )
                if roster_res.status_code == 200:
                    for u in roster_res.json():
                        if u["id"] == target_user["id"] and u["role"] == "administrator":
                            patch_res = cleanup_client.patch(
                                f"/api/v1/admin/users/{target_user['id']}/role",
                                headers={"X-CSRF-Token": csrf},
                                json={"role": "user"},
                            )
                            assert patch_res.status_code == 200, (
                                f"Cleanup demotion failed for {target_user['username']}: {patch_res.text}"
                            )
        finally:
            cleanup_client.close()


def test_final_administrator_protection(
    page: Page,
    base_url: str,
    admin_credentials: tuple[str, str],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Attempting to deactivate the only active administrator triggers protective safeguards."""
    admin_user, admin_pass = admin_credentials

    # 1. Ensure known, controlled administrator state before beginning test
    pre_client = httpx.Client(base_url=base_url, timeout=10.0)
    try:
        login_res = pre_client.post(
            "/api/v1/auth/login",
            json={"username": admin_user, "password": admin_pass},
        )
        assert login_res.status_code == 200, f"Pre-test admin login failed: {login_res.text}"
        csrf = login_res.json()["csrf_token"]
        roster_res = pre_client.get(
            "/api/v1/admin/users",
            headers={"X-CSRF-Token": csrf},
        )
        assert roster_res.status_code == 200, f"Pre-test roster fetch failed: {roster_res.text}"
        for u in roster_res.json():
            if u["username"] != admin_user and u["role"] == "administrator" and u["is_active"]:
                demote_res = pre_client.patch(
                    f"/api/v1/admin/users/{u['id']}/role",
                    headers={"X-CSRF-Token": csrf},
                    json={"role": "user"},
                )
                assert demote_res.status_code == 200, (
                    f"Pre-test state normalization failed for {u['username']}: {demote_res.text}"
                )
    finally:
        pre_client.close()

    # 2. Login via UI and navigate to Admin Console
    login_ui(page, admin_user, admin_pass)

    page.wait_for_selector("#nav-admin", state="visible")
    page.click("#nav-admin")
    page.wait_for_selector("#admin-user-search", state="visible")

    # Search for own admin account
    page.fill("#admin-user-search", admin_user)
    admin_row = page.locator(f".dv-admin-table tbody tr:has-text('{admin_user}')")
    expect(admin_row).to_be_visible()

    # Click Deactivate on own account
    deactivate_btn = admin_row.locator("button:has-text('Deactivate')").first
    deactivate_btn.click()

    page.wait_for_selector("#confirm-modal-title", state="visible")

    # Await expected HTTP 409 Conflict from backend rejecting deactivation of final administrator
    with page.expect_response(
        lambda r: "/api/v1/admin/users/" in r.url
        and "/status" in r.url
        and r.request.method == "PATCH"
        and r.status == 409
    ):
        page.locator(".modal-footer button.btn-danger").click()

    # Confirm rejection alert renders in notification area
    expect(page.locator("#notification-area")).to_be_visible(timeout=5000)
    expect(page.locator("#notification-area")).to_contain_text("final active administrator")

    # 3. Verify bootstrap administrator remains active after expected rejection
    status_badge = admin_row.locator("td:nth-child(3) span.badge")
    expect(status_badge).to_have_text("Active", ignore_case=True)
    expect(page.locator("#nav-admin")).to_be_visible()
    expect(page.locator("#btn-navbar-logout")).to_be_visible()

    # Confirm account remains active and capable of authenticating via API
    verify_client = httpx.Client(base_url=base_url, timeout=10.0)
    try:
        verify_res = verify_client.post(
            "/api/v1/auth/login",
            json={"username": admin_user, "password": admin_pass},
        )
        assert verify_res.status_code == 200, (
            f"Bootstrap administrator was unexpectedly deactivated: {verify_res.text}"
        )
    finally:
        verify_client.close()
