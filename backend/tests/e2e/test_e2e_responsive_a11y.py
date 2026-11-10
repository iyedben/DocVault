"""E2E Test Scenario G: Responsive Design & Accessibility (Viewports, Overflow, Focus, Skip Link)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from playwright.sync_api import Page, expect

VIEWPORTS = [
    {"name": "desktop", "width": 1920, "height": 1080},
    {"name": "laptop", "width": 1440, "height": 900},
    {"name": "tablet", "width": 768, "height": 1024},
    {"name": "mobile", "width": 375, "height": 667},
]


@pytest.mark.parametrize("vp", VIEWPORTS, ids=[str(v["name"]) for v in VIEWPORTS])
def test_responsive_layout_and_zero_horizontal_overflow(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    vp: dict[str, Any],
) -> None:
    """Dashboard layout renders cleanly without horizontal scrolling across all viewports."""
    page.set_viewport_size({"width": vp["width"], "height": vp["height"]})
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    # Ensure main content is visible
    expect(page.locator("#main-content")).to_be_visible()

    # Verify zero horizontal overflow
    overflow = page.evaluate("""() => {
        const root = document.documentElement;
        return root.scrollWidth > window.innerWidth;
    }""")
    assert not overflow, f"Horizontal overflow detected at {vp['name']} ({vp['width']}x{vp['height']})"


def test_mobile_navbar_toggler_expand_collapse(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """On mobile viewport (375px), navbar collapses into a toggleable hamburger menu."""
    page.set_viewport_size({"width": 375, "height": 667})
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    toggler = page.locator("button.navbar-toggler")
    expect(toggler).to_be_visible()

    # Click toggler to expand menu
    toggler.click()
    page.wait_for_selector("#mainNavbarNav.show", state="visible", timeout=3000)
    expect(page.locator("#btn-navbar-logout")).to_be_visible()

    # Click toggler again to collapse
    toggler.click()
    page.wait_for_selector("#mainNavbarNav.show", state="hidden", timeout=3000)


def test_keyboard_skip_link_accessibility(page: Page, base_url: str) -> None:
    """Keyboard skip link exists, targets #main-content, and receives focus on initial Tab."""
    page.goto(base_url)

    skip_link = page.locator("a.dv-skip-link")
    expect(skip_link).to_have_attribute("href", "#main-content")

    # Focus skip link via keyboard Tab
    page.keyboard.press("Tab")
    is_focused = page.evaluate("() => document.activeElement === document.querySelector('.dv-skip-link')")
    assert is_focused, "Skip link did not receive focus on initial keyboard Tab"


def test_modal_focus_trap_and_escape_dismissal(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
) -> None:
    """Opening a modal dialog traps keyboard focus within and dismisses on Escape."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.click("#nav-documents")
    page.wait_for_selector("#btn-open-upload-modal", state="visible")

    # Open upload modal
    page.click("#btn-open-upload-modal")
    page.wait_for_selector("#upload-modal-title", state="visible")

    # Focus should be inside modal
    in_modal = page.evaluate("""() => {
        const modal = document.querySelector('.dv-modal-dialog');
        return modal && modal.contains(document.activeElement);
    }""")
    assert in_modal, "Active element is not within the modal dialog"

    # Tab multiple times; active element must remain within modal
    for _ in range(5):
        page.keyboard.press("Tab")
        still_in_modal = page.evaluate("""() => {
            const modal = document.querySelector('.dv-modal-dialog');
            return modal && modal.contains(document.activeElement);
        }""")
        assert still_in_modal, "Focus escaped the modal dialog during keyboard Tab cycling"

    # Press Escape key to dismiss modal
    page.keyboard.press("Escape")
    page.wait_for_selector("#upload-modal-title", state="hidden", timeout=5000)
    expect(page.locator(".dv-modal-backdrop")).not_to_be_visible()


def test_form_labels_accessible_association(page: Page, base_url: str) -> None:
    """Form controls in the login view have accessible labels matching their input IDs."""
    page.goto(f"{base_url}/#login")

    # Username input and label
    username_label = page.locator("label[for='login-username']")
    expect(username_label).to_be_visible()
    expect(username_label).to_contain_text("Username")

    # Password input and label
    password_label = page.locator("label[for='login-password']")
    expect(password_label).to_be_visible()
    expect(password_label).to_contain_text("Password")
