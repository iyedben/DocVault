"""Shared fixtures and configuration for Playwright E2E browser tests."""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from playwright.sync_api import Browser, BrowserContext, Page, expect
from playwright.sync_api import Error as PlaywrightError

# Configure default assertion timeout to 15s to accommodate CPU-constrained container execution
expect.set_options(timeout=15000)

# Ensure Playwright can load extracted headless libraries on Ubuntu server
_PLAYWRIGHT_LIBS = Path.home() / ".local/lib/playwright-libs/usr/lib/x86_64-linux-gnu"
if _PLAYWRIGHT_LIBS.is_dir():
    _current_ld = os.environ.get("LD_LIBRARY_PATH", "")
    _lib_str = str(_PLAYWRIGHT_LIBS)
    if _lib_str not in _current_ld:
        os.environ["LD_LIBRARY_PATH"] = f"{_lib_str}:{_current_ld}" if _current_ld else _lib_str

# Ensure Playwright finds extracted fonts and fontconfig
_FONTCONFIG_DIR = Path.home() / ".local/etc/fonts"
if _FONTCONFIG_DIR.is_dir():
    if "FONTCONFIG_PATH" not in os.environ:
        os.environ["FONTCONFIG_PATH"] = str(_FONTCONFIG_DIR)
    if "FONTCONFIG_FILE" not in os.environ:
        _fonts_conf = _FONTCONFIG_DIR / "fonts.conf"
        if _fonts_conf.is_file():
            os.environ["FONTCONFIG_FILE"] = str(_fonts_conf)


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, Any]) -> dict[str, Any]:
    """Provide robust launch args for headless Chromium in containerized environments."""
    launch_args = list(browser_type_launch_args.get("args", []))
    for arg in ("--no-sandbox", "--disable-dev-shm-usage"):
        if arg not in launch_args:
            launch_args.append(arg)
    return {
        **browser_type_launch_args,
        "args": launch_args,
    }


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args: dict[str, Any]) -> dict[str, Any]:
    """Default browser context to desktop 1280x720 viewport."""
    return {
        **browser_context_args,
        "viewport": {"width": 1280, "height": 720},
    }


@pytest.fixture(autouse=True)
def _default_browser_viewport(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure manual browser.new_context() calls default to desktop viewport unless overridden."""
    orig_new_context = Browser.new_context

    def _wrapped_new_context(self: Browser, **kwargs: Any) -> BrowserContext:
        if "viewport" not in kwargs:
            kwargs["viewport"] = {"width": 1280, "height": 720}
        return orig_new_context(self, **kwargs)

    monkeypatch.setattr(Browser, "new_context", _wrapped_new_context)


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Any:
    """Capture full-page screenshot on test failure for diagnostics."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        funcargs: dict[str, Any] = getattr(item, "funcargs", {})
        page = funcargs.get("page")
        if isinstance(page, Page):
            out_dir = Path("test-results/failures")
            out_dir.mkdir(parents=True, exist_ok=True)
            screenshot_path = out_dir / f"{item.name}_{int(time.time())}.png"
            try:
                page.screenshot(path=str(screenshot_path), full_page=True)
            except (PlaywrightError, OSError):
                pass


@pytest.fixture(scope="session")
def base_url() -> str:
    """Determine the base URL for the DocVault application under test."""
    env_url = os.environ.get("DOCVAULT_BASE_URL")
    if env_url:
        return env_url.rstrip("/")

    # Probe default isolated port 8001 first, then fallback to 8000
    for port in (8001, 8000):
        try:
            res = httpx.get(f"http://127.0.0.1:{port}/ready", timeout=1.0)
            if res.status_code == 200:
                return f"http://127.0.0.1:{port}"
        except httpx.HTTPError:
            continue

    return "http://127.0.0.1:8001"


@pytest.fixture(scope="session")
def admin_credentials() -> tuple[str, str]:
    """Retrieve administrator credentials from the execution environment."""
    username = os.environ.get("DOCVAULT_ADMIN_USER", "admin")
    password = os.environ.get("DOCVAULT_ADMIN_PASSWORD", "AdminPass1234!Aa")
    return username, password


@pytest.fixture(scope="session")
def sample_pdf_path() -> Path:
    """Path to the valid minimal PDF test fixture."""
    pdf_path = Path(__file__).parent.parent / "fixtures" / "minimal_valid.pdf"
    assert pdf_path.is_file(), f"Test fixture not found: {pdf_path}"
    return pdf_path


@pytest.fixture
def user_factory(base_url: str, admin_credentials: tuple[str, str]) -> Callable[..., dict[str, Any]]:
    """Factory creating disposable test users via the backend administration API."""

    def _create_user(role: str = "user", password: str | None = None) -> dict[str, Any]:
        admin_user, admin_pass = admin_credentials
        client = httpx.Client(base_url=base_url, timeout=30.0)

        # 1. Login as admin to get session cookie and CSRF token
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": admin_user, "password": admin_pass},
        )
        assert login_res.status_code == 200, f"Admin login failed: {login_res.text}"
        csrf_token = login_res.json()["csrf_token"]

        # 2. Provision new user
        unique_suffix = secrets.token_hex(4)
        username = f"e2e_{role[:3]}_{unique_suffix}"
        user_pwd = password or f"User_{unique_suffix}!Aa1"

        prov_res = client.post(
            "/api/v1/admin/users",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": username,
                "password": user_pwd,
                "role": role,
            },
        )
        assert prov_res.status_code == 201, f"User provisioning failed: {prov_res.text}"
        user_data = prov_res.json()
        client.close()

        return {
            "id": user_data["id"],
            "username": username,
            "password": user_pwd,
            "role": role,
        }

    return _create_user


@pytest.fixture
def login_ui(base_url: str) -> Callable[[Page, str, str], None]:
    """Helper function to log into DocVault through the browser UI."""

    def _login(page: Page, username: str, password: str) -> None:
        page.goto(f"{base_url}/#login")
        page.wait_for_selector("#login-username", state="visible")
        page.fill("#login-username", username)
        page.fill("#login-password", password)
        page.click("#login-submit-btn")
        # Wait for navigation to complete and dashboard content to render (accessible across all viewports)
        page.wait_for_selector("text=Welcome back", state="visible", timeout=15000)
        # Ensure login form has transitioned out
        page.wait_for_selector("#login-form", state="hidden", timeout=10000)

    return _login


@pytest.fixture
def logout_ui() -> Callable[[Page], None]:
    """Helper function to log out of DocVault through the browser UI."""

    def _logout(page: Page) -> None:
        # If mobile navbar is collapsed, toggle it open
        toggler = page.locator("button.navbar-toggler")
        if toggler.is_visible():
            toggler.click()
            page.wait_for_selector("#btn-navbar-logout", state="visible", timeout=3000)

        with page.expect_response(lambda r: "/api/v1/auth/logout" in r.url and r.status in (204, 401)):
            page.click("#btn-navbar-logout")
        page.wait_for_selector("#login-form", state="visible", timeout=10000)
        page.wait_for_selector("#login-username:not([disabled])", state="visible", timeout=5000)

    return _logout
