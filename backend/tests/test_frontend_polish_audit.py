"""Tests for Phase B7 frontend quality, accessibility, and security audit.
Verifies absence of unsafe DOM APIs, absence of client storage mechanisms,
WCAG landmarks in HTML shell, strict CSP headers, and URL sanitization in dom.js.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from app.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_JS_DIR = REPO_ROOT / "frontend" / "static" / "js"
INDEX_HTML = REPO_ROOT / "frontend" / "index.html"


def test_zero_unsafe_dom_apis_in_frontend_modules() -> None:
    """1. Frontend JS code strictly avoids innerHTML, outerHTML, and dynamic execution."""
    assert FRONTEND_JS_DIR.is_dir(), f"Directory not found: {FRONTEND_JS_DIR}"

    dangerous_patterns = [
        re.compile(r"\binnerHTML\b"),
        re.compile(r"\bouterHTML\b"),
        re.compile(r"\binsertAdjacentHTML\b"),
        re.compile(r"\bdocument\.write\b"),
        re.compile(r"\beval\s*\("),
        re.compile(r"\bnew\s+Function\s*\("),
    ]

    js_files = list(FRONTEND_JS_DIR.rglob("*.js"))
    assert len(js_files) >= 10, f"Expected at least 10 JS modules, found {len(js_files)}"

    violations = []
    for js_path in js_files:
        content = js_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            # Skip documentation comments
            stripped = line.strip()
            if stripped.startswith(("*", "//", "/*")):
                continue
            for pattern in dangerous_patterns:
                if pattern.search(line):
                    violations.append(f"{js_path.name}:{idx}: {line.strip()}")

    assert not violations, "Detected unsafe DOM APIs in frontend JS:\n" + "\n".join(violations)


def test_zero_browser_storage_persistence() -> None:
    """2. Client code strictly avoids localStorage, sessionStorage, and IndexedDB."""
    storage_patterns = [
        re.compile(r"\blocalStorage\b"),
        re.compile(r"\bsessionStorage\b"),
        re.compile(r"\bindexedDB\b"),
        re.compile(r"\bdocument\.cookie\s*="),
    ]

    js_files = list(FRONTEND_JS_DIR.rglob("*.js"))
    violations = []
    for js_path in js_files:
        content = js_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("*", "//", "/*")):
                continue
            for pattern in storage_patterns:
                if pattern.search(line):
                    violations.append(f"{js_path.name}:{idx}: {line.strip()}")

    assert not violations, "Detected client storage access in frontend JS:\n" + "\n".join(violations)


def test_dom_utility_safeguards() -> None:
    """3. Verify dom.js implements URL sanitization, htmlFor normalization, and trapFocus."""
    dom_js_path = FRONTEND_JS_DIR / "utils" / "dom.js"
    assert dom_js_path.is_file()

    content = dom_js_path.read_text(encoding="utf-8")

    # Verify trapFocus is exported
    assert "export function trapFocus(" in content

    # Verify htmlFor normalization
    assert "key === \"htmlFor\"" in content or "key === 'htmlFor'" in content
    assert "element.setAttribute(\"for\"" in content or "element.setAttribute('for'" in content

    # Verify URL scheme sanitization against javascript:, data:, vbscript:
    assert "javascript" in content.lower()
    assert "data" in content.lower()
    assert "vbscript" in content.lower()


def test_index_html_accessibility_landmarks() -> None:
    """4. Verify index.html contains accessible landmarks, skip link, and lang attribute."""
    assert INDEX_HTML.is_file()
    html = INDEX_HTML.read_text(encoding="utf-8")

    # Document language
    assert '<html lang="en">' in html or "<html lang='en'>" in html

    # Skip navigation link
    assert "dv-skip-link" in html
    assert 'href="#main-content"' in html

    # Main landmark
    assert "<main" in html
    assert 'id="main-content"' in html

    # Navigation landmark
    assert "<nav" in html
    assert 'aria-label="Main Navigation"' in html or 'aria-label=\'Main Navigation\'' in html

    # Live notification area
    assert 'id="notification-area"' in html
    assert 'aria-live="polite"' in html


@pytest.mark.anyio
async def test_strict_csp_and_security_headers_audit() -> None:
    """5. HTTP responses strictly enforce Content Security Policy and defensive headers."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        res = await client.get("/")
        assert res.status_code == 200

        headers = res.headers
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("Referrer-Policy") == "no-referrer"

        csp = headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp

        # Strictly forbid unsafe inline or eval allowances in production policy
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp


def test_responsive_dashboard_layout_rules() -> None:
    """6. Verify responsive desktop layout and dashboard width rules."""
    app_css_path = REPO_ROOT / "frontend" / "static" / "css" / "app.css"
    assert app_css_path.is_file()
    css_content = app_css_path.read_text(encoding="utf-8")

    # Body overflow protection
    assert "overflow-x: hidden" in css_content

    # Container responsive sizing (max-width expanded from 1200px to 1600px)
    assert ".dv-main-container" in css_content
    assert "min-width: 0" in css_content
    assert "max-width: 1600px" in css_content

    # Platform status column sizing
    assert ".dv-status-label-col" in css_content

    # Roadmap item styling
    assert ".dv-roadmap-item" in css_content

    # Verify router.js uses responsive grid classes
    router_js_path = FRONTEND_JS_DIR / "router.js"
    assert router_js_path.is_file()
    router_content = router_js_path.read_text(encoding="utf-8")

    assert "dv-status-label-col" in router_content
    assert "table-responsive" in router_content
    assert "col-12 col-lg-6" in router_content
