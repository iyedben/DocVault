"""E2E Test Scenario D: Document Sharing (Search, Grant Access, Revoke Access, Permissions)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, Page, expect


def test_document_sharing_full_lifecycle(
    browser: Browser,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    sample_pdf_path: Path,
) -> None:
    """Owner searches user, grants share, sharee views/downloads, owner revokes share."""
    owner = user_factory(role="user")
    recipient = user_factory(role="user")

    # 1. Owner logs in and uploads document
    owner_context = browser.new_context()
    owner_page = owner_context.new_page()
    login_ui(owner_page, owner["username"], owner["password"])
    owner_page.wait_for_selector("#nav-documents", state="visible")

    owner_page.click("#nav-documents")
    owner_page.click("#btn-open-upload-modal")
    owner_page.locator("#modal-file-picker").set_input_files(str(sample_pdf_path))
    owner_page.locator(".modal-footer button.btn-primary").click()
    owner_page.wait_for_selector("#upload-modal-title", state="hidden")
    expect(owner_page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")

    # 2. Open Share modal
    owner_page.locator("button[id^='btn-share-doc-']").first.click()
    owner_page.wait_for_selector("#share-modal-title", state="visible")

    # Search for recipient username (debounced lookup)
    search_input = owner_page.locator("#share-user-search-input")
    search_input.fill(recipient["username"])
    owner_page.wait_for_selector("#share-lookup-results .dv-lookup-item", state="visible", timeout=5000)

    # Grant access to recipient
    grant_btn = owner_page.locator("#share-lookup-results button:has-text('Grant Access')").first
    grant_btn.click()

    # Recipient should now appear in active collaborators
    owner_page.wait_for_selector("#share-active-list .dv-share-item", state="visible", timeout=5000)
    expect(owner_page.locator("#share-active-list")).to_contain_text(recipient["username"])

    # Close share modal
    owner_page.locator(".dv-modal-dialog button[aria-label='Close']").click()
    owner_page.wait_for_selector("#share-modal-title", state="hidden")

    # 3. Recipient logs in in a separate context
    recipient_context = browser.new_context()
    recipient_page = recipient_context.new_page()
    login_ui(recipient_page, recipient["username"], recipient["password"])
    recipient_page.wait_for_selector("#nav-documents", state="visible")

    recipient_page.click("#nav-documents")
    recipient_page.wait_for_selector("#documents-table-container", state="visible")

    # Recipient sees the shared document
    expect(recipient_page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")
    expect(recipient_page.locator("#documents-table-container")).to_contain_text("Shared")

    # Recipient CAN download
    with recipient_page.expect_download() as dl_info:
        recipient_page.locator("button:has-text('Download')").first.click()
    dl = dl_info.value
    assert dl.path() is not None

    # Recipient CANNOT Share or Delete (no buttons rendered)
    expect(recipient_page.locator("button[id^='btn-share-doc-']")).not_to_be_visible()
    expect(recipient_page.locator("button:has-text('Delete')")).not_to_be_visible()

    # 4. Owner revokes access
    owner_page.locator("button[id^='btn-share-doc-']").first.click()
    owner_page.wait_for_selector("#share-modal-title", state="visible")

    revoke_btn = owner_page.locator("#share-active-list button:has-text('Revoke')").first
    revoke_btn.click()

    # Verify collaborator removed from list
    expect(owner_page.locator("#share-active-list")).not_to_contain_text(recipient["username"])
    owner_page.locator(".dv-modal-dialog button[aria-label='Close']").click()

    # 5. Recipient refreshes documents; document is no longer accessible
    recipient_page.reload()
    recipient_page.wait_for_selector("#documents-table-container", state="visible")
    expect(recipient_page.locator("#documents-table-container")).not_to_contain_text("minimal_valid.pdf")
    expect(recipient_page.locator("#documents-table-container")).to_contain_text("No documents")

    owner_context.close()
    recipient_context.close()
