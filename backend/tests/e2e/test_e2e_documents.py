"""E2E Test Scenario C: Document Management (Upload, Download, Search, Filter, Delete, Isolation)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, Page, expect


def test_upload_valid_pdf_appears_in_document_list(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    sample_pdf_path: Path,
) -> None:
    """User can upload a valid PDF via the modal; document immediately appears in list."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    # Navigate to Documents
    page.click("#nav-documents")
    page.wait_for_selector("#documents-table-container", state="visible")

    # Open upload modal
    page.click("#btn-open-upload-modal")
    page.wait_for_selector("#upload-modal-title", state="visible")

    # Set file input
    file_input = page.locator("#modal-file-picker")
    file_input.set_input_files(str(sample_pdf_path))

    # Selected file card appears, submit button enabled
    expect(page.locator(".dv-selected-file-card")).to_be_visible()
    upload_submit_btn = page.locator(".modal-footer button.btn-primary")
    expect(upload_submit_btn).to_be_enabled()

    # Submit upload
    upload_submit_btn.click()

    # Modal closes, document table contains minimal_valid.pdf
    page.wait_for_selector("#upload-modal-title", state="hidden", timeout=10000)
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")
    expect(page.locator("#documents-table-container")).to_contain_text("Owner")


def test_download_uploaded_pdf_integrity(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    sample_pdf_path: Path,
) -> None:
    """Downloading an uploaded document returns authentic PDF binary bytes."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.click("#nav-documents")
    page.wait_for_selector("#btn-open-upload-modal", state="visible")

    # Upload document
    page.click("#btn-open-upload-modal")
    page.locator("#modal-file-picker").set_input_files(str(sample_pdf_path))
    page.locator(".modal-footer button.btn-primary").click()
    page.wait_for_selector("#upload-modal-title", state="hidden")

    # Download document
    with page.expect_download() as download_info:
        # Click download button on the first document row
        page.locator("button:has-text('Download')").first.click()

    download = download_info.value
    download_path = download.path()
    assert download_path is not None

    with open(download_path, "rb") as f:
        downloaded_bytes = f.read()

    assert downloaded_bytes.startswith(b"%PDF-"), "Downloaded file does not start with PDF magic bytes"
    with open(sample_pdf_path, "rb") as orig_f:
        expected_bytes = orig_f.read()
    assert downloaded_bytes == expected_bytes, "Downloaded content does not match original uploaded file"


def test_document_search_and_tab_filtering(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    sample_pdf_path: Path,
) -> None:
    """Client-side search filters visible documents and tab filters toggle properly."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.click("#nav-documents")
    page.wait_for_selector("#btn-open-upload-modal", state="visible")

    # Upload document
    page.click("#btn-open-upload-modal")
    page.locator("#modal-file-picker").set_input_files(str(sample_pdf_path))
    page.locator(".modal-footer button.btn-primary").click()
    page.wait_for_selector("#upload-modal-title", state="hidden")
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")

    # 1. Search for matching text
    search_input = page.locator("#docs-search-input")
    search_input.fill("minimal")
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")

    # 2. Search for non-matching text
    search_input.fill("nonexistent_term_xyz")
    expect(page.locator("#documents-table-container")).to_contain_text("No matching documents")

    # Clear search
    search_input.fill("")
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")

    # 3. Filter tabs: My Documents (shows file), Shared with me (shows empty)
    page.click("#filter-shared")
    expect(page.locator("#documents-table-container")).to_contain_text("No matching documents")

    page.click("#filter-owner")
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")

    page.click("#filter-all")
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")


def test_delete_document_with_confirmation(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    sample_pdf_path: Path,
) -> None:
    """Deleting a document prompts for confirmation and removes the item from the list."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.click("#nav-documents")
    page.wait_for_selector("#btn-open-upload-modal", state="visible")

    # Upload document
    page.click("#btn-open-upload-modal")
    page.locator("#modal-file-picker").set_input_files(str(sample_pdf_path))
    page.locator(".modal-footer button.btn-primary").click()
    page.wait_for_selector("#upload-modal-title", state="hidden")
    expect(page.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")

    # Click Delete button
    page.locator("button:has-text('Delete')").first.click()

    # Confirmation modal renders
    page.wait_for_selector("#delete-modal-title", state="visible")
    expect(page.locator("#delete-modal-title")).to_contain_text("Delete Document")

    # Confirm deletion
    delete_confirm_btn = page.locator(".modal-footer button.btn-danger")
    delete_confirm_btn.click()

    # Modal closes, document is removed
    page.wait_for_selector("#delete-modal-title", state="hidden", timeout=10000)
    expect(page.locator("#documents-table-container")).not_to_contain_text("minimal_valid.pdf")


def test_reject_invalid_file_type_in_upload_modal(
    page: Page,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    tmp_path: Path,
) -> None:
    """Client-side validation rejects non-PDF files and blocks submission."""
    user = user_factory(role="user")
    login_ui(page, user["username"], user["password"])

    page.click("#nav-documents")
    page.click("#btn-open-upload-modal")
    page.wait_for_selector("#upload-modal-title", state="visible")

    # Create dummy text file
    txt_file = tmp_path / "test_invalid.txt"
    txt_file.write_text("This is not a PDF")

    # Attempt to upload text file
    page.locator("#modal-file-picker").set_input_files(str(txt_file))

    # Error message should render inside modal
    expect(page.locator(".dv-modal-dialog .alert-danger")).to_be_visible()
    expect(page.locator(".dv-modal-dialog .alert-danger")).to_contain_text("Only PDF documents are allowed")

    # Submit button remains disabled
    expect(page.locator(".modal-footer button.btn-primary")).to_be_disabled()


def test_cross_user_document_isolation(
    browser: Browser,
    base_url: str,
    user_factory: Callable[..., dict[str, Any]],
    login_ui: Callable[[Page, str, str], None],
    sample_pdf_path: Path,
) -> None:
    """User B cannot see documents owned by User A without an explicit share."""
    user_a = user_factory(role="user")
    user_b = user_factory(role="user")

    # User A uploads document in context A
    context_a = browser.new_context()
    page_a = context_a.new_page()
    login_ui(page_a, user_a["username"], user_a["password"])
    page_a.wait_for_selector("#nav-documents", state="visible")

    page_a.click("#nav-documents")
    page_a.click("#btn-open-upload-modal")
    page_a.locator("#modal-file-picker").set_input_files(str(sample_pdf_path))
    page_a.locator(".modal-footer button.btn-primary").click()
    page_a.wait_for_selector("#upload-modal-title", state="hidden")
    expect(page_a.locator("#documents-table-container")).to_contain_text("minimal_valid.pdf")
    context_a.close()

    # User B logs in in context B
    context_b = browser.new_context()
    page_b = context_b.new_page()
    login_ui(page_b, user_b["username"], user_b["password"])
    page_b.wait_for_selector("#nav-documents", state="visible")

    page_b.click("#nav-documents")
    page_b.wait_for_selector("#documents-table-container", state="visible")

    # User B must NOT see User A's document
    expect(page_b.locator("#documents-table-container")).not_to_contain_text("minimal_valid.pdf")
    expect(page_b.locator("#documents-table-container")).to_contain_text("No documents")
    context_b.close()
