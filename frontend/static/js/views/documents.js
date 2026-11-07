/**
 * Documents Workspace view for DocVault.
 * Safe DOM construction for listing, filtering, uploading, downloading,
 * and deleting PDF documents.
 */

import { createElement, createSvgIcon, clearElement } from "../utils/dom.js";
import { showAlert } from "../components/alerts.js";
import { showLoading } from "../components/loading.js";
import {
  listDocuments,
  uploadDocument,
  downloadDocument,
  deleteDocument,
  formatFileSize,
  formatDateTime,
  MAX_DOCUMENT_SIZE_BYTES,
} from "../documents.js";

// SVG Icon Path Data
const ICON_PDF =
  "M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z";
const ICON_UPLOAD =
  "M9 16h6v-6h4l-7-7-7 7h4zm-4 2h14v2H5z";
const ICON_CLOUD_UPLOAD =
  "M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM14 13v4h-4v-4H7l5-5 5 5h-3z";
const ICON_DOWNLOAD =
  "M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z";
const ICON_TRASH =
  "M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z";
const ICON_REFRESH =
  "M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z";
const ICON_SEARCH =
  "M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z";
const ICON_CLOSE =
  "M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z";

/**
 * Render the main Document Workspace view.
 *
 * @param {HTMLElement} container
 */
export async function renderDocumentsView(container) {
  clearElement(container);

  let allDocuments = [];
  let activeFilter = "all"; // "all" | "owner" | "shared"
  let searchQuery = "";

  // 1. Workspace Header and Title
  const header = createElement(
    "div",
    { className: "d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3 mb-4" },
    createElement(
      "div",
      {},
      createElement("h3", { className: "fw-bold mb-1" }, "Document Workspace"),
      createElement(
        "p",
        { className: "text-muted small mb-0" },
        "Securely upload, store, download, and manage your protected PDF files."
      )
    ),
    createElement(
      "div",
      { className: "d-flex align-items-center gap-2" },
      createElement(
        "button",
        {
          type: "button",
          className: "btn btn-outline-secondary btn-sm d-flex align-items-center gap-1",
          id: "btn-refresh-docs",
          title: "Refresh documents list",
          onclick: () => loadDocumentList(),
        },
        createSvgIcon(ICON_REFRESH, "", 16),
        createElement("span", {}, "Refresh")
      ),
      createElement(
        "button",
        {
          type: "button",
          className: "btn btn-primary btn-sm d-flex align-items-center gap-1",
          id: "btn-open-upload-modal",
          title: "Upload a PDF document",
          onclick: () => openUploadModal(),
        },
        createSvgIcon(ICON_UPLOAD, "", 16),
        createElement("span", { className: "fw-medium" }, "Upload Document")
      )
    )
  );

  // 2. Filter & Search Controls Bar
  const searchInput = createElement("input", {
    type: "search",
    className: "form-control form-control-sm",
    placeholder: "Filter documents by name...",
    id: "docs-search-input",
    oninput: (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      renderTableRows();
    },
  });

  const searchWrapper = createElement(
    "div",
    { className: "position-relative flex-grow-1 dv-search-wrapper" },
    searchInput
  );

  const filterTabs = createElement(
    "div",
    { className: "btn-group btn-group-sm", role: "group", "aria-label": "Filter documents" },
    createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-primary active",
        id: "filter-all",
        onclick: (e) => setFilter("all", e.currentTarget),
      },
      "All"
    ),
    createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-primary",
        id: "filter-owner",
        onclick: (e) => setFilter("owner", e.currentTarget),
      },
      "My Documents"
    ),
    createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-primary",
        id: "filter-shared",
        onclick: (e) => setFilter("shared", e.currentTarget),
      },
      "Shared with me"
    )
  );

  function setFilter(newFilter, btn) {
    activeFilter = newFilter;
    const buttons = filterTabs.querySelectorAll("button");
    buttons.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    renderTableRows();
  }

  const controlsBar = createElement(
    "div",
    { className: "dv-card p-3 mb-4 d-flex flex-column flex-md-row justify-content-between align-items-stretch align-items-md-center gap-3" },
    filterTabs,
    searchWrapper
  );

  // 3. Document Content Container
  const contentCard = createElement(
    "div",
    { className: "dv-card shadow-sm mb-4", id: "documents-table-container" }
  );

  container.appendChild(header);
  container.appendChild(controlsBar);
  container.appendChild(contentCard);

  // Load document list from backend
  await loadDocumentList();

  async function loadDocumentList() {
    showLoading(contentCard, "Loading documents from secure storage...");
    const result = await listDocuments();

    if (!result.success) {
      clearElement(contentCard);
      const errorBanner = createElement(
        "div",
        { className: "p-4 text-center" },
        createElement(
          "div",
          { className: "alert alert-danger d-inline-block text-start mb-3" },
          createElement("strong", {}, "Error loading documents: "),
          createElement("span", {}, result.error || "Unknown server response")
        ),
        createElement(
          "div",
          {},
          createElement(
            "button",
            {
              type: "button",
              className: "btn btn-outline-primary btn-sm",
              onclick: () => loadDocumentList(),
            },
            "Try Again"
          )
        )
      );
      contentCard.appendChild(errorBanner);
      return;
    }

    allDocuments = result.documents || [];
    renderTableRows();
  }

  function renderTableRows() {
    clearElement(contentCard);

    // Apply active filter & search query
    let filtered = allDocuments;
    if (activeFilter === "owner") {
      filtered = filtered.filter((d) => d.access === "owner");
    } else if (activeFilter === "shared") {
      filtered = filtered.filter((d) => d.access === "shared");
    }

    if (searchQuery) {
      filtered = filtered.filter((d) =>
        (d.display_filename || "").toLowerCase().includes(searchQuery)
      );
    }

    // Update filter counts
    const countAll = allDocuments.length;
    const countOwner = allDocuments.filter((d) => d.access === "owner").length;
    const countShared = allDocuments.filter((d) => d.access === "shared").length;

    const bAll = filterTabs.querySelector("#filter-all");
    const bOwner = filterTabs.querySelector("#filter-owner");
    const bShared = filterTabs.querySelector("#filter-shared");

    if (bAll) bAll.textContent = `All (${countAll})`;
    if (bOwner) bOwner.textContent = `My Documents (${countOwner})`;
    if (bShared) bShared.textContent = `Shared with me (${countShared})`;

    // Empty state
    if (filtered.length === 0) {
      const emptyContainer = createElement(
        "div",
        { className: "p-5 text-center" },
        createElement(
          "div",
          { className: "text-muted mb-3" },
          createSvgIcon(ICON_PDF, "text-secondary opacity-50", 48)
        ),
        createElement(
          "h5",
          { className: "fw-bold text-secondary mb-1" },
          allDocuments.length === 0 ? "No documents uploaded yet" : "No matching documents"
        ),
        createElement(
          "p",
          { className: "text-muted small mb-3 dv-constrained-text mx-auto" },
          allDocuments.length === 0
            ? "Your vault is currently empty. Upload your first PDF file (up to 10 MiB) to store it securely."
            : "No documents matched your search query. Try clearing the filter."
        ),
        allDocuments.length === 0
          ? createElement(
              "button",
              {
                type: "button",
                className: "btn btn-primary btn-sm d-inline-flex align-items-center gap-1",
                onclick: () => openUploadModal(),
              },
              createSvgIcon(ICON_UPLOAD, "", 16),
              createElement("span", {}, "Upload Document")
            )
          : createElement(
              "button",
              {
                type: "button",
                className: "btn btn-outline-secondary btn-sm",
                onclick: () => {
                  searchInput.value = "";
                  searchQuery = "";
                  renderTableRows();
                },
              },
              "Clear Search"
            )
      );
      contentCard.appendChild(emptyContainer);
      return;
    }

    // Populated table
    const table = createElement(
      "table",
      { className: "table table-hover align-middle mb-0 dv-documents-table" },
      createElement(
        "thead",
        { className: "table-light text-muted small text-uppercase" },
        createElement(
          "tr",
          {},
          createElement("th", { scope: "col", className: "ps-3 py-3" }, "Document"),
          createElement("th", { scope: "col", className: "py-3" }, "Size"),
          createElement("th", { scope: "col", className: "py-3" }, "Uploaded"),
          createElement("th", { scope: "col", className: "py-3" }, "Access"),
          createElement("th", { scope: "col", className: "pe-3 py-3 text-end" }, "Actions")
        )
      )
    );

    const tbody = createElement("tbody", {});

    for (const doc of filtered) {
      const isOwner = doc.access === "owner";

      // File icon and name cell
      const nameCell = createElement(
        "td",
        { className: "ps-3 py-3" },
        createElement(
          "div",
          { className: "d-flex align-items-center gap-2" },
          createElement(
            "div",
            { className: "dv-doc-icon-wrapper text-danger flex-shrink-0" },
            createSvgIcon(ICON_PDF, "", 24)
          ),
          createElement(
            "div",
            { className: "text-truncate", title: doc.display_filename },
            createElement("span", { className: "fw-semibold text-dark d-block text-truncate" }, doc.display_filename),
            createElement("span", { className: "text-muted small" }, doc.media_type || "application/pdf")
          )
        )
      );

      // File size cell
      const sizeCell = createElement(
        "td",
        { className: "py-3 text-nowrap small text-muted" },
        formatFileSize(doc.file_size)
      );

      // Upload date cell
      const dateCell = createElement(
        "td",
        { className: "py-3 text-nowrap small text-muted" },
        formatDateTime(doc.created_at)
      );

      // Access badge cell
      const badge = createElement(
        "span",
        {
          className: `badge ${isOwner ? "text-bg-primary" : "text-bg-info text-dark"} text-uppercase px-2 py-1 small`,
        },
        isOwner ? "Owner" : "Shared"
      );
      const accessCell = createElement("td", { className: "py-3" }, badge);

      // Actions cell
      const downloadBtn = createElement(
        "button",
        {
          type: "button",
          className: "btn btn-outline-primary btn-sm d-inline-flex align-items-center gap-1",
          title: `Download ${doc.display_filename}`,
          onclick: async (e) => {
            const btn = e.currentTarget;
            btn.disabled = true;
            try {
              const dlRes = await downloadDocument(doc.id, doc.display_filename);
              if (!dlRes.success) {
                showAlert(dlRes.error || "Download failed.", "danger", 5000);
              }
            } finally {
              btn.disabled = false;
            }
          },
        },
        createSvgIcon(ICON_DOWNLOAD, "", 14),
        createElement("span", { className: "d-none d-md-inline" }, "Download")
      );

      const actionButtons = [downloadBtn];

      if (isOwner) {
        const deleteBtn = createElement(
          "button",
          {
            type: "button",
            className: "btn btn-outline-danger btn-sm d-inline-flex align-items-center gap-1 ms-1",
            title: `Delete ${doc.display_filename}`,
            onclick: () => openDeleteModal(doc),
          },
          createSvgIcon(ICON_TRASH, "", 14),
          createElement("span", { className: "d-none d-md-inline" }, "Delete")
        );
        actionButtons.push(deleteBtn);
      }

      const actionsCell = createElement(
        "td",
        { className: "pe-3 py-3 text-end text-nowrap" },
        ...actionButtons
      );

      const row = createElement(
        "tr",
        { id: `doc-row-${doc.id}` },
        nameCell,
        sizeCell,
        dateCell,
        accessCell,
        actionsCell
      );

      tbody.appendChild(row);
    }

    table.appendChild(tbody);

    const responsiveWrapper = createElement("div", { className: "table-responsive mb-0" }, table);
    contentCard.appendChild(responsiveWrapper);
  }

  // -------------------------------------------------------------------------
  // Modal Handlers: Upload & Delete
  // -------------------------------------------------------------------------

  function openUploadModal() {
    let selectedFile = null;

    const modalBackdrop = createElement("div", {
      className: "dv-modal-backdrop",
      onclick: (e) => {
        if (e.target === modalBackdrop) closeModal();
      },
    });

    const modalTitle = createElement("h5", { className: "fw-bold mb-0", id: "upload-modal-title" }, "Upload Document");

    const closeBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn-close",
        "aria-label": "Close",
        onclick: closeModal,
      }
    );

    const modalHeader = createElement(
      "div",
      { className: "modal-header d-flex justify-content-between align-items-center p-3 border-bottom" },
      modalTitle,
      closeBtn
    );

    // Dropzone Elements
    const fileInput = createElement("input", {
      type: "file",
      accept: "application/pdf,.pdf",
      className: "d-none",
      id: "modal-file-picker",
      onchange: (e) => {
        if (e.target.files && e.target.files[0]) {
          handleFileSelected(e.target.files[0]);
        }
      },
    });

    const dropzoneContent = createElement(
      "div",
      { className: "text-center py-4 px-3" },
      createSvgIcon(ICON_CLOUD_UPLOAD, "text-primary mb-3", 44),
      createElement("h6", { className: "fw-semibold mb-1" }, "Drag & drop your PDF here"),
      createElement("p", { className: "text-muted small mb-2" }, "or click anywhere to browse local files"),
      createElement("span", { className: "badge bg-secondary bg-opacity-10 text-secondary" }, "Max: 10 MiB • PDF Only")
    );

    const dropzone = createElement(
      "div",
      {
        className: "dv-dropzone mb-3",
        role: "button",
        tabIndex: "0",
        onclick: () => fileInput.click(),
        onkeydown: (e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            fileInput.click();
          }
        },
        ondragover: (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropzone.classList.add("dv-dragover");
        },
        ondragleave: (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropzone.classList.remove("dv-dragover");
        },
        ondrop: (e) => {
          e.preventDefault();
          e.stopPropagation();
          dropzone.classList.remove("dv-dragover");
          if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelected(e.dataTransfer.files[0]);
          }
        },
      },
      fileInput,
      dropzoneContent
    );

    // Selected file display card
    const selectedFileCard = createElement(
      "div",
      { className: "dv-selected-file-card p-3 mb-3 d-none border rounded bg-light" }
    );

    // Error alert container inside modal
    const modalAlertArea = createElement("div", { className: "mb-3 d-none" });

    function setModalError(msg) {
      clearElement(modalAlertArea);
      if (msg) {
        modalAlertArea.className = "alert alert-danger small py-2 px-3 mb-3";
        modalAlertArea.textContent = msg;
        modalAlertArea.classList.remove("d-none");
      } else {
        modalAlertArea.classList.add("d-none");
      }
    }

    function handleFileSelected(file) {
      setModalError("");

      // Validate PDF type
      const isPdf =
        file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf");
      if (!isPdf) {
        setModalError("Invalid file type. Only PDF documents are allowed.");
        selectedFile = null;
        updateSelectedView();
        return;
      }

      // Validate empty file
      if (file.size === 0) {
        setModalError("Selected file is empty (0 bytes).");
        selectedFile = null;
        updateSelectedView();
        return;
      }

      // Validate size limit (10 MiB)
      if (file.size > MAX_DOCUMENT_SIZE_BYTES) {
        setModalError(
          `File size (${formatFileSize(file.size)}) exceeds the maximum 10 MiB limit.`
        );
        selectedFile = null;
        updateSelectedView();
        return;
      }

      selectedFile = file;
      updateSelectedView();
    }

    function updateSelectedView() {
      clearElement(selectedFileCard);
      if (!selectedFile) {
        selectedFileCard.classList.add("d-none");
        dropzone.classList.remove("d-none");
        submitBtn.disabled = true;
        return;
      }

      dropzone.classList.add("d-none");
      selectedFileCard.classList.remove("d-none");
      submitBtn.disabled = false;

      const fileInfo = createElement(
        "div",
        { className: "d-flex justify-content-between align-items-center" },
        createElement(
          "div",
          { className: "d-flex align-items-center gap-2 text-truncate" },
          createSvgIcon(ICON_PDF, "text-danger flex-shrink-0", 24),
          createElement(
            "div",
            { className: "text-truncate" },
            createElement("span", { className: "fw-semibold text-dark d-block text-truncate small" }, selectedFile.name),
            createElement("span", { className: "text-muted small" }, formatFileSize(selectedFile.size))
          )
        ),
        createElement(
          "button",
          {
            type: "button",
            className: "btn btn-outline-secondary btn-sm",
            onclick: () => {
              selectedFile = null;
              fileInput.value = "";
              updateSelectedView();
            },
          },
          "Change"
        )
      );

      selectedFileCard.appendChild(fileInfo);
    }

    // Modal Footer
    const cancelBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-secondary btn-sm",
        onclick: closeModal,
      },
      "Cancel"
    );

    const submitBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-primary btn-sm d-flex align-items-center gap-1",
        disabled: true,
        onclick: async () => {
          if (!selectedFile) return;

          submitBtn.disabled = true;
          cancelBtn.disabled = true;
          closeBtn.disabled = true;
          submitBtn.textContent = "Uploading...";

          setModalError("");

          const res = await uploadDocument(selectedFile);
          if (res.success) {
            closeModal();
            showAlert(`"${res.document?.display_filename || "Document"}" uploaded successfully.`, "success", 4000);
            await loadDocumentList();
          } else {
            setModalError(res.error || "Upload failed. Please try again.");
            submitBtn.disabled = false;
            cancelBtn.disabled = false;
            closeBtn.disabled = false;
            submitBtn.textContent = "Upload";
          }
        },
      },
      "Upload"
    );

    const modalFooter = createElement(
      "div",
      { className: "modal-footer p-3 border-top d-flex justify-content-end gap-2" },
      cancelBtn,
      submitBtn
    );

    const modalContent = createElement(
      "div",
      { className: "dv-modal-dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": "upload-modal-title" },
      modalHeader,
      createElement("div", { className: "modal-body p-4" }, dropzone, selectedFileCard, modalAlertArea),
      modalFooter
    );

    modalBackdrop.appendChild(modalContent);
    document.body.appendChild(modalBackdrop);

    function onKeyDown(e) {
      if (e.key === "Escape") closeModal();
    }
    document.addEventListener("keydown", onKeyDown);

    function closeModal() {
      document.removeEventListener("keydown", onKeyDown);
      if (modalBackdrop.parentNode) {
        modalBackdrop.parentNode.removeChild(modalBackdrop);
      }
    }
  }

  function openDeleteModal(doc) {
    const modalBackdrop = createElement("div", {
      className: "dv-modal-backdrop",
      onclick: (e) => {
        if (e.target === modalBackdrop) closeModal();
      },
    });

    const modalTitle = createElement("h5", { className: "fw-bold text-danger mb-0", id: "delete-modal-title" }, "Delete Document");

    const closeBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn-close",
        "aria-label": "Close",
        onclick: closeModal,
      }
    );

    const modalHeader = createElement(
      "div",
      { className: "modal-header d-flex justify-content-between align-items-center p-3 border-bottom" },
      modalTitle,
      closeBtn
    );

    const alertArea = createElement("div", { className: "mb-3 d-none" });

    const docCard = createElement(
      "div",
      { className: "p-3 mb-3 border rounded bg-light d-flex align-items-center gap-2" },
      createSvgIcon(ICON_PDF, "text-danger flex-shrink-0", 24),
      createElement(
        "div",
        { className: "text-truncate" },
        createElement("strong", { className: "d-block text-truncate" }, doc.display_filename),
        createElement("span", { className: "text-muted small" }, formatFileSize(doc.file_size))
      )
    );

    const modalBody = createElement(
      "div",
      { className: "modal-body p-4" },
      createElement(
        "p",
        { className: "text-muted small mb-3" },
        "Are you sure you want to permanently delete this document? This action will permanently remove the file from secure storage and revoke all active shares. This cannot be undone."
      ),
      docCard,
      alertArea
    );

    const cancelBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-outline-secondary btn-sm",
        onclick: closeModal,
      },
      "Cancel"
    );

    const deleteBtn = createElement(
      "button",
      {
        type: "button",
        className: "btn btn-danger btn-sm",
        onclick: async () => {
          deleteBtn.disabled = true;
          cancelBtn.disabled = true;
          closeBtn.disabled = true;
          deleteBtn.textContent = "Deleting...";

          clearElement(alertArea);
          alertArea.classList.add("d-none");

          const res = await deleteDocument(doc.id);
          if (res.success) {
            closeModal();
            showAlert(`"${doc.display_filename}" was permanently deleted.`, "info", 4000);
            await loadDocumentList();
          } else {
            alertArea.className = "alert alert-danger small py-2 px-3 mb-3";
            alertArea.textContent = res.error || "Failed to delete document. Please try again.";
            alertArea.classList.remove("d-none");
            deleteBtn.disabled = false;
            cancelBtn.disabled = false;
            closeBtn.disabled = false;
            deleteBtn.textContent = "Delete Document";
          }
        },
      },
      "Delete Document"
    );

    const modalFooter = createElement(
      "div",
      { className: "modal-footer p-3 border-top d-flex justify-content-end gap-2" },
      cancelBtn,
      deleteBtn
    );

    const modalContent = createElement(
      "div",
      { className: "dv-modal-dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": "delete-modal-title" },
      modalHeader,
      modalBody,
      modalFooter
    );

    modalBackdrop.appendChild(modalContent);
    document.body.appendChild(modalBackdrop);

    function onKeyDown(e) {
      if (e.key === "Escape") closeModal();
    }
    document.addEventListener("keydown", onKeyDown);

    function closeModal() {
      document.removeEventListener("keydown", onKeyDown);
      if (modalBackdrop.parentNode) {
        modalBackdrop.parentNode.removeChild(modalBackdrop);
      }
    }
  }
}
