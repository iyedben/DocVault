/**
 * Document management API service for DocVault.
 * Interacts with /api/v1/documents endpoints for listing, uploading,
 * downloading, and deleting user documents.
 */

import { apiFetch, MAX_DOCUMENT_SIZE_BYTES } from "./api.js";

export { MAX_DOCUMENT_SIZE_BYTES };

/**
 * Format bytes into human-readable string (e.g. "1.2 MiB", "450 KiB").
 *
 * @param {number} bytes
 * @returns {string}
 */
export function formatFileSize(bytes) {
  if (typeof bytes !== "number" || isNaN(bytes) || bytes < 0) {
    return "0 B";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

/**
 * Format ISO datetime string into user-friendly localized format.
 *
 * @param {string} isoString
 * @returns {string}
 */
export function formatDateTime(isoString) {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return String(isoString);
    return d.toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(isoString);
  }
}

/**
 * Fetch list of all accessible documents for the current user.
 *
 * @returns {Promise<{ success: boolean, documents?: Array, status: number, error?: string }>}
 */
export async function listDocuments() {
  try {
    const response = await apiFetch("/api/v1/documents", {
      method: "GET",
    });

    if (response.status === 200) {
      const data = await response.json();
      return { success: true, documents: Array.isArray(data) ? data : [], status: 200 };
    }

    let detail = "Failed to load documents.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Unable to reach server to retrieve documents.",
    };
  }
}

/**
 * Upload a PDF file to the DocVault backend.
 *
 * @param {File} file
 * @returns {Promise<{ success: boolean, document?: object, status: number, error?: string }>}
 */
export async function uploadDocument(file) {
  if (!file) {
    return { success: false, status: 400, error: "No file selected." };
  }

  // Client validation: PDF extension/type check
  const isPdf =
    file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf");
  if (!isPdf) {
    return {
      success: false,
      status: 422,
      error: "Only valid PDF documents are supported (.pdf).",
    };
  }

  // Client validation: Empty file check
  if (file.size === 0) {
    return {
      success: false,
      status: 422,
      error: "Selected file is empty (0 bytes).",
    };
  }

  // Client validation: Size limit check (10 MiB)
  if (file.size > MAX_DOCUMENT_SIZE_BYTES) {
    return {
      success: false,
      status: 413,
      error: `File size exceeds the 10 MiB limit (${formatFileSize(file.size)}).`,
    };
  }

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await apiFetch("/api/v1/documents", {
      method: "POST",
      body: formData,
    });

    if (response.status === 201) {
      const data = await response.json();
      return { success: true, document: data, status: 201 };
    }

    let detail = "Document upload rejected.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error during upload. Please verify connectivity.",
    };
  }
}

/**
 * Download a document by ID and trigger browser file save.
 *
 * @param {string} documentId
 * @param {string} [fallbackFilename="document.pdf"]
 * @returns {Promise<{ success: boolean, status: number, error?: string }>}
 */
export async function downloadDocument(documentId, fallbackFilename = "document.pdf") {
  if (!documentId) {
    return { success: false, status: 400, error: "Invalid document ID." };
  }

  try {
    const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(documentId)}/download`, {
      method: "GET",
      headers: {
        Accept: "application/pdf, application/octet-stream, */*",
      },
    });

    if (response.status === 200) {
      // Determine filename from Content-Disposition header if available
      let filename = fallbackFilename;
      const disposition = response.headers.get("Content-Disposition");
      if (disposition) {
        const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
        if (utf8Match && utf8Match[1]) {
          try {
            filename = decodeURIComponent(utf8Match[1]);
          } catch {
            // Ignore decoding failure
          }
        } else {
          const simpleMatch = disposition.match(/filename="?([^";]+)"?/i);
          if (simpleMatch && simpleMatch[1]) {
            filename = simpleMatch[1];
          }
        }
      }

      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);

      const downloadLink = document.createElement("a");
      downloadLink.href = objectUrl;
      downloadLink.download = filename || "document.pdf";
      downloadLink.rel = "noopener";
      document.body.appendChild(downloadLink);
      downloadLink.click();
      document.body.removeChild(downloadLink);

      // Revoke temporary object URL after download is triggered
      setTimeout(() => {
        try {
          URL.revokeObjectURL(objectUrl);
        } catch {
          // Ignore revocation failure
        }
      }, 1500);

      return { success: true, status: 200 };
    }

    let detail = "Download failed.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error during download. Please check connectivity.",
    };
  }
}

/**
 * Permanently delete an owned document.
 *
 * @param {string} documentId
 * @returns {Promise<{ success: boolean, status: number, error?: string }>}
 */
export async function deleteDocument(documentId) {
  if (!documentId) {
    return { success: false, status: 400, error: "Invalid document ID." };
  }

  try {
    const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(documentId)}`, {
      method: "DELETE",
    });

    if (response.status === 204) {
      return { success: true, status: 204 };
    }

    let detail = "Failed to delete document.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error during deletion. The document was not deleted.",
    };
  }
}

/**
 * Search active users by partial username match for sharing.
 *
 * @param {string} query Minimum 2 characters
 * @returns {Promise<{ success: boolean, users?: Array<{ id: string, username: string }>, status: number, error?: string }>}
 */
export async function lookupUsers(query) {
  const cleanQuery = String(query || "").trim();
  if (cleanQuery.length < 2) {
    return { success: false, status: 422, error: "Search query must be at least 2 characters." };
  }

  try {
    const response = await apiFetch(`/api/v1/users/lookup?username=${encodeURIComponent(cleanQuery)}`, {
      method: "GET",
    });

    if (response.status === 200) {
      const data = await response.json();
      return { success: true, users: Array.isArray(data) ? data : [], status: 200 };
    }

    let detail = "User search failed.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Unable to reach server to search users.",
    };
  }
}

/**
 * List all users who currently have access to an owned document.
 *
 * @param {string} documentId
 * @returns {Promise<{ success: boolean, shares?: Array<{ user_id: string, username: string, created_at: string }>, status: number, error?: string }>}
 */
export async function listDocumentShares(documentId) {
  if (!documentId) {
    return { success: false, status: 400, error: "Invalid document ID." };
  }

  try {
    const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(documentId)}/shares`, {
      method: "GET",
    });

    if (response.status === 200) {
      const data = await response.json();
      return { success: true, shares: Array.isArray(data) ? data : [], status: 200 };
    }

    let detail = "Failed to load shares.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Unable to reach server to load document shares.",
    };
  }
}

/**
 * Grant document access to a specified user.
 *
 * @param {string} documentId
 * @param {string} userId
 * @returns {Promise<{ success: boolean, share?: object, status: number, error?: string }>}
 */
export async function grantDocumentShare(documentId, userId) {
  if (!documentId || !userId) {
    return { success: false, status: 400, error: "Invalid document or user ID." };
  }

  try {
    const response = await apiFetch(
      `/api/v1/documents/${encodeURIComponent(documentId)}/shares/${encodeURIComponent(userId)}`,
      {
        method: "PUT",
      }
    );

    if (response.status === 201) {
      const data = await response.json();
      return { success: true, share: data, status: 201 };
    }

    let detail = "Failed to grant document share.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error while granting share. Share was not granted.",
    };
  }
}

/**
 * Revoke document access for a specified user.
 *
 * @param {string} documentId
 * @param {string} userId
 * @returns {Promise<{ success: boolean, status: number, error?: string }>}
 */
export async function revokeDocumentShare(documentId, userId) {
  if (!documentId || !userId) {
    return { success: false, status: 400, error: "Invalid document or user ID." };
  }

  try {
    const response = await apiFetch(
      `/api/v1/documents/${encodeURIComponent(documentId)}/shares/${encodeURIComponent(userId)}`,
      {
        method: "DELETE",
      }
    );

    if (response.status === 204) {
      return { success: true, status: 204 };
    }

    let detail = "Failed to revoke document share.";
    try {
      const err = await response.json();
      if (err?.detail) detail = err.detail;
    } catch {
      // Non-JSON response
    }

    return { success: false, status: response.status, error: detail };
  } catch {
    return {
      success: false,
      status: 0,
      error: "Network error while revoking share. Share was not revoked.",
    };
  }
}
