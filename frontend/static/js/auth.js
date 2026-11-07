/**
 * Authentication and session foundation for DocVault.
 * Phase B1: Infrastructure ready; user authentication planned for Phase B2.
 */

import { apiFetch } from "./api.js";

/**
 * Check backend API process health and database readiness.
 *
 * @returns {Promise<{ healthy: boolean, ready: boolean }>}
 */
export async function checkBackendStatus() {
  let healthy = false;
  let ready = false;

  try {
    const healthResp = await apiFetch("/health");
    healthy = healthResp.ok;
  } catch {
    healthy = false;
  }

  try {
    const readyResp = await apiFetch("/ready");
    ready = readyResp.ok;
  } catch {
    ready = false;
  }

  return { healthy, ready };
}
