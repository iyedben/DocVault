# Instructions for Codex sessions

## Project

DocVault is an academic secure document management and DevSecOps project. It is under active development and is not production-ready. The backend stack is Python 3.14, FastAPI, Pydantic, SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker and Docker Compose provide the local runtime. The planned browser client uses HTML, CSS, Bootstrap, and JavaScript; CI/CD and security/deployment tooling are roadmap items unless repository evidence shows otherwise.

## Repository conventions and architecture

- `backend/app/api/routes/`: FastAPI route modules; `api/dependencies.py` contains request authentication/authorization dependencies and `api/*schemas.py` contains request/response schemas.
- `backend/app/core/`: environment-backed configuration.
- `backend/app/db/`: SQLAlchemy base, engine, and session management.
- `backend/app/models/`: ORM models; `backend/migrations/versions/`: Alembic revisions.
- `backend/app/security/`: authentication and validation controls; `services/`: business rules; `storage/`: private file operations; `middleware/`: request-wide controls.
- `backend/tests/`: backend automated tests. `scripts/`: explicit operational or runtime validation helpers. `docs/`: phase records, plans, and handovers.
- Keep database schema changes in a new Alembic migration. Do not edit an already applied migration to change schema.
- Follow the existing small-module and typed Python style, pinned dependency conventions, and evidence-recording style. Keep phase plans distinct from results.

## Security requirements

- Inspect existing code and the current session/authentication model before implementing anything. Enforce authentication and authorization on the server for every protected operation; derive actor and owner from the authenticated session, never request-supplied identity, role, or permission data.
- Preserve least privilege: the API uses the application database role, while schema migrations use the separate migrator role. Use parameterized SQL/ORM operations.
- Preserve Argon2id password hashing, server-side opaque sessions, CSRF checks for cookie-authenticated state changes, and existing role safeguards.
- Treat filenames, IDs, MIME types, and file contents as untrusted. Keep document bytes outside the public web root, use opaque server-generated storage keys, bound request and file sizes, and avoid unsafe path operations.
- Return safe errors and avoid logging passwords, credentials, session/CSRF tokens, document bytes, or filesystem paths. Do not expose secrets in docs, command output, or generated artifacts.
- Do not grant administrators implicit document access unless an explicit project requirement and implementation authorize it.

## Coding and validation

- Read relevant docs, source, tests, Git status, and history before editing. Treat repository state as authoritative over stale summaries.
- Preserve existing user changes. Avoid unnecessary refactoring and keep edits within the requested scope.
- Add or adjust focused tests for behavior changes when requested or necessary to implement the task. Do not run broad/full suites unless asked; report exactly what was run and its actual result. Separate automated tests, static checks, and manual runtime evidence.
- Use the isolated project environment when available. Never infer that a passing test or runtime check occurred from test files, bytecode, or prior plans.
- Before finishing documentation or code changes, inspect the diff and run `git diff --check` when appropriate.

## Docker and runtime constraints

- Preserve the API container's non-root UID/GID 10001, read-only root filesystem, dropped capabilities, `no-new-privileges`, resource limits, and dedicated private persistent document volume.
- PostgreSQL is not host-published; it is on the internal database network. The API is loopback-published and uses its separate application access network. Do not weaken these boundaries casually.
- Keep `.env` and credentials out of Git, image build contexts, logs, and documentation. Do not remove or recreate persistent database/document volumes during setup or cleanup.
- Runtime observations are environment-specific. Verify Compose configuration or runtime only when relevant and safe; do not treat prior Phase 2 checks as validation of later application revisions.

## Git and change safety

- Never commit, push, reset, amend, or discard changes without explicit user authorization.
- Never overwrite or clean uncommitted user work. Inspect `git status` and diffs before edits and after them.
- Do not modify application source or migrations when a task is documentation-only. Keep generated or temporary files out of the repository unless explicitly required.

## Current verified project status — Phase B7

Phase B6 is finalized, committed, and pushed to `feature/frontend` (`431afb8`). Active development is on branch `feature/frontend` with baseline `431afb8`.

Phase B1, B2, B3, B4, B5, B6, and B7 add:
- Single-page application shell (`frontend/index.html`) using HTML5, CSS3, and vanilla JavaScript ES2022 modules.
- 100% locally vendored Bootstrap 5.3.3 (`bootstrap.min.css`, `bootstrap.bundle.min.js`) under MIT license with zero external CDN dependencies.
- FastAPI integration: `StaticFiles` mounted at `/static`, `GET /` serving `index.html` with `Cache-Control: no-cache`, and `/favicon.ico` handler.
- Strict Content Security Policy compatibility (`default-src 'self'`, `script-src 'self'`, `style-src 'self'`) with zero inline `<style>` or `<script>` tags and zero inline `style="..."` attributes.
- Safe DOM construction (`dom.js`) using `textContent` and `createElement` to prevent DOM XSS.
- Responsive layout with dark navy navigation (`#0f172a`), neutral workspace, global alert area, loading spinners, and role-aware navigation.
- Authentication and session management (`auth-state.js`, `api.js`, `auth.js`, `views/login.js`, `components/navbar.js`, `router.js`):
  - In-memory auth state with zero browser storage persistence.
  - Transparent single-flight CSRF token bootstrap (`POST /api/v1/auth/csrf`) preventing recovery race conditions.
  - Synchronizer `X-CSRF-Token` header injection on state-changing API requests.
  - Non-recursive 401 interception handling session expiration.
  - Accessible login view with card layout, password visibility toggle, double-submit protection, and server error handling.
  - Confirmed server-side session invalidation and cookie clearing on logout (`POST /api/v1/auth/logout`).
- Document management workspace (`documents.js`, `views/documents.js`, `app.css`, `router.js`):
  - Interactive document list with filter tabs (All, My Documents, Shared with me) and instant client-side search.
  - Drag-and-drop PDF upload modal with client-side 10 MiB size limit, PDF extension validation, and double-submit protection.
  - Authenticated streaming download with safe Content-Disposition filename parsing and `URL.revokeObjectURL` cleanup.
  - Document deletion confirmation dialog with owner verification and CSRF-protected deletion.
- Document sharing and user lookup (`documents.js`, `views/documents.js`, `app.css`):
  - Share action button displayed exclusively on owned documents (`access === "owner"`). Shared documents omit the button.
  - Interactive "Manage Document Sharing" modal with accessible dialog semantics (`role="dialog"`, `aria-modal="true"`, `aria-labelledby="share-modal-title"`, Escape/backdrop handling).
  - Debounced user search (300ms) querying `GET /api/v1/users/lookup?username=...` with sequence counter `currentSearchSeq` guarding against stale out-of-order responses, exclusion of self-sharing, and "Already shared" detection.
  - Granular access granting (`PUT /api/v1/documents/{id}/shares/{user_id}`) with CSRF protection, immediate list refresh, and 409 Conflict handling.
  - Active collaborators list (`GET /api/v1/documents/{id}/shares`) with formatted timestamps and CSRF-protected revocation (`DELETE /api/v1/documents/{id}/shares/{user_id}`).
- Account and security settings (`views/settings.js`, `auth.js`, `app.css`, `router.js`):
  - Dedicated account security settings view displaying authenticated username and role badge.
  - Accessible password-change form requiring current password, new password, and confirmation.
  - Keyboard-accessible password visibility toggles with SVG icons for all password fields.
  - Real-time client-side password policy validation (12–128 characters, 3 character categories, difference check, confirmation match).
  - Double-submit protection with loading indicators and field clearing on successful change.
  - Automatic CSRF token rotation synchronization via `POST /api/v1/auth/password` response and server-side multi-session invalidation.
- Role-gated administration console (`admin.js`, `views/admin.js`, `router.js`, `app.css`):
  - Strict client-side route guard in `router.js` backed by authoritative server-side `require_admin` dependency.
  - User roster table (`GET /api/v1/admin/users`) displaying user identity, role badge, account status, registration date, and `(You)` tag for self.
  - Metrics row providing instant breakdown: Total Accounts, Active Accounts, Administrators, and Standard Users.
  - Real-time client-side username search and status/role filtering buttons.
  - User provisioning modal (`POST /api/v1/admin/users`) with role selection, password policy checklist, visibility toggle, and 409 duplicate handling.
  - Account lifecycle toggles (`PATCH /api/v1/admin/users/{id}/status`) with confirmation dialogs, multi-session revocation, self-deactivation session termination, and final active administrator 409 Conflict protection.
  - Role assignment toggles (`PATCH /api/v1/admin/users/{id}/role`) supporting promotion to administrator and demotion to standard user with final administrator demotion safeguards.
  - Security audit logging architecture panel explaining structured JSON event streaming to container stdout (`docvault.security`) without insecure or fabricated database endpoints.
- Frontend polish, accessibility, security hardening & dashboard layout (`dom.js`, `index.html`, `app.css`, `router.js`, `views/documents.js`, `views/admin.js`, `components/navbar.js`, `test_frontend_polish_audit.py`):
  - Automated security audit: verified 0 occurrences of dangerous DOM sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`) and 0 occurrences of persistent client storage (`localStorage`, `sessionStorage`, `indexedDB`, client `document.cookie`).
  - Enhanced DOM utility: automatic `htmlFor` to `for` property normalization for robust form label binding; URL scheme sanitization for `href` and `src` attributes blocking dangerous protocols (`javascript:`, `data:`, `vbscript:`); and exported `trapFocus(container)` helper managing keyboard focus cycling (`Tab` / `Shift+Tab`) with clean unbind listeners.
  - Modal focus trapping and focus restoration: all interactive modal dialogs (upload, delete, share, admin provisioning, admin confirmation) now trap keyboard focus within the dialog and restore focus to the triggering element upon dismissal.
  - Accessible landmarks and skip links: added keyboard skip link (`.dv-skip-link` targeting `#main-content`), distinct `aria-label="Main Navigation"` on `<nav id="main-navbar">`, and `role="region" aria-label="Notifications" aria-live="polite"` on `#notification-area`.
  - Heading hierarchy and accessible controls: replaced non-standard `<h3>` with styled spans in stat cards under `<h2>` in admin view; added explicit accessible labels and titles to icon-only buttons (sign-out, close buttons).
  - Responsive modal design: bounded modal dialog height (`max-height: calc(100vh - 2rem)`) with scrollable body (`overflow-y: auto`) ensuring usability across compact mobile viewports.
  - Responsive dashboard layout refinement: expanded `.dv-main-container` from restrictive 1200px to responsive `max-width: 1600px` with `min-width: 0` and breakpoint-tailored padding (`2rem 2.5rem` on >=1400px, `1.5rem` on <=991px, `1rem` on <=767px); widened Platform Status table with `.dv-status-label-col` (32% label / 68% value) and `.table-responsive` wrapper; upgraded roadmap grid to two columns on desktop (`col-12 col-lg-6`) and one column on narrow screens with `.dv-roadmap-item` card styling; added `overflow-x: hidden` on body to prevent horizontal scrolling.
- Containerized packaging: `Dockerfile` copies `frontend/` into `/app/frontend` with non-root ownership (UID 10001).

Latest verified validation:
- Complete backend & frontend integration suite: **319 passed, 6 skipped** in 32.27s.
- Isolated PostgreSQL concurrency integration: **1 passed** in 0.72s.
- Isolated PostgreSQL document integration: **5 passed** on PostgreSQL 17.11 in 2.62s.
- Ruff: **passed cleanly with 0 errors**.
- Mypy (52 source files): **passed cleanly with 0 errors**.
- Whitespace check (`git diff --check`): **passed cleanly**.
- Live Docker container runtime check: verified `200 OK` on `/`, `/health`, `/ready`, `/static/js/utils/dom.js`, `/static/css/app.css`, and verified CSP / security headers.

Phase B roadmap: Phase B completed (B1–B7). Next phase: Phase C (Production Readiness, Deployment & CI/CD).

Known limitations: No malware scanning or sanitization; filesystem and database operations are not fully atomic. All Phase B7 work is on `feature/frontend` and uncommitted. Never commit, push, reset, or amend without explicit authorization.
