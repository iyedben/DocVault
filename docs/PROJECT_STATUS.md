# DocVault project status and handover

**Inspected:** 11 November 2026. **Branch:** `feature/container-security`. Baseline checkpoint `a7adbb19ebc1831002d258e851055e89b1f33e06` is committed on `main` (following sequential integration of PR #1, PR #2, PR #3, and PR #4). Dedicated branch `feature/container-security` contains Phase D4.2 Container Hardening, Vulnerability Validator, Debian snapshot zlib remediation, and Controlled Exception Register changes. This record distinguishes verified results from remaining limitations.

## Project and architecture

DocVault is an academic secure document management and DevSecOps project. Its backend is Python 3.13/FastAPI with SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker Compose runs PostgreSQL, a one-shot migration service, and the API. The API runs as UID/GID 10001 with a read-only root filesystem and a dedicated document volume; PostgreSQL is not host-published and the API binds to loopback. Application code is in `backend/app` (routes, configuration, database, models, security, services, storage, middleware); migrations and tests are in `backend/migrations` and `backend/tests`. Frontend code is in `frontend/` (SPA shell in `index.html`, vendored Bootstrap 5.3.3 in `static/vendor/` and `static/css/`, and modular ES2022 JavaScript in `static/js/`). CI/CD pipeline expansion and Kubernetes are subsequent roadmap items. The project is not production-ready.

Security architecture includes Argon2id, PostgreSQL-backed opaque server sessions, CSRF on authenticated state changes, role checks, separate app/migrator database accounts, private filesystem storage with generated keys, global security headers, CSRF token recovery, and strict Content Security Policy (`default-src 'self'`, `script-src 'self'`, `style-src 'self'`). Document access must be owner or explicit sharee; administrator role alone does not imply document access. Secrets are kept out of logs/docs and container/network boundaries are preserved.

## Completed phases and verified record

- **Phases 0–1:** environment audit, Docker installation, and isolated Compose smoke check are documented in their phase reports.
- **Phase 2A–2C:** Python development environment, PostgreSQL deployment, FastAPI health/readiness endpoints and Compose architecture are documented.
- **Phase 3:** identity, authentication, sessions, CSRF, RBAC, and administrator management are implemented and committed (`385d32d`).
- **Phase 4.1–4.4:** secure document management API (upload, download, metadata, deletion tombstone, sharing, PDF structural validation via `pypdf`, descriptor-relative private storage) is implemented and committed (`eedd07b`, `80e42e9`, `2cbbfff`).
- **Security workflow:** GitHub Actions Gitleaks and Semgrep automated checks committed (`2444557`).
- **Phase A — Backend API completion & security polish (Committed: `4db1553`):**
  - **A1 — CSRF bootstrap:** `POST /api/v1/auth/csrf` provides authenticated sessions with a freshly rotated CSRF token after browser reload. Validates origin and fetch metadata (`Sec-Fetch-Site`, `Sec-Fetch-Mode`), rejects cross-site/navigation requests, stores SHA-256 digest in PostgreSQL, and returns raw token to caller with `Cache-Control: private, no-store`.
  - **A2 — User lookup:** `GET /api/v1/users/lookup?username={query}` allows authenticated users to search active users for document sharing by case-insensitive partial match with minimum length and result limits.
  - **A3 — Global security headers:** `SecurityHeadersMiddleware` centralizes CSP (`default-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, conditional HSTS, and `Cache-Control: private, no-store` on API routes, with a documented development exception for `/docs` and `/redoc`.
  - **A4 — Self-service password change:** `POST /api/v1/auth/password` allows authenticated users to update their password with Argon2id current password verification, Pydantic password policy enforcement, atomic revocation of other active sessions, and CSRF token rotation on the active session.
  - **A5 — Testing & verification:** Complete backend suite passed with 246 passed, 6 skipped.
- **Phase B1 — Frontend Foundation & FastAPI Integration (Committed: `dbf1cfa`):**
  - **B1.1 — SPA Shell:** Modern HTML5/CSS3 application shell with dark navy navbar (`#0f172a`), responsive sidebar, main container, global alerts area, and loading states.
  - **B1.2 — Local Vendoring:** Bootstrap v5.3.3 (`bootstrap.min.css`, `bootstrap.bundle.min.js`) locally vendored under MIT license with verified SHA-256 digests in `frontend/static/vendor/VENDOR.md`. Zero external CDN requests.
  - **B1.3 — Vanilla JS Architecture:** Modular ES2022 modules (`app.js`, `api.js`, `auth.js`, `router.js`, `components/navbar.js`, `components/alerts.js`, `components/loading.js`, `utils/dom.js`). Safe DOM construction via `textContent` and `createElement` (strictly prohibiting `innerHTML` on untrusted data).
  - **B1.4 — FastAPI Integration:** `StaticFiles` mounted at `/static`, `GET /` serving `index.html` with `Cache-Control: no-cache`, `/favicon.ico` route, and non-shadowing routing order.
  - **B1.5 — Security Headers & CSP:** Verified full inheritance of `SecurityHeadersMiddleware` (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`). Zero inline scripts or styles.
  - **B1.6 — Docker Image & Runtime:** Updated `backend/Dockerfile` to copy `frontend/` into `/app/frontend` with non-root ownership (UID 10001). Rebuilt image `docvault-api:local` and verified live HTTP responses over loopback.
- **Phase B2 — Authentication & Session Integration (Committed: `b1e7e85`):**
  - **B2.1 — In-Memory Auth State:** `auth-state.js` maintains transient user metadata (`id`, `username`, `role`) and reactive lifecycle states (`initializing`, `anonymous`, `authenticated`, `logging_out`). Zero browser persistence (no `localStorage`, `sessionStorage`, or `IndexedDB`).
  - **B2.2 — Single-Flight CSRF Refresh & API Interception:** `api.js` provides single-flight promise deduplication for `POST /api/v1/auth/csrf` to prevent race conditions during concurrent recovery; automatically injects `X-CSRF-Token` on state-changing requests; intercepts 401 Unauthorized globally without recursive loops; synchronizes 403 CSRF token rejections.
  - **B2.3 — Login View & Safe DOM:** `views/login.js` provides an accessible card layout, username/password validation, password reveal toggle with SVG icons, client-side validation, accessible alert banners, and double-submit protection with loading spinner. All DOM manipulation uses `textContent` and `createElement` via `dom.js`.
  - **B2.4 — Reactive Role-Aware Navigation:** `components/navbar.js` renders brand, dynamic user pill (`username` + `role`), sign-out button, and role-gated navigation items (admin sees "Administration", standard user does not).
  - **B2.5 — Session Bootstrap, Route Guarding & Logout Safety:** `app.js` and `router.js` restore sessions on startup (`POST /csrf` -> `GET /me`); redirect unauthenticated route attempts to `/login`; prevent non-admin access to admin routes. `auth.js` enforces strict logout safety: clears local state only upon confirmed HTTP 204 (or reconciled 401); network and server failures retain authenticated state and display error alerts without creating false logout states.
  - **B2.6 — Zero-Automatic-Retry Policy & Explicit CSRF Handling:** `api.js` strictly prohibits automatic retries for state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`). Generic HTTP 403s are never retried and do not rotate CSRF tokens. Explicit `CSRF validation failed` responses synchronize the token in the background via single-flight `refreshCsrfToken()` for subsequent user actions while returning the error directly.
  - **B2.7 — Frontend Auth & Security Integration Test Suite:** Added `backend/tests/test_frontend_auth_integration.py` (16 test cases) testing anonymous guards, regular/admin login, session restoration, expired session failure, CSRF rotation on logout, server-side session invalidation, rate limiting (429), successful logout (204), network failure resilience, unexpected server failure (500) rollback, session restoration after failed logout, state-changing CSRF rejection without side effects, no duplicate execution, and generic 403 authorization denials without CSRF rotation.
- **Phase B3 — Document Management Workspace (Committed: `afe0108`):**
  - **B3.1 — Document Service:** `documents.js` provides API operations (`listDocuments`, `uploadDocument`, `downloadDocument`, `deleteDocument`) and formatting helpers (`formatFileSize`, `formatDateTime`).
  - **B3.2 — Workspace View:** `views/documents.js` provides a responsive document list, search bar, filter tabs (All, My Documents, Shared with me), and loading/empty/error/populated states.
  - **B3.3 — PDF Upload Modal:** Accessible dialog supporting drag-and-drop, standard file picker, client-side PDF type and 10 MiB size validation, double-submit protection with loading indicators, and post-upload list refresh.
  - **B3.4 — Secure Download:** Authenticated document download triggering browser download with Content-Disposition parsing and temporary object URL cleanup (`URL.revokeObjectURL`).
  - **B3.5 — Deletion Confirmation:** Accessible modal identifying the document filename and size, requiring user confirmation before invoking `DELETE /api/v1/documents/{id}` with `X-CSRF-Token`. Only document owners can initiate deletion.
  - **B3.6 — Document Integration Tests:** Added `backend/tests/test_frontend_document_integration.py` (13 test cases) covering anonymous guards, list retrieval, access types, upload validation (type and size), upload CSRF enforcement, download streaming and headers, unauthorized access rejection (404), owner deletion (204), non-owner rejection (404), and static module serving.
- **Phase B4 — Document Sharing & User Lookup (Committed: `26e35af`):**
  - **B4.1 — Sharing Client API:** `documents.js` adds `lookupUsers(query)`, `listDocumentShares(docId)`, `grantDocumentShare(docId, userId)`, and `revokeDocumentShare(docId, userId)`. All mutating requests inject `X-CSRF-Token` and enforce zero-retry on failure.
  - **B4.2 — Role-Aware Share Action:** `views/documents.js` renders a "Share" button exclusively on owned documents (`access === "owner"`). Shared documents omit the button.
  - **B4.3 — Interactive Sharing Modal:** Accessible modal (`role="dialog"`, `aria-modal="true"`, `aria-labelledby="share-modal-title"`, Escape/backdrop dismissal) providing real-time collaborator management.
  - **B4.4 — Debounced User Lookup with Race Guard:** Collaborator search with 300ms debouncing, sequence counter `currentSearchSeq` discarding stale out-of-order responses, exclusion of self-sharing, and "Already shared" detection.
  - **B4.5 — Granular Share Grants & Revocation:** Instant grant via `PUT /api/v1/documents/{id}/shares/{user_id}` and revocation via `DELETE /api/v1/documents/{id}/shares/{user_id}` with immediate feedback and list synchronization.
  - **B4.6 — Sharing Integration Tests:** Added `backend/tests/test_frontend_sharing_integration.py` (12 test cases) validating anonymous access denial (401), user lookup validation and inactive omission, empty and populated share listing, non-owner denial (404), duplicate share rejection (409), self-share rejection (422), nonexistent user rejection (404), owner revocation (204), recipient access update, non-owner/shared user modification rejection (404), and CSRF token enforcement (403).
- **Phase B5 — Self-Service Security Settings (Committed: `28a7221`):**
  - **B5.1 — Settings View Component:** `views/settings.js` provides dedicated account security management, displaying authenticated identity, role badge, session status, and password update card.
  - **B5.2 — Client Password Change Service:** `auth.js` implements `changePassword(currentPassword, newPassword)` dispatching `POST /api/v1/auth/password` with automatic `X-CSRF-Token` injection and zero-retry enforcement.
  - **B5.3 — Validation & Real-time Policy Checking:** Client validation enforcing 12–128 character bounds, 3 character categories (lowercase, uppercase, digit, symbol), difference check against current password, and confirmation mismatch prevention.
  - **B5.4 — Accessible Visibility Toggles:** Password visibility toggle controls for all password fields with accessible SVG icons (`ICON_EYE` / `ICON_EYE_SLASH`), ARIA labels, and keyboard focus retention.
  - **B5.5 — CSRF Token Rotation Synchronization:** Transparently captures the rotated CSRF token returned in `PasswordChangeResponse` and updates client in-memory state via `setCsrfToken` without requiring page reload.
  - **B5.6 — Multi-Session Invalidation:** Preserves current authenticated session while informing user and verifying that all other active user sessions across browsers/devices are revoked.
  - **B5.7 — Settings Integration Tests:** Added `backend/tests/test_frontend_settings_integration.py` (10 test cases) covering anonymous guards, identity retrieval, successful password update, invalid current password rejection (400), policy validation (422), mismatch prevention, CSRF enforcement (403), duplicate submit blocking via token rotation, multi-session revocation verification, and static module serving.
- **Phase B6 — Role-Gated Administration Console (Committed: `431afb8`):**
  - **B6.1 — Admin Service API:** `admin.js` implements `listAdminUsers()`, `provisionAdminUser({ username, password, role })`, `setUserActiveStatus(userId, isActive)`, and `setUserRole(userId, newRole)` with input validation and zero automatic retries.
  - **B6.2 — Route Protection & Authorization Guard:** Strict client-side route guard in `router.js` backed by authoritative server-side `require_admin` dependency; redirects or alerts non-admin users.
  - **B6.3 — User Roster Workspace:** `views/admin.js` renders a responsive user roster with live search, status filters (All, Active, Deactivated), role filters (All, Admins, Users), and quick metrics row (Total, Active, Admins, Users).
  - **B6.4 — User Provisioning Modal:** Accessible dialog (`role="dialog"`, `aria-modal="true"`) supporting user creation, role assignment, password policy checklist, visibility toggle, double-submit protection, and 409 Conflict handling.
  - **B6.5 — Sensitive Action Confirmation Modals:** Reusable confirmation dialogs for account deactivation, reactivation, role promotion, and role demotion. Includes clear warnings for self-deactivation and self-demotion.
  - **B6.6 — Multi-Session Revocation & Final Admin Safeguards:** Account deactivation triggers server-side session revocation across all devices. Gracefully handles 409 Conflict when attempting to deactivate or demote the final active administrator. Self-deactivation cleanly clears the session cookie and transitions client state to anonymous.
  - **B6.7 — Security Audit Architecture Review:** Transparent informational panel detailing real-time JSON security audit logging to container stdout (`docvault.security`) without fabricating non-existent database endpoints.
  - **B6.8 — Admin Integration Test Suite:** Added `backend/tests/test_frontend_admin_integration.py` (10 test cases) covering anonymous denial (401), ordinary user denial (403), roster retrieval, user provisioning, validation/conflict handling (409/422), activation/deactivation, final admin protection, role lifecycle, self-deactivation cookie clearing, and static asset delivery with CSP.
- **Phase B7 — Frontend Polish & Security Audit (Committed: `beda2e7`):**
  - **B7.1 — Automated Client Security Audit:** Regex and structural audit confirming zero dangerous DOM APIs (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`) and zero client-side storage persistence (`localStorage`, `sessionStorage`, `indexedDB`, client `document.cookie`).
  - **B7.2 — Enhanced DOM Safeguards:** `dom.js` updated with `htmlFor` normalization to `for` attribute for accessible form labels; URL scheme validation for `href` and `src` attributes blocking dangerous protocols (`javascript:`, `data:`, `vbscript:`); and exported `trapFocus(container)` utility managing keyboard focus cycling (`Tab` / `Shift+Tab`) with clean unbind listeners.
  - **B7.3 — Dialog Focus Trapping & Restoration:** Modal dialogs across document workspace (upload, delete, share) and admin console (provision, confirmation) now trap keyboard focus within the dialog container and restore focus to the triggering element upon dismissal.
  - **B7.4 — Accessible Landmarks & Skip Link:** Single-page shell (`index.html`) equipped with `.dv-skip-link` targeting `#main-content`, `aria-label="Main Navigation"` on `<nav id="main-navbar">`, and `role="region" aria-label="Notifications" aria-live="polite"` on `#notification-area`.
  - **B7.5 — Heading Hierarchy & Semantic Controls:** Standardized heading structure in admin view by replacing non-standard `<h3>` with styled spans in stat cards under `<h2>`; added explicit accessible labels and titles to icon-only buttons (sign-out buttons, modal close buttons).
  - **B7.6 — Responsive Modal Polish:** CSS rules in `app.css` bounding modal height (`max-height: calc(100vh - 2rem)`) with scrollable body (`overflow-y: auto`) ensuring usability across compact mobile viewports.
  - **B7.7 — Dashboard Responsive Width & Layout Polish:** Replaced restrictive 1200px max-width on `.dv-main-container` with `max-width: 1600px`, `min-width: 0`, and breakpoint-tailored padding (`2rem 2.5rem` >=1400px, `1.5rem` <=991px, `1rem` <=767px); widened Platform Status table with proportional `.dv-status-label-col` (32% label, 68% value) and responsive scroll wrapper; upgraded roadmap grid to two columns on desktop (`col-12 col-lg-6`) and one column on narrow screens with `.dv-roadmap-item` card styling; added `overflow-x: hidden` on body.
  - **B7.8 — Audit Test Suite:** Added `backend/tests/test_frontend_polish_audit.py` (6 test cases) validating DOM safety, client storage absence, DOM utility features, HTML landmarks, CSP headers, and responsive layout rules.
- **Phase C — Playwright End-to-End Browser Testing (Committed: `6c14797`):**
  - **C1 — Isolated Architecture & Docker Stack:** Created `compose.e2e.yaml` configuring an isolated runtime on loopback port `8001`, random project names, disposable test users and credentials, tmpfs PostgreSQL, and a dedicated named volume `e2e_documents_data` strictly preserving non-root UID 10001 ownership and 0700 permissions.
  - **C2 — Test Orchestrator & Traps:** Created `scripts/run_e2e_tests.sh` managing lifecycle: boots container stack with bounded health checks, dynamically bootstraps test admin account, exports fontconfig path (`~/.local/etc/fonts`), runs pytest with Playwright against `127.0.0.1:8001`, captures failure screenshots, and executes deterministic docker compose teardown via `EXIT`/`INT`/`TERM` traps.
  - **C3 — Scenario A (Application Startup & Routing):** `test_e2e_routing.py` (5 tests) testing root loading, reload stability across multiple refreshes, unauthenticated route redirection, session restoration across reloads, and client-side view navigation.
  - **C4 — Scenario B (Authentication & Session Management):** `test_e2e_auth.py` (6 tests) testing successful login/logout, invalid credentials error banners, client-side validation on empty inputs, double-submit protection with loading spinners, role-aware navigation visibility (admin sees Administration link, standard user does not), and expired/revoked session 401 handling with redirection.
  - **C5 — Scenario C (Document Management):** `test_e2e_documents.py` (6 tests) testing valid PDF upload modal, list rendering, streaming download with SHA-256 byte integrity verification, client-side search and tab filtering ("All", "My Documents", "Shared with me"), deletion modal confirmation with CSRF protection, invalid file type rejection, and cross-user isolation.
  - **C6 — Scenario D (Document Sharing & Permissions):** `test_e2e_sharing.py` (1 comprehensive multi-context test) testing user lookup, granting read access, recipient document visibility and download access across separate browser contexts, access revocation, and post-revocation access denial.
  - **C7 — Scenario E (Account Security Settings):** `test_e2e_settings.py` (4 tests) testing user identity and role badge display, password visibility toggles, client-side password policy validation checklist, and multi-session revocation across browser contexts upon password change.
  - **C8 — Scenario F (Administration Console):** `test_e2e_admin.py` (5 tests) testing admin route access gating, user provisioning modal with 409 conflict detection, account deactivation and reactivation lifecycle with multi-session termination, role promotion/demotion, and final active administrator 409 protection.
  - **C9 — Scenario G (Responsive & Accessibility Smoke Tests):** `test_e2e_responsive_a11y.py` (8 tests) testing 4 viewports (1920px desktop, 1440px laptop, 768px tablet, 375px mobile) with zero horizontal overflow (`scrollWidth <= clientWidth`), mobile navbar hamburger expand/collapse, keyboard skip link (`.dv-skip-link`), modal focus trapping (`trapFocus`) with Escape dismissal, and accessible form label bindings (`for`/`id`).
- **Phase D1 — GitHub Actions CI Foundation (Committed: `fa24ba5`):**
  - **D1.1 — Workflow Architecture & Triggers:** Added `.github/workflows/ci.yml` triggered on `push` and `pull_request` against `main` and `feature/**`, plus `workflow_dispatch` for manual executions.
  - **D1.2 — Security & Permissions:** Strict top-level `permissions: contents: read` (zero write capabilities), immutable commit SHA pinning for actions (`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`, `actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0`), prohibition of untrusted triggers like `pull_request_target`, and zero hardcoded credentials.
  - **D1.3 — Concurrency & Resource Bounding:** Top-level concurrency control (`group: ci-${{ github.workflow }}-${{ github.ref }}`, `cancel-in-progress: true`) preventing redundant parallel builds and resource waste, bounded by `timeout-minutes: 10`.
  - **D1.4 — Python 3.14 & Dependency Caching:** Standardized Python 3.14 runtime with native pip caching keyed on `requirements.txt`, `requirements-dev.txt`, and `requirements-lock.txt`.
  - **D1.5 — Deterministic Integrity & Smoke Gates:** Fast baseline validation executing environment inspection (`uname`, `python --version`, `pip --version`), dependency installation from `requirements-lock.txt`, full Python bytecode compilation (`compileall`), Ruff linting/formatting verification (`ruff check .`), and application import smoke check (`PYTHONPATH=backend python -c "import app.main"`).
  - **D1.6 — CI vs CD Architectural Separation:** Strict demarcation established: GitHub Actions serves as the developer-facing continuous integration runner and quality gate (Phases D1–D7); Jenkins is designated for CD deployment orchestration and will be implemented in Phase D8.
- **Phase D2 — Static Analysis, Linting & Coverage Gates (Committed: `d59ff6d`):**
  - **D2.1 — Static Analysis Gates:** Integrated Mypy static type checking (`mypy backend/app`) and Semgrep SAST rule validation (`semgrep scan --config p/default`).
  - **D2.2 — Automated Quality Gates:** Integrated full Python bytecode compilation (`compileall`) and Ruff linting/format checking (`ruff check .`).
  - **D2.3 — Regression Testing & Coverage Artifacts:** Automated pytest test runner in CI with coverage export (`--cov=app --cov-report=xml:coverage.xml`) uploaded with 7-day retention (`actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1 # v4.6.1`).
- **Phase D3 — Dependency Security and Vulnerability Management (Committed to `main` via PR #4, merge commit `a7adbb1`):**
  - **D3.1 — Scanner Integration (`.github/workflows/security.yml`):** Added `dependency-audit` job running parallel to Gitleaks and Semgrep under `permissions: contents: read`. Installs pinned `pip-audit==2.10.1` and executes `pip-audit -r requirements-lock.txt --no-deps --desc -f json -o pip-audit-report.json`.
  - **D3.2 — Machine-Readable Exception Register (`.github/security/dependency-exceptions.json`):** Canonical register with strict root schema (`version: "1.0"`, `exceptions: [...]`), PEP 508 package name validation, PEP 503 normalization, family-specific advisory ID validation (CVE, GHSA with 20-character alphabet `23456789cfghjmpqrvwx`, PYSEC), duplicate entry rejection, and UTC calendar-day expiration rules.
  - **D3.3 — Automated Validation Engine (`scripts/validate_dependency_audit.py`):** Python validator parsing top-level JSON object report (`dependencies` and `fixes` arrays per `pip-audit` v2.10.1 specification), rejecting skipped dependencies to ensure 100% complete audit coverage, rejecting explicit nulls on optional fields (`aliases`, `fix_versions`, `description`), enforcing bidirectional scanner/report consistency (status 0 requires 0 findings; status 1 requires >=1 findings), generating rich Step Summaries (`$GITHUB_STEP_SUMMARY`), and printing explicit console diagnostics.
  - **D3.4 — Decoupled Artifact Handling:** Fail-safe artifact upload preserving unfiltered `pip-audit-report.json` with 7-day retention and `if-no-files-found: ignore` to prevent secondary runner errors when scans fail.
  - **D3.5 — Automated Validator Test Suite (`backend/tests/test_dependency_audit_validator.py`):** Added 34 automated unit and integration tests validating helper patterns, register schema, structural report contracts (root object with `dependencies` and `fixes`), skipped dependency rejection, duplicate rejections, expiration semantics, consistency rules, and Step Summary outputs.
- **Phase D4.2 — Container Hardening, Vulnerability Validator and Exception Framework (Current Worktree on `feature/container-security`):**
  - **D4.2.1 — Production Dependency Lockfile (`requirements-prod-lock.txt`):** Created dedicated production lockfile with exact pins for 27 runtime packages (direct + transitives), isolating the runtime environment from all 17 development/test dependencies (`pytest`, `ruff`, `mypy`, `coverage`, `httpx`, `playwright`, etc.).
  - **D4.2.2 — Hardened Container Build (`backend/Dockerfile` & `.dockerignore`):** Pinned base image to multi-arch digest `python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f`. Dependencies installed with `--no-deps`. Container runs as non-root UID 10001 with read-only root, dropped capabilities (`cap_drop: ALL`), `no-new-privileges`, and tmpfs on `/tmp`. Hardened `.dockerignore` excludes test suites, CI workflows, and temporary reports.
  - **D4.2.3 — Reproducible zlib Vulnerability Remediation (Committed `3642249`):** Remediated fixable zlib vulnerabilities (`CVE-2026-76844` and `CVE-2026-85091`) by updating `zlib1g` to exact Debian Security snapshot version `1:1.3.dfsg+really1.3.1-1+deb13u1` (`snapshot.debian.org/archive/debian-security/20261108T000000Z`) with archive keyring verification, eliminating all fixable zlib vulnerabilities without modifying unrelated packages.
  - **D4.2.4 — Machine-Readable Container Exception Register (`.github/security/container-exceptions.json`):** Strict versioned schema (`version: "1.0"`, `exceptions: [...]`) for container vulnerability exceptions, validating identifiers, package names, affected versions, severity levels (`CRITICAL`, `HIGH`), justification reasons, and canonical `YYYY-MM-DD` expiration dates.
  - **D4.2.5 — Controlled OS Exception Population (Phase D4.2.2):** Populated register with exactly 59 package-level entries covering 17 distinct Debian OS CVEs (all tracked as `no-dsa`, `postponed`, or `point-release planned` with no available Trixie fix) under review expiration `2027-02-09`:
    - *12 Standard Exception Candidates (21 package matches):* Functionality not loaded, invoked, or reachable in DocVault API runtime (`infocmp` buffer overflow, `libstdc++` binary heap UAF and operator new overflow, Perl `Pod::Text` and `Archive::Tar` exhaustions, `libacl` symlink and TOCTOU flaws, SQLite FTS5 and Session overflows with SQLite unmapped in memory, and glibc `strfmon` / deprecated resolver printing flaws).
    - *5 Conditional Exception Candidates (38 package matches):* Unreachability strictly depends on verified runtime configuration and operational assumptions (glibc `gettext` `LANGUAGE` traversal conditioned on `LANG=C.UTF-8` and read-only rootfs; util-linux `mount` flaws conditioned on non-root UID 10001, `CapEff=0`, `no-new-privileges`, read-only rootfs, and unconfigured empty `/etc/fstab`; util-linux `nsenter` cgroup leak conditioned on host operator restraint from invoking `nsenter --join-cgroup`).
  - **D4.2.6 — Automated Grype Scan Validator (`scripts/validate_container_scan.py`):** Engine validating Grype JSON scan reports, enforcing severity policy (blocking Critical/High, non-blocking Medium/Low/Negligible/Unknown), deterministic exit codes (0 = pass, 1 = policy violation, 2 = operational failure), and GitHub Step Summary generation.
  - **D4.2.7 — Local Container Scan Runner (`scripts/run_container_scan.sh`):** Helper script to scan container images locally using Grype (binary or `anchore/grype:latest` container) and pipe reports into the validator.
  - **D4.2.8 — Automated Validator Test Suite (`backend/tests/test_container_scan_validator.py`):** 24 automated unit and integration tests validating report parsing, severity policy enforcement, exception register semantics, alias matching, expiration handling, unused warnings, scanner failures, and Step Summary formatting.
  - **Remediation vs. Temporary Risk Acceptance Policy:**
    - *Vulnerability Remediation:* Direct resolution through software updates (e.g. pinned dependency upgrades, Debian Security snapshot package upgrades) that eliminate vulnerable code.
    - *Temporary Risk Acceptance:* Formal, time-bounded (`2027-02-09`) exception registration for unpatched upstream OS findings backed by empirical reachability and isolation proofs.
    - *Operational Invariants:* Exception validity mandates maintaining: non-root UID 10001 execution, zero capabilities (`cap_drop: ALL`), `no-new-privileges: true`, read-only root filesystem, `noexec` on `/tmp`, unconfigured `/etc/fstab`, `LANG=C.UTF-8` with `LANGUAGE` unset, descriptor-relative UUID storage, and absence of host-side `nsenter --join-cgroup` operations.
    - *Reassessment Trigger:* Re-evaluation is mandatory whenever the base image digest, installed package versions, container runtime configuration, or host orchestration policies change, and before expiration on `2027-02-09`.
- **Phase D4.3 — Container Security CI Integration & Workflow Implementation (`.github/workflows/container-security.yml`):**
  - **D4.3.1 — Workflow Architecture & Triggers:** Implemented GitHub Actions workflow `Container Security & Artifact Gate` triggered on pushes to `main` and `feature/container-security`, pull requests targeting `main`, and manual dispatch (`workflow_dispatch`). Concurrency group `container-security-${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true`.
  - **D4.3.2 — Build Stage (`build`):** Checks out repository, builds production container image (`docker build -t docvault-api:local -f backend/Dockerfile .`), records `BUILD_IMAGE_ID` to `build-image-id.txt`, exports image archive `docvault-api.tar`, calculates SHA-256 checksum `docvault-api.tar.sha256`, and uploads archive artifact with 1-day retention.
  - **D4.3.3 — Vulnerability Scanning & Policy Gate (`scan`):** Depends on `build`. Downloads image archive, verifies SHA-256 checksum before loading, loads image via `docker load`, verifies loaded image ID against `BUILD_IMAGE_ID`, records `scanned-image-id.txt`, executes Grype scan via `anchore/scan-action@8576240a41341d866dbd7ebc72cd9fc0ef023f54` (pinned to v7.4.2 full commit SHA) with `output-format: "json"` and `fail-build: false`, evaluates findings against `.github/security/container-exceptions.json` via `scripts/validate_container_scan.py`, writes GitHub Step Summary (`$GITHUB_STEP_SUMMARY`), uploads raw Grype JSON report with 7-day retention (`if: always()`), and uploads scanned metadata.
  - **D4.3.4 — Isolated Docker Hub Publishing (`publish`):** Depends on `build` and `scan`. Runs strictly on push to `main` (`if: github.event_name == 'push' && github.ref == 'refs/heads/main'`), never on pull requests or feature branches. Downloads image archive and scanned metadata, verifies archive checksum, loads image into Docker, verifies loaded image ID against both `BUILD_IMAGE_ID` and `SCANNED_IMAGE_ID`, validates presence of `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets (failing clearly if missing), authenticates via `docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567`, tags image with immutable commit SHA (`${{ github.sha }}`) and `latest`, pushes to `iyedbnaissa/docvault-api`, and reports registry `RepoDigest`.
  - **D4.3.5 — Build-to-Scan-to-Publish Integrity:** Verified handoff using SHA-256 archive checksums and Docker image IDs ensuring the exact image scanned and validated is the one published without rebuilding.
  - **D4.3.6 — Automated Workflow Test Suite (`backend/tests/test_container_security_workflow.py`):** 11 automated unit tests validating triggers, concurrency, permissions (`contents: read`), job dependency graph, publish isolation conditions, Docker Hub secrets isolation, action commit SHA pinning, Grype integration, artifact retention, and image checksum/ID verification.
  - **Unexecuted Validation Disclosure:** Docker Hub publishing to `iyedbnaissa/docvault-api` was not executed locally or from the feature branch because it requires a main-branch push event and repository secrets. All workflow structure, YAML syntax, integrity checks, and local validator steps were fully validated.

## Phase A, B1, B2, B3, B4, B5 & B6 Endpoints & Contracts

| Method & Path | Auth & CSRF | Purpose & Contract |
|---|---|---|
| `GET /` | Public / Same-Origin | Serves frontend SPA shell (`index.html`) with `Cache-Control: no-cache` and global security headers. |
| `GET /static/*` | Public / Same-Origin | Serves locally vendored CSS, JavaScript, and asset files. |
| `GET /favicon.ico` | Public | Serves DocVault SVG favicon. |
| `POST /api/v1/auth/login` | Public (Rate limited) | Authenticates credentials (`{"username": "...", "password": "..."}`). Sets `docvault_session` cookie (`Path=/api/v1; HttpOnly; SameSite=lax`), returns `{"csrf_token": "...", "user": {"id": "...", "username": "...", "role": "..."}}`. |
| `POST /api/v1/auth/logout` | Active session cookie + `X-CSRF-Token` | Revokes server session in PostgreSQL, deletes `docvault_session` cookie (`Max-Age=0`), returns 204 No Content. |
| `GET /api/v1/auth/me` | Active session cookie | Returns authenticated user details `{"id": "...", "username": "...", "role": "..."}`. Returns 401 if unauthenticated/expired. |
| `POST /api/v1/auth/csrf` | Active session cookie; Origin / Fetch Metadata validation | Rotates and returns fresh `{"csrf_token": "..."}` for authenticated session bootstrap. Rejects cross-site/navigation requests. Response sets `Cache-Control: private, no-store`. |
| `GET /api/v1/documents` | Active session cookie | Lists accessible documents for authenticated user. Returns `list[DocumentResponse]`. |
| `POST /api/v1/documents` | Active session cookie + `X-CSRF-Token` | Uploads PDF document via `multipart/form-data` (single file field named `file`, max 10 MiB). Returns 201 Created with `DocumentResponse`. |
| `GET /api/v1/documents/{id}` | Active session cookie | Returns `DocumentResponse` for accessible document. 404 if inaccessible or deleted. |
| `GET /api/v1/documents/{id}/download` | Active session cookie | Streams PDF binary content with safe `Content-Disposition`, `X-Content-Type-Options: nosniff`, and `Cache-Control: private, no-store`. 404 if inaccessible or tombstoned. |
| `DELETE /api/v1/documents/{id}` | Active session cookie + `X-CSRF-Token` | Permanently deletes owned document (tombstones, removes storage file, removes database record). Returns 204 No Content. Returns 404 if not owned. |
| `GET /api/v1/documents/{id}/shares` | Active session cookie | Lists current active shares for owned document. Returns `list[DocumentShareResponse]`. Returns 404 if not owned. |
| `PUT /api/v1/documents/{id}/shares/{user_id}` | Active session cookie + `X-CSRF-Token` | Grants read access to active user. Returns 201 Created. 409 if duplicate, 422 if self-share, 404 if not owned or user not found. |
| `DELETE /api/v1/documents/{id}/shares/{user_id}` | Active session cookie + `X-CSRF-Token` | Revokes read access for specified user. Returns 204 No Content (idempotent). 404 if document not owned. |
| `GET /api/v1/users/lookup?username={query}` | Active session cookie | Case-insensitive partial username search (min 2, max 32 chars). Returns `[{"id": "<uuid>", "username": "<name>"}]` for active users only (max 10 results). |
| `POST /api/v1/auth/password` | Active session cookie + `X-CSRF-Token` | Changes password (`{"current_password": "...", "new_password": "..."}`). Revokes all other user sessions, keeps current session active, rotates and returns new CSRF token. |
| `GET /api/v1/admin/users` | Administrator session cookie | Lists all users (`id`, `username`, `role`, `is_active`, `created_at`, `updated_at`). Never exposes password hashes or sessions. |
| `POST /api/v1/admin/users` | Administrator session cookie + `X-CSRF-Token` | Provisions a new user account with role. Returns 201 Created. 409 if duplicate username, 422 if policy validation fails. |
| `PATCH /api/v1/admin/users/{user_id}/status` | Administrator session cookie + `X-CSRF-Token` | Updates active status (`{"is_active": bool}`). Revokes user sessions on deactivation. 409 if last active admin, 404 if not found. Clears cookie if self-deactivated. |
| `PATCH /api/v1/admin/users/{user_id}/role` | Administrator session cookie + `X-CSRF-Token` | Updates user role (`{"role": "user" \| "administrator"}`). 409 if last active admin demoted, 404 if not found. |

## Verification update — 11 November 2026

- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`: **YAML syntax clean and valid**.
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"`: **YAML syntax clean and valid**.
- `python3 -m json.tool .github/security/dependency-exceptions.json`: **JSON syntax clean and valid**.
- `python3 -m json.tool .github/security/container-exceptions.json`: **JSON syntax clean and valid (59 active exceptions)**.
- `python3 scripts/validate_container_scan.py --report /tmp/grype-remediated.json --exceptions .github/security/container-exceptions.json`: **Policy compliant: 0 unapproved Critical/High, 59 approved exceptions, 0 unused warnings (exit code 0)**.
- `python3 -m compileall backend/app backend/tests scripts`: **compiled cleanly with 0 syntax errors**.
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/container-security.yml'))"`: **YAML syntax clean and valid**.
- `PYTHONPATH=backend python -c "import app.main"`: **DocVault FastAPI application successfully imported**.
- `.venv/bin/ruff check .`: **passed with 0 errors**.
- `.venv/bin/mypy backend/app scripts/validate_container_scan.py`: **passed with 0 issues in 41 source files**.
- `git diff --check`: **passed with 0 whitespace issues**.
- `PYTHONPATH=backend:scripts .venv/bin/pytest backend/tests/test_container_security_workflow.py -v`: **11 passed in 0.28s**.
- `PYTHONPATH=backend:scripts .venv/bin/pytest backend/tests/test_container_scan_validator.py -v`: **24 passed in 0.83s**.
- `PYTHONPATH=backend:scripts .venv/bin/pytest backend/tests/test_dependency_audit_validator.py -v`: **34 passed in 0.19s**.
- `PYTHONPATH=backend:scripts .venv/bin/pytest backend/tests -q`: **388 passed, 6 skipped** in 29.78s.
- `docker build -t docvault-api:local -f backend/Dockerfile .`: **built cleanly (286MB disk usage, 66.8MB content size)**.
- `docker compose up -d --no-deps api`: **container started cleanly**.
- `curl -fsS http://127.0.0.1:8000/health`: `{"status":"ok"}`.
- `curl -fsS http://127.0.0.1:8000/ready`: `{"status":"ready"}`.
- `scripts/run_phase3_pg_concurrency_test.sh`: **1 passed** (PostgreSQL advisory-lock administrator concurrency) in 0.77s.
- `scripts/run_phase4_pg_document_tests.sh`: **5 passed** on **PostgreSQL 17.11** (isolated document integration, deletion tombstones, concurrent shares, failure compensation) in 2.33s.
- `bash scripts/run_e2e_tests.sh`: **35 passed** across all 7 scenarios in 104.31s (0 failed, 0 errors, 0 skipped).
- `pytest backend/tests/test_e2e_workflow.py`: **10 passed** in 0.06s.

## Current Phase — Phase D5 (Headless Browser E2E Testing in CI)

Phase D5 integrates the Playwright browser E2E test suite into GitHub Actions:
- **D5.1 — CI Runner Dynamic Environment Compatibility (`scripts/run_e2e_tests.sh`):** Dynamically resolves `pytest` from `PYTEST_BIN`, `.venv/bin/pytest`, or system/runner `pytest` in `PATH`, ensuring compatibility across both local and CI environments.
- **D5.2 — Dedicated GitHub Actions Workflow (`.github/workflows/e2e.yml`):**
  - Name: `Browser E2E Testing`
  - Triggers: `push` and `pull_request` on `main` and `feature/**`, plus `workflow_dispatch`.
  - Permissions: Least-privilege `contents: read`.
  - Concurrency: `group: e2e-${{ github.workflow }}-${{ github.ref }}`, `cancel-in-progress: true`.
  - Timeout: 15 minutes.
  - Steps: Python 3.14 setup with pip dependency caching, Playwright and E2E test dependency installation (`requirements-lock.txt` and pinned `requirements-e2e.txt`), Playwright Chromium and system dependencies installation (`python -m playwright install --with-deps chromium`), local container image build (`docvault-api:local`), E2E test execution against isolated Docker stack, and fail-safe artifact retention (`test-results/`) for 7 days (`if: always()`).
- **D5.3 — Automated Workflow Unit Tests (`backend/tests/test_e2e_workflow.py`):** Added 10 unit tests verifying workflow triggers, concurrency, least-privilege permissions, third-party action SHA pinning, dependencies installation, Playwright browser setup, image build, and artifact retention fail-safes.
- **D5.4 — Local and CI Verification:** Verified 35 passing Playwright E2E browser tests in 104.31s with resilient 15s assertion timeouts (`expect.set_options(timeout=15000)` in `backend/tests/e2e/conftest.py`), 10 passing workflow unit tests in 0.06s, and 388 passing backend regression tests.
- **D5.5 — E2E Suite Completion & Merge:** Extended suite to 38 passing tests with state-aware router idempotency and focus stabilization, integrated to `main` via PR #6 (commit `45b462af8b6690c540127296950fa7d14131cc73`).

## Python 3.13 Runtime Migration & Compatibility Validation (12 November 2026)

- **Migration Objective:** Eliminate Python 3.14.10 upstream regression finding `CVE-2026-119170` by migrating the production container and CI workflow runtime to official Python 3.13 (`python:3.13.18-slim`).
- **Runtime Transition:**
  - Previous runtime: Python 3.14.10 (container) / Python 3.14.4 (host)
  - New target runtime: Python 3.13.18
  - Verified Docker base image: `python:3.13.18-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`
  - OS distribution & architecture: Debian GNU/Linux 13 (Trixie), `x86_64`
- **Dependency Compatibility Assessment:**
  - Evaluated all 27 runtime packages in `requirements-prod-lock.txt`, 17 development/test packages in `requirements-lock.txt`, and 6 Playwright dependencies in `requirements-e2e.txt`.
  - Exactly 0 version modifications required. All pinned dependencies provide official, pre-built binary wheels for CPython 3.13 (`cp313` or `cp310-abi3`) or are pure Python.
  - Dependency validation via `pip install --no-cache-dir --disable-pip-version-check -r requirements-lock.txt -r requirements-e2e.txt` and `pip check` confirmed zero broken requirements.
- **Docker Hardening & Runtime Verification:**
  - Production image `docvault-api:local` built cleanly with `--no-deps` production dependency installation and reproducible `zlib1g` security snapshot remediation (`1:1.3.dfsg+really1.3.1-1+deb13u1`).
  - Container runtime verification confirmed:
    - Reports `Python 3.13.18 (main, Nov  5 2026, 07:59:38) [GCC 14.2.0]` on `Debian GNU/Linux 13 (trixie)`.
    - Non-root UID/GID 10001 (`docvault`), read-only root filesystem (`ReadOnlyRootfs: true`), dropped capabilities (`CapDrop: [ALL]`), `no-new-privileges: true`, tmpfs on `/tmp:rw,noexec,nosuid,size=16m`, and isolated document volume.
    - Application endpoints `/health` and `/ready` return HTTP 200 OK with full security headers.
    - Alembic database migration service ran cleanly to `head`.
    - Live PDF document upload and download integrity verified across multiple test sessions.
- **Container Security & Vulnerability Gate Results:**
  - Scanned `docvault-api:local` using Anchore Grype scanner.
  - Scan report validated against `.github/security/container-exceptions.json` via `scripts/validate_container_scan.py`:
    - Total detected vulnerabilities: 203 (down from 204 in Python 3.14.10)
    - Unapproved Critical / High findings: 0
    - Approved active exceptions: 59
    - Monitored findings (Medium/Low/Negligible): 144
    - Unused exception warnings: 0
    - **Policy compliant: All Critical/High findings are approved or zero vulnerabilities detected (exit code 0).**
    - **Vulnerability elimination verified:** `CVE-2026-119170` is completely absent from the Python 3.13.18 scan report. Zero exception additions were required.
- **Automated Quality & Test Results:**
  - Complete backend test suite: **389 passed, 6 skipped** in 30.95s.
  - PostgreSQL advisory-lock concurrency test: **1 passed** in 0.65s.
  - PostgreSQL document integration suite: **5 passed** on PostgreSQL 17.11 in 2.91s.
  - Playwright browser E2E test suite: **38 passed** across 7 test scenarios in 183.10s.
  - Workflow and validator unit test suite: **79 passed** in 1.11s.
  - Static type check (`mypy backend/app scripts/validate_container_scan.py`): **Success (0 issues in 41 source files)**.
  - Linter (`ruff check .`): **0 errors**.
  - Python byte compilation (`compileall`): **Clean, 0 errors**.
  - Workflow YAML & exception JSON validation: **100% valid**.
  - Whitespace check (`git diff --check`): **Clean, 0 issues**.
- **CI Workflow Alignment:**
  - Standardized all GitHub Actions workflows (`ci.yml`, `e2e.yml`, `security.yml`, `container-security.yml`) to set up `python-version: '3.13'`.
  - Added `feature/python-runtime-migration` branch trigger to `container-security.yml`.
  - Preserved full 40-character commit SHA pinning on all GitHub Actions.

## Phase D7.2 — DAST Policy Validator and Exception Register (Current Worktree on `feature/dast-integration`)

Phase D7.2 implements the policy validation engine and machine-readable exception register for OWASP ZAP Dynamic Application Security Testing (DAST):
- **D7.2.1 — Machine-Readable DAST Exception Register (`.github/security/dast-exceptions.json`):**
  - Strict versioned schema (`version: "1.0"`, `exceptions: [...]`) dedicated to DAST findings.
  - Initialized with an empty exceptions array (`"exceptions": []`), strictly prohibiting speculative suppressions.
  - Strict field schema: `zap_rule_id` (string/integer), `alert_name` (string), `target_url_pattern` (regex pattern), `severity` (`CRITICAL`, `HIGH`, `MEDIUM`), `reason` (minimum 10 characters), and canonical `expires_at` (`YYYY-MM-DD` through 23:59:59 UTC).
  - Explicit rejection of wildcard blanket suppressions (`.*`, `.+`, server root wildcards) ensuring targeted endpoint scoping.
  - Automatic duplicate exception rejection and expiration enforcement (expired exceptions trigger policy violation exit code 1).
- **D7.2.2 — Automated DAST Scan Validator (`scripts/validate_dast_scan.py`):**
  - Parses OWASP ZAP JSON reports (`site[].alerts[]` or top-level `alerts[]`), extracting individual alert instances with method and URI.
  - Enforces targeted regex endpoint matching against active exceptions to prevent broad suppression across unrelated endpoints sharing the same ZAP rule ID.
  - Normalizes ZAP risk codes (0–3) and risk descriptions (`High`, `Medium`, `Low`, `Informational`), raising operational errors on unknown or missing severities.
  - Enforces severity gating: unapproved `CRITICAL`, `HIGH`, and `MEDIUM` findings fail policy; `LOW` and `INFORMATIONAL` are monitored non-blocking.
  - Deterministic exit codes: 0 = compliant/pass, 1 = policy violation (unapproved High/Medium findings or expired exceptions), 2 = operational error (malformed report, schema errors, blanket suppressions, duplicate exceptions, scanner failures).
  - Emits console diagnostics and formatted GitHub Step Summary (`$GITHUB_STEP_SUMMARY`).
- **D7.2.3 — Automated DAST Validator Test Suite (`backend/tests/test_dast_scan_validator.py`):**
  - 24 automated unit and integration tests covering helper parsing, UTC date semantics, blanket suppression detection, severity normalization, clean reports, unapproved High/Medium findings, Low/Informational monitoring, valid exception matches, mismatched rule IDs, mismatched endpoint patterns, expired exceptions, duplicate exceptions, blanket suppression rejection, invalid report/register JSON, missing files, malformed alert structures, unknown severities, GitHub Step Summary output, scanner error statuses, and multi-instance partial matches.

## Remaining work & Phase D roadmap

- **Phase D1:** GitHub Actions CI Foundation (`.github/workflows/ci.yml`) (Merged).
- **Phase D2:** Static Analysis, Linting & Backend Automated Test CI Gates (Merged).
- **Phase D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning & Exception Management) (Merged).
- **Phase D4:** Container Image Build & Artifact Security Validation (Merged via PR #5).
- **Phase D5:** Headless Browser E2E Testing in CI (Merged via PR #6).
- **Phase D6:** PR Verification Policies & Quality Gates (Active ruleset ID `27123717` requiring 7 checks).
- **Phase D7:** OWASP ZAP DAST Integration & Pipeline Hardening (D7.1 Assessment & D7.2 Validator Implemented; D7.3 Orchestrator Pending).
- **Phase D8:** Jenkins CD Pipeline Orchestration & Deployment.

## Known limitations

Phase D4 is merged to `main` via PR #5 with Docker Hub publishing to `iyedbnaissa/docvault-api`. 59 package-level exceptions covering 17 Debian OS CVEs are temporarily accepted under reviewed technical reachability assumptions expiring `2027-02-09`. Application dependencies have 0 known vulnerabilities. DAST exception register starts empty; speculative suppressions are prohibited. No malware scanning or PDF sanitization; database and filesystem operations are not fully atomic. Work is on dedicated branch `feature/dast-integration`. Final repository review, staging, commit, and push require explicit authorization.
