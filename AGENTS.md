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

## Current verified project status — Phase C

Phase B (B1–B7) is finalized, committed, and pushed to `feature/frontend` (`beda2e7`). Active development is on dedicated branch `feature/e2e-testing` with baseline `beda2e7`. Phase C (Playwright End-to-End Browser Testing) is implemented and verified.

Phase C adds:
- **Playwright Browser E2E Test Suite (`backend/tests/e2e/`):**
  - Built with Python `pytest-playwright` and Chromium headless runner.
  - Test suites covering complete real-browser workflows against the live FastAPI application:
    - **Scenario A (`test_e2e_routing.py`):** Root rendering, SPA routing, reload stability, unauthenticated route guards, session restoration, and authenticated navigation (5 tests).
    - **Scenario B (`test_e2e_auth.py`):** Full login/logout lifecycle, invalid credentials feedback, client validation on empty submit, double-submit protection with button spinners, role-aware navigation visibility (admin vs standard user), and expired session 401 interception (6 tests).
    - **Scenario C (`test_e2e_documents.py`):** PDF upload modal, list rendering, download streaming with file integrity verification (SHA-256 match), search and filter tabs, deletion with confirmation dialog, invalid file type rejection, and cross-user isolation (6 tests).
    - **Scenario D (`test_e2e_sharing.py`):** Document sharing end-to-end lifecycle across two independent browser contexts: search collaborator, grant read access, verify collaborator can view and download document, revoke access, and verify cross-user isolation after revocation (1 test / comprehensive multi-context scenario).
    - **Scenario E (`test_e2e_settings.py`):** Identity and role badge display, password visibility toggles, client-side password policy validation errors, and multi-session password change lifecycle with cross-browser session revocation (4 tests).
    - **Scenario F (`test_e2e_admin.py`):** Role-gated administration console access (granted for admin, denied for standard user), user provisioning modal, account deactivation/reactivation lifecycle with session termination, role promotion/demotion, and final active administrator 409 protection (5 tests).
    - **Scenario G (`test_e2e_responsive_a11y.py`):** Responsive layout and horizontal overflow validation across 4 viewports (1920px desktop, 1440px laptop, 768px tablet, 375px mobile), mobile navbar toggler, keyboard skip link (`.dv-skip-link`), modal focus trapping (`trapFocus`) with Escape dismissal, and accessible form label bindings (8 tests).
- **Isolated E2E Container Stack & Test Runner (`compose.e2e.yaml`, `scripts/run_e2e_tests.sh`):**
  - Dedicated Compose stack isolated from development environments using port `8001`, random project names, disposable test users/documents, and ephemeral tmpfs PostgreSQL.
  - Uses dedicated persistent named volume `e2e_documents_data` preserving storage directory permissions (`0700`, UID 10001) required by DocVault storage validation.
  - Autonomous test runner script (`scripts/run_e2e_tests.sh`) bootstrapping test admin with disposable credentials, configuring Playwright shared libraries and font configurations (`~/.local/etc/fonts`), executing tests, and ensuring deterministic container teardown via traps.
  - Zero exposure of credentials, cookies, or CSRF tokens in logs; automatic full-page failure screenshot capture under `test-results/failures/`.

Latest verified validation:
- Playwright Browser E2E suite (`scripts/run_e2e_tests.sh`): **35 passed** in 104.14s (0 failures, 0 errors, 0 skipped).
- Complete backend & frontend integration suite: **319 passed, 6 skipped** in 29.00s.
- Isolated PostgreSQL concurrency integration: **1 passed** in 0.77s.
- Isolated PostgreSQL document integration: **5 passed** on PostgreSQL 17.11 in 2.33s.
- Ruff: **passed cleanly with 0 errors**.
- Mypy (backend/app & backend/tests/e2e): **passed cleanly with 0 errors**.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase C roadmap: Phase C completed. Next phase: Phase D (CI/CD Pipeline, Automated Quality Gates & Deployment).

Known limitations: No malware scanning or sanitization; filesystem and database operations are not fully atomic. All Phase C work is on `feature/frontend` and uncommitted. Never commit, push, reset, or amend without explicit authorization.
