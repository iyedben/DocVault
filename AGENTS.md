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

## Current verified project status — Phase D1

Phase C (Playwright End-to-End Browser Testing) is finalized, committed, and pushed to `feature/e2e-testing` (`6c14797`). Active development is on dedicated branch `feature/ci-foundation` with baseline `6c14797`. Phase D1 (GitHub Actions CI Foundation) establishes the base CI pipeline.

Phase D1 adds:
- **GitHub Actions CI Workflow Foundation (`.github/workflows/ci.yml`):**
  - **Triggers:** Push to `main` and `feature/**`, pull requests to `main` and `feature/**`, and manual dispatch (`workflow_dispatch`).
  - **Security posture & least privilege:** Top-level `permissions: contents: read` ensuring no write capabilities; actions pinned to immutable 40-character commit SHAs with human-readable release comments; zero untrusted triggers (`pull_request_target` prohibited); zero secrets or credential exposure.
  - **Concurrency & timeouts:** Top-level concurrency control (`group: ci-${{ github.workflow }}-${{ github.ref }}`, `cancel-in-progress: true`) automatically cancelling obsolete in-flight runs; job bounded by `timeout-minutes: 10`.
  - **Python 3.14 & pip caching:** Predictable runtime via `actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0` using native pip cache bound to `requirements.txt`, `requirements-dev.txt`, and `requirements-lock.txt`.
  - **Deterministic integrity & smoke verification:** CI environment inspection, pinned dependency installation, Python bytecode compilation across `backend/app`, `backend/tests`, and `scripts`, Ruff linting/formatting verification (`ruff check .`), and application importability smoke check (`PYTHONPATH=backend python -c "import app.main"`).
- **CI vs CD Separation:** GitHub Actions handles fast continuous integration and quality gates (Phases D1–D7). Jenkins CD orchestration and deployment is strictly deferred to Phase D8.

Latest verified validation:
- Workflow YAML parsing: **clean** (PyYAML safe_load validated).
- Bytecode compilation (`compileall`): **38 modules compiled cleanly with 0 syntax errors**.
- Ruff linter check (`ruff check .`): **0 errors / clean**.
- Application import check (`PYTHONPATH=backend python -c "import app.main"`): **passed**.
- Complete backend & frontend integration suite: **319 passed, 6 skipped** in 29.00s.
- Playwright Browser E2E suite (`scripts/run_e2e_tests.sh`): **35 passed** in 104.14s (0 failures, 0 errors, 0 skipped).
- Isolated PostgreSQL concurrency integration: **1 passed** in 0.77s.
- Isolated PostgreSQL document integration: **5 passed** on PostgreSQL 17.11 in 2.33s.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase D roadmap:
- **D1:** GitHub Actions CI Foundation (Current).
- **D2:** Static Analysis, Linting & Backend Automated Test CI Gates.
- **D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning, SBOM, SAST & Secrets).
- **D4:** Container Image Build & Artifact Security Validation.
- **D5:** Headless Browser E2E Testing in CI.
- **D6:** PR Verification Policies & Quality Gates.
- **D7:** Pipeline Hardening & CI Performance Optimization.
- **D8:** Jenkins CD Pipeline Orchestration & Deployment.

Known limitations: No malware scanning or sanitization; filesystem and database operations are not fully atomic. All Phase D1 work is on `feature/ci-foundation` and uncommitted. Never commit, push, reset, or amend without explicit authorization.
