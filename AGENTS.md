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

## Current verified project status — Phase D4.2

Phase C (Playwright End-to-End Browser Testing) is merged to `main` via PR #2. Phase D1/D2 CI Foundation and Automated Quality Gates are merged to `main` via PR #3. Phase D3 Dependency Security and Vulnerability Management is merged to `main` via PR #4 (`084a47f` -> merge commit `a7adbb1`). Active development is on dedicated branch `feature/container-security` based on `a7adbb19ebc1831002d258e851055e89b1f33e06` (`main`). Phase D4.2 implements Container Hardening, Vulnerability Validator, and Exception Framework.

Phase D4.2 adds:
- **Dedicated Production Dependency Lockfile (`requirements-prod-lock.txt`):**
  - Contains exact pins for all 27 runtime packages and their transitive dependencies, derived directly from the audited `requirements-lock.txt`.
  - Excludes all 17 development, test, and linting tools (`pytest`, `ruff`, `mypy`, `coverage`, `httpx`, `playwright`, etc.) from production container images.
- **Hardened Container Build (`backend/Dockerfile` & `.dockerignore`):**
  - Pins base image to multi-arch index digest: `python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f`.
  - Installs production dependencies with `--no-deps` flag ensuring zero unpinned or dynamic resolution during container builds.
  - Hardened `.dockerignore` excluding `.git/`, `.github/`, `scripts/`, `backend/tests/`, `test-results/`, and temporary reports.
  - Container runs as non-root UID/GID 10001 (`docvault`), with read-only root filesystem, dropped capabilities (`cap_drop: ALL`), `no-new-privileges: true`, tmpfs on `/tmp`, and healthcheck verifying `/ready`.
- **Machine-Readable Container Exception Register (`.github/security/container-exceptions.json`):**
  - Strict JSON schema requiring `version: "1.0"` and `exceptions: [...]`.
  - Strict validation of entry fields: `vulnerability_id` (CVE, GHSA, PYSEC), `package_name`, `affected_version`, `severity` (CRITICAL, HIGH), `reason`, `expires_at` (canonical `YYYY-MM-DD` through 23:59:59 UTC).
  - Automatic duplicate entry rejection and warnings for unused exceptions.
- **Grype Container Scan Validator (`scripts/validate_container_scan.py`):**
  - Validates Grype JSON scan reports against the container exception register.
  - Enforces severity policy: blocks on unapproved `CRITICAL` and `HIGH` findings; treats `MEDIUM`, `LOW`, `NEGLIGIBLE`, and `UNKNOWN` as monitored non-blocking.
  - Deterministic exit codes: 0 = pass/approved, 1 = policy violation (unapproved Critical/High), 2 = operational error (malformed JSON, invalid exceptions, scanner failure).
  - Emits console diagnostics and GitHub Step Summary (`$GITHUB_STEP_SUMMARY`) on all exit paths.
- **Local Container Scan Helper (`scripts/run_container_scan.sh`):**
  - Developer script to scan local Docker images (`docvault-api:local`) via host `grype` binary or fallback `anchore/grype:latest` container.
- **Automated Validator Test Suite (`backend/tests/test_container_scan_validator.py`):**
  - 24 automated unit and integration tests covering helper parsing, schema validation, Grype match extraction, severity gating, alias matching, expiration handling, unused warnings, scanner failures, and Step Summary formatting.

Latest verified validation:
- Exception register JSON parsing: **clean** (Python `json.tool` validated).
- Bytecode compilation (`compileall`): **compiled cleanly across `backend/app`, `backend/tests`, and `scripts` with 0 errors**.
- Ruff linter check (`ruff check .`): **0 errors / clean**.
- Mypy static type checking (`mypy backend/app scripts/validate_container_scan.py`): **Success (0 issues in 41 source files)**.
- Validator test suite (`test_container_scan_validator.py`): **24 passed in 0.97s**.
- Complete backend regression test suite: **377 passed, 6 skipped** in 30.35s.
- Container image build: **`docvault-api:local` built cleanly (286MB disk usage, 66.8MB content size)**.
- Container runtime verification: **`docvault-api-1` running, healthy, `/health` and `/ready` return HTTP 200 OK**.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase D roadmap:
- **D1:** GitHub Actions CI Foundation (Merged).
- **D2:** Static Analysis, Linting & Backend Automated Test CI Gates (Merged).
- **D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning & Exception Management) (Merged).
- **D4:** Container Image Build & Artifact Security Validation (D4.2 Implemented; D4.3 Workflow & Docker Hub Publishing Pending).
- **D5:** Headless Browser E2E Testing in CI.
- **D6:** PR Verification Policies & Quality Gates.
- **D7:** Pipeline Hardening & CI Performance Optimization.
- **D8:** Jenkins CD Pipeline Orchestration & Deployment.

Known limitations: Base image OS packages contain unpatched upstream vulnerabilities (monitored via Grype); no malware scanning or sanitization; filesystem and database operations are not fully atomic. All Phase D4.2 work is on `feature/container-security` and uncommitted. Never commit, push, reset, or amend without explicit authorization.
