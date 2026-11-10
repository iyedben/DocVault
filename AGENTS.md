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

## Current verified project status — Phase D3

Phase C (Playwright End-to-End Browser Testing) is finalized, committed, and pushed to `feature/e2e-testing` (`6c14797`). Phase D1/D2 CI Foundation and Automated Quality Gates are finalized on `feature/ci-foundation` at baseline checkpoint `d59ff6d` (`fix(ci): scope mypy to application code`). Active development is on dedicated branch `feature/dependency-security` based on `d59ff6d`. Phase D3 implements Dependency Security and Vulnerability Management.

Phase D3 adds:
- **Dependency Vulnerability Scanning Gate (`.github/workflows/security.yml`):**
  - **Scanner & Tooling:** Pinned `pip-audit==2.10.1` executed in dedicated `dependency-audit` job under least-privilege `permissions: contents: read`.
  - **Deterministic Target:** Audits fully locked Python dependencies in `requirements-lock.txt` with `--no-deps` flag (evaluates exact package pins against advisory feeds without re-resolving or duplicate dependency installation).
  - **Decoupled Reporting & Fail-Safe Artifacts:** Emits unfiltered machine-readable JSON scan report (`pip-audit-report.json`), uploaded as an artifact (`dependency-audit-report`) with 7-day retention and `if-no-files-found: ignore` to prevent misleading runner failures.
- **Machine-Readable Exception Register (`.github/security/dependency-exceptions.json`):**
  - Strict JSON schema allowing exactly `version: "1.0"` and `exceptions: [...]`.
  - Strict type checking (rejecting non-strings, nulls, whitespace-only strings, and unknown fields).
  - Exact PEP 508 package name validation and PEP 503 normalization.
  - Strict advisory ID validation for supported families (CVE, GHSA with 20-character alphabet `23456789cfghjmpqrvwx`, and PYSEC).
  - Strict canonical `YYYY-MM-DD` date validation with UTC calendar-day expiration rules (valid through 23:59:59 UTC of stated date).
  - Automatic duplicate entry rejection and non-blocking warnings for unused exceptions.
- **Automated Validation Engine (`scripts/validate_dependency_audit.py`):**
  - Enforces bidirectional scanner/report consistency (`status == 0` requires 0 vulnerabilities; `status == 1` requires >=1 vulnerabilities; unexpected exit status fails).
  - Validates scan report top-level JSON object structure (`dependencies` and `fixes` arrays per `pip-audit` v2.10.1 specification), rejects skipped dependencies to ensure 100% complete audit coverage, and rejects explicit nulls on optional fields (`aliases`, `fix_versions`, `description`).
  - Generates comprehensive GitHub Step Summary (`$GITHUB_STEP_SUMMARY`) on all exit paths (non-fatal supplementary write policy).
  - Tested comprehensively in `backend/tests/test_dependency_audit_validator.py` (34 automated unit/integration tests).

Latest verified validation:
- Workflow YAML parsing: **clean** (PyYAML safe_load validated for both `ci.yml` and `security.yml`).
- Exception register JSON parsing: **clean** (Python json.tool validated).
- Bytecode compilation (`compileall`): **compiled cleanly across `backend/app`, `backend/tests`, and `scripts` with 0 errors**.
- Ruff linter check (`ruff check .`): **0 errors / clean**.
- Mypy static type checking (`mypy backend/app`): **Success (0 issues in 40 source files)**.
- Application import check (`PYTHONPATH=backend python -c "import app.main"`): **passed**.
- Validator test suite (`test_dependency_audit_validator.py`): **34 passed in 0.19s**.
- Complete backend regression test suite: **353 passed, 6 skipped** in 31.94s.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase D roadmap:
- **D1:** GitHub Actions CI Foundation.
- **D2:** Static Analysis, Linting & Backend Automated Test CI Gates.
- **D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning & Exception Management) (Current).
- **D4:** Container Image Build & Artifact Security Validation.
- **D5:** Headless Browser E2E Testing in CI.
- **D6:** PR Verification Policies & Quality Gates.
- **D7:** Pipeline Hardening & CI Performance Optimization.
- **D8:** Jenkins CD Pipeline Orchestration & Deployment.

Known limitations: No malware scanning or sanitization; filesystem and database operations are not fully atomic. Dockerfile installs from `requirements.txt` (transitives resolved at container build time, deferred to D4). All Phase D3 work is on `feature/dependency-security` and uncommitted. Never commit, push, reset, or amend without explicit authorization.
