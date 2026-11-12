# Instructions for Codex sessions

## Project

DocVault is an academic secure document management and DevSecOps project. It is under active development and is not production-ready. The backend stack is Python 3.13, FastAPI, Pydantic, SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker and Docker Compose provide the local runtime. The planned browser client uses HTML, CSS, Bootstrap, and JavaScript; CI/CD and security/deployment tooling are roadmap items unless repository evidence shows otherwise.

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

## Current verified project status — Phase D7.2

Phase C (Playwright End-to-End Browser Testing), Phase D1/D2 (CI Foundation & Automated Quality Gates), Phase D3 (Dependency Vulnerability Audit), Phase D4 (Container Security & Artifact Gate), Phase D5 (Headless Browser E2E in CI), and Python 3.13 Runtime Migration are merged to `main` (commit `43718a6`). Active development is on dedicated branch `feature/dast-integration`. Phase D7.1 (DAST Architecture & Read-Only Assessment) and Phase D7.2 (DAST Policy Validator & Exception Register) are implemented.

Phase D7.2 adds:
- **Dedicated Machine-Readable DAST Exception Register (`.github/security/dast-exceptions.json`):**
  - Strict JSON schema requiring `version: "1.0"` and `exceptions: [...]`.
  - Initially empty exception array (`"exceptions": []`) with zero speculative suppressions.
  - Strict field validation: `zap_rule_id` (numeric or string), `alert_name`, `target_url_pattern` (targeted regex path pattern), `severity` (`CRITICAL`, `HIGH`, `MEDIUM`), `reason` (minimum 10 characters), and canonical `expires_at` (`YYYY-MM-DD` through 23:59:59 UTC).
  - Explicit rejection of wildcard blanket suppressions (`.*`, `.+`, root wildcards) to ensure targeted endpoint scoping.
  - Automatic duplicate exception rejection and policy violation triggers for expired exceptions.
- **OWASP ZAP DAST Scan Validator (`scripts/validate_dast_scan.py`):**
  - Parses OWASP ZAP JSON reports robustly (`site[].alerts[]` or top-level `alerts[]`).
  - Evaluates alert instances with targeted URI regex matching to avoid broad suppression across unrelated endpoints sharing the same rule ID.
  - Normalizes ZAP risk codes (0–3) and risk descriptions (`High`, `Medium`, `Low`, `Informational`), strictly failing on unrecognized or missing severities.
  - Enforces severity policy: blocks on unapproved `CRITICAL`, `HIGH`, and `MEDIUM` findings; monitors `LOW` and `INFORMATIONAL` non-blocking.
  - Deterministic exit codes: 0 = pass/compliant, 1 = policy violation (unapproved High/Medium findings or expired exceptions), 2 = operational error (malformed report, invalid register schema, blanket suppressions, duplicate exceptions, scanner failures).
  - Emits console diagnostics and GitHub Step Summary (`$GITHUB_STEP_SUMMARY`) on all execution paths.
- **Automated DAST Validator Test Suite (`backend/tests/test_dast_scan_validator.py`):**
  - 24 automated unit and integration tests covering helper parsing, UTC date semantics, blanket suppression detection, severity normalization, clean reports, unapproved High/Medium findings, Low/Informational monitoring, valid exception matches, mismatched rule IDs, mismatched endpoint patterns, expired exceptions, duplicate exceptions, blanket suppression rejection, invalid report/register JSON, missing files, malformed alert structures, unknown severities, GitHub Step Summary output, scanner error statuses, and multi-instance partial matches.

Latest verified validation:
- Exception register JSON parsing: **clean** (Python `json.tool` validated, 0 entries / empty baseline).
- Validator test suite (`test_dast_scan_validator.py`): **24 passed in 2.08s**.
- Bytecode compilation (`compileall`): **compiled cleanly across `backend/app`, `backend/tests`, and `scripts` with 0 errors**.
- Ruff linter check (`ruff check .`): **0 errors / clean**.
- Mypy static type checking (`mypy backend/app scripts/validate_dast_scan.py`): **Success (0 issues in 41 source files)**.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase D roadmap:
- **D1:** GitHub Actions CI Foundation (Merged).
- **D2:** Static Analysis, Linting & Backend Automated Test CI Gates (Merged).
- **D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning & Exception Management) (Merged).
- **D4:** Container Image Build & Artifact Security Validation (Merged).
- **D5:** Headless Browser E2E Testing in CI (Merged).
- **D6:** PR Verification Policies & Quality Gates (Active ruleset ID `27123717` requiring 7 checks).
- **D7:** OWASP ZAP DAST Integration & Pipeline Hardening (D7.1 & D7.2 Implemented; D7.3 Orchestrator Pending).
- **D8:** Jenkins CD Pipeline Orchestration & Deployment.

Known limitations: Upstream Debian base OS packages in `python:3.13.18-slim` contain unpatched vulnerabilities covered by reviewed temporary exceptions in `.github/security/container-exceptions.json` through `2027-02-09`; application dependencies in `requirements-prod-lock.txt` have 0 known vulnerabilities; CVE-2026-119170 is completely absent on Python 3.13; Docker Hub publishing requires an authorized push event to `main` with configured repository secrets; DAST exceptions register starts empty; no malware scanning or sanitization; filesystem and database operations are not fully atomic. Active development is on `feature/dast-integration`. Never commit, push, reset, or amend without explicit authorization.
