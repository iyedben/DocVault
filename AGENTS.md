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

## Current verified project status — Phase D4.3

Phase C (Playwright End-to-End Browser Testing) is merged to `main` via PR #2. Phase D1/D2 CI Foundation and Automated Quality Gates are merged to `main` via PR #3. Phase D3 Dependency Security and Vulnerability Management is merged to `main` via PR #4 (`084a47f` -> merge commit `a7adbb1`). Active development is on dedicated branch `feature/container-security` based on `a7adbb19ebc1831002d258e851055e89b1f33e06` (`main`). Phase D4.2 & D4.3 implement Container Hardening, Vulnerability Validator, Debian snapshot zlib remediation, Controlled Container Exception Register, and Container Security CI Workflow.

Phase D4.2 & D4.3 add:
- **Dedicated Production Dependency Lockfile (`requirements-prod-lock.txt`):**
  - Contains exact pins for all 27 runtime packages and their transitive dependencies, derived directly from the audited `requirements-lock.txt`.
  - Excludes all 17 development, test, and linting tools (`pytest`, `ruff`, `mypy`, `coverage`, `httpx`, `playwright`, etc.) from production container images.
- **Hardened Container Build (`backend/Dockerfile` & `.dockerignore`):**
  - Pins base image to multi-arch index digest: `python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f`.
  - Installs production dependencies with `--no-deps` flag ensuring zero unpinned or dynamic resolution during container builds.
  - Hardened `.dockerignore` excluding `.git/`, `.github/`, `scripts/`, `backend/tests/`, `test-results/`, and temporary reports.
  - Container runs as non-root UID/GID 10001 (`docvault`), with read-only root filesystem, dropped capabilities (`cap_drop: ALL`), `no-new-privileges: true`, tmpfs on `/tmp`, and healthcheck verifying `/ready`.
- **Reproducible zlib Vulnerability Remediation (Commit `3642249`):**
  - Upgraded Debian package `zlib1g` to exact security snapshot version `1:1.3.dfsg+really1.3.1-1+deb13u1` (`snapshot.debian.org/archive/debian-security/20261108T000000Z`) with archive keyring verification, completely remediating `CVE-2026-76844` and `CVE-2026-85091`.
- **Machine-Readable Container Exception Register (`.github/security/container-exceptions.json`):**
  - Strict JSON schema requiring `version: "1.0"` and `exceptions: [...]`.
  - Strict validation of entry fields: `vulnerability_id` (CVE, GHSA, PYSEC), `package_name`, `affected_version`, `severity` (CRITICAL, HIGH), `reason`, `expires_at` (canonical `YYYY-MM-DD` through 23:59:59 UTC).
  - Populated with 59 exact package-level entries covering 17 distinct Debian OS CVEs (all tracked as `no-dsa`, `postponed`, or `point-release planned`) expiring on `2027-02-09`:
    - 12 standard exception candidates (21 package matches) for uninvoked, unmapped, or unused components (ncurses `infocmp`, gcc-14/libstdc++ binary heap UAF & operator new overflow, perl `Pod::Text` & `Archive::Tar`, libacl symlink & TOCTOU, sqlite3 FTS5 & Session overflows with SQLite unmapped in memory, and glibc `strfmon` / deprecated resolver printing flaws).
    - 5 conditional exception candidates (38 package matches) whose reachability is strictly mitigated by verified container isolation (glibc `gettext` `LANGUAGE` traversal conditioned on `LANG=C.UTF-8`, empty `/etc/fstab`, and read-only rootfs; util-linux `mount` flaws conditioned on non-root UID 10001, `CapEff=0`, `no-new-privileges`, and empty `/etc/fstab`; util-linux `nsenter` leak conditioned on host operator restraint from using `nsenter --join-cgroup`).
  - Automatic duplicate entry rejection and warnings for unused exceptions.
- **Grype Container Scan Validator (`scripts/validate_container_scan.py`):**
  - Validates Grype JSON scan reports against the container exception register.
  - Enforces severity policy: blocks on unapproved `CRITICAL` and `HIGH` findings; treats `MEDIUM`, `LOW`, `NEGLIGIBLE`, and `UNKNOWN` as monitored non-blocking.
  - Deterministic exit codes: 0 = pass/approved, 1 = policy violation (unapproved Critical/High), 2 = operational error (malformed JSON, invalid exceptions, scanner failure).
  - Emits console diagnostics and GitHub Step Summary (`$GITHUB_STEP_SUMMARY`) on all exit paths.
- **Container Security CI Workflow (`.github/workflows/container-security.yml`):**
  - Implements automated `Container Security & Artifact Gate` workflow with least-privilege `permissions: contents: read` and concurrency controls.
  - Build → Scan → Validate → Publish pipeline:
    - `build`: Builds production image, records Image ID, saves image archive, generates SHA-256 checksum, and uploads archive artifact with 1-day retention.
    - `scan`: Downloads image archive, verifies checksum before loading, verifies loaded Image ID against build record, scans with Grype (`anchore/scan-action@8576240a41341d866dbd7ebc72cd9fc0ef023f54`), validates findings against `.github/security/container-exceptions.json`, emits Step Summary, uploads scan report with 7-day retention (`if: always()`), and uploads scanned metadata.
    - `publish`: Runs strictly on push to `main`, never on PRs or feature branch. Downloads image archive and scanned metadata, verifies archive checksum, loads image into Docker, verifies loaded image ID against both build and scan records, validates presence of `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets (failing clearly if missing), authenticates via `docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567`, pushes immutable commit-SHA tag (`${{ github.sha }}`) and `latest` to `iyedbnaissa/docvault-api`, and captures `RepoDigest`.
- **Local Container Scan Helper (`scripts/run_container_scan.sh`):**
  - Developer script to scan local Docker images (`docvault-api:local`) via host `grype` binary or fallback `anchore/grype:latest` container.
- **Automated Validator and Workflow Test Suites:**
  - `backend/tests/test_container_scan_validator.py`: 24 automated unit and integration tests covering helper parsing, schema validation, Grype match extraction, severity gating, alias matching, expiration handling, unused warnings, scanner failures, and Step Summary formatting.
  - `backend/tests/test_container_security_workflow.py`: 11 automated unit tests validating workflow triggers, concurrency, permissions (`contents: read`), job dependency graph, publish isolation conditions, Docker Hub secrets isolation, action commit SHA pinning, Grype integration, artifact retention, and image checksum/ID verification.
- **Remediation vs Risk Acceptance Distinction & Operational Assumptions:**
  - Distinction: Remediation eliminates vulnerable code at build time (e.g. `zlib1g` upgrade); Risk Acceptance temporarily permits unpatched OS findings under technical reachability proofs.
  - Invariants: Non-root execution (UID 10001), `cap_drop: ALL`, `no-new-privileges: true`, read-only rootfs, `noexec` on `/tmp`, unconfigured `/etc/fstab`, `LANG=C.UTF-8` with `LANGUAGE` unset, UUID-only storage, and absence of host-side `nsenter --join-cgroup`.
  - Reassessment: Mandatory upon any change to base image digest, package versions, container configuration, or orchestration practices, or by `2027-02-09`.

Latest verified validation:
- Exception register JSON parsing: **clean** (Python `json.tool` validated, 59 active entries).
- Grype scan validation: **0 unapproved Critical/High, 59 approved exceptions, 0 unused warnings (exit code 0)**.
- Workflow YAML validation: **clean and valid**.
- Bytecode compilation (`compileall`): **compiled cleanly across `backend/app`, `backend/tests`, and `scripts` with 0 errors**.
- Ruff linter check (`ruff check .`): **0 errors / clean**.
- Mypy static type checking (`mypy backend/app scripts/validate_container_scan.py`): **Success (0 issues in 41 source files)**.
- Validator test suite (`test_container_scan_validator.py`): **24 passed in 0.83s**.
- Workflow test suite (`test_container_security_workflow.py`): **11 passed in 0.28s**.
- Complete backend regression test suite: **388 passed, 6 skipped** in 29.78s.
- Container image build: **`docvault-api:local` built cleanly (286MB disk usage, 66.8MB content size)**.
- Container runtime verification: **`docvault-api-1` running, healthy, `/health` and `/ready` return HTTP 200 OK**.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase D roadmap:
- **D1:** GitHub Actions CI Foundation (Merged).
- **D2:** Static Analysis, Linting & Backend Automated Test CI Gates (Merged).
- **D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning & Exception Management) (Merged).
- **D4:** Container Image Build & Artifact Security Validation (D4.2 & D4.3 Implemented; Docker Hub Publishing on main Pending PR merge).
- **D5:** Headless Browser E2E Testing in CI.
- **D6:** PR Verification Policies & Quality Gates.
- **D7:** Pipeline Hardening & CI Performance Optimization.
- **D8:** Jenkins CD Pipeline Orchestration & Deployment.

Known limitations: Upstream Debian base OS packages in `python:3.14-slim` contain unpatched vulnerabilities covered by reviewed temporary exceptions in `.github/security/container-exceptions.json` through `2027-02-09`; application dependencies in `requirements-prod-lock.txt` have 0 known vulnerabilities; Docker Hub publishing requires an authorized push event to `main` with configured repository secrets (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`) and was not executed from the feature branch; no malware scanning or sanitization; filesystem and database operations are not fully atomic. Active development is on `feature/container-security`. Never commit, push, reset, or amend without explicit authorization.
