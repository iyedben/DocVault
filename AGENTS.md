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

## Current verified project status — Phase 4.4

Phase 4.4 document management implementation is present in the current uncommitted worktree. The API provides upload, list, metadata, download, delete, and share list/grant/revoke operations. Document access is restricted to owners and explicit active recipients; administrator status alone does not grant access. Cookie-authenticated state changes require CSRF validation.

PDF upload validation checks the `.pdf` filename extension, declared `application/pdf` media type, signature, nonempty content, 10 MiB maximum size, and structural parsing with pinned `pypdf`. Structural validation is not malware scanning or PDF sanitization. Documents use a private volume, opaque UUID storage keys, descriptor-relative filesystem operations, restrictive permissions, staging/promotion, and tombstone-based deletion. PostgreSQL sharing and deletion behavior has focused integration coverage; database and filesystem operations are not fully atomic.

Latest reported validation: backend suite **210 passed, 6 skipped**; focused document API/storage/validation tests **147 passed**; isolated PostgreSQL integration **5 passed** on PostgreSQL 17.11; Ruff, Mypy (43 files), and `git diff --check` passed. The isolated Docker HTTP workflow recorded **41 checks passed**. Runtime checks recorded UID/GID 10001, private storage permissions, read-only root filesystem, dropped capabilities, and no-new-privileges. After API restart, `/ready` and download returned HTTP 200 and the downloaded file SHA-256 matched the uploaded file. An earlier apparent readiness failure was traced to the harness using a stale ephemeral host port after restart; the refreshed port succeeded. `/health` was not re-polled on that refreshed port. These are recorded verification results; do not assume they validate future code revisions.

An upload read-failure cleanup defect was fixed: failure from `UploadFile.read()` now returns a safe error and best-effort cleanup removes the staging file without masking the original failure. Regression tests confirm no new record or stage remains and existing documents are unaffected. The cleanup-failure test also confirms the original upload error remains visible as the safe API response.

Known limitations: no malware scanning or sanitization; no automatic orphan-file reconciliation; no dedicated process-crash recovery; filesystem and database operations are not fully atomic. Frontend, CI/CD, security tooling, Kubernetes deployment, and final repository acceptance are still pending. Current Phase 4.4 work is uncommitted. Final repository review, staging, commit, and push are pending and require explicit authorization. Preserve all existing changes and inspect the complete worktree before any further edits.
