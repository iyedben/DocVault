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

## Current verified project status — Phase A

Phase 4.4 document management (`2cbbfff`) and GitHub Actions security workflow (`2444557`) are committed to `main`. Phase A backend completion and security polish implementation is present in the current uncommitted worktree.

Phase A adds:
- `POST /api/v1/auth/csrf`: CSRF token bootstrap for authenticated sessions with origin / fetch metadata validation, cryptographic rotation, and `Cache-Control: private, no-store`.
- `GET /api/v1/users/lookup`: case-insensitive partial username search for document sharing (minimal safe schema, active users only, bounded query and results).
- `SecurityHeadersMiddleware`: application-wide HTTP security headers (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, conditional HSTS, API `Cache-Control: private, no-store`, deduplication).
- `POST /api/v1/auth/password`: self-service password change with Argon2id current password verification, Pydantic password policy, atomic revocation of other active sessions, and active session CSRF rotation.

Latest verified validation: backend suite **246 passed, 6 skipped**; isolated PostgreSQL concurrency integration **1 passed**; isolated PostgreSQL document integration **5 passed** on PostgreSQL 17.11; Ruff, Mypy (45 source files + 4 test files), and `git diff --check` passed cleanly.

Known limitations: no malware scanning or sanitization; no automatic orphan-file reconciliation; no dedicated process-crash recovery; filesystem and database operations are not fully atomic. Frontend (Phase B), end-to-end browser validation (Phase C), CI/CD pipeline expansion, and final repository acceptance are pending. Current Phase A work is uncommitted. Final repository review, staging, commit, and push require explicit authorization. Preserve all existing changes and inspect the complete worktree before any further edits.
