# DocVault project status and handover

**Inspected:** 7 November 2026. **Branch:** `main`. Latest commit is `2444557` (`add security workflow`), following `2cbbfff` (`feat: implement secure document management API`). The worktree contains Phase A backend API completion and security polish changes. No commit or push has been performed for Phase A. This record distinguishes verified results from remaining limitations.

## Project and architecture

DocVault is an academic secure document management and DevSecOps project. Its backend is Python 3.14/FastAPI with SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker Compose runs PostgreSQL, a one-shot migration service, and the API. The API runs as UID/GID 10001 with a read-only root filesystem and a dedicated document volume; PostgreSQL is not host-published and the API binds to loopback. Application code is in `backend/app` (routes, configuration, database, models, security, services, storage, middleware); migrations and tests are in `backend/migrations` and `backend/tests`. Frontend, CI/CD pipeline expansion, and Kubernetes are subsequent roadmap items. The project is not production-ready.

Security architecture includes Argon2id, PostgreSQL-backed opaque server sessions, CSRF on authenticated state changes, role checks, separate app/migrator database accounts, private filesystem storage with generated keys, global security headers, and CSRF token recovery. Document access must be owner or explicit sharee; administrator role alone does not imply document access. Secrets are kept out of logs/docs and container/network boundaries are preserved.

## Completed phases and verified record

- **Phases 0–1:** environment audit, Docker installation, and isolated Compose smoke check are documented in their phase reports.
- **Phase 2A–2C:** Python development environment, PostgreSQL deployment, FastAPI health/readiness endpoints and Compose architecture are documented.
- **Phase 3:** identity, authentication, sessions, CSRF, RBAC, and administrator management are implemented and committed (`385d32d`).
- **Phase 4.1–4.4:** secure document management API (upload, download, metadata, deletion tombstone, sharing, PDF structural validation via `pypdf`, descriptor-relative private storage) is implemented and committed (`eedd07b`, `80e42e9`, `2cbbfff`).
- **Security workflow:** GitHub Actions Gitleaks and Semgrep automated checks committed (`2444557`).
- **Phase A — Backend API completion & security polish:**
  - **A1 — CSRF recovery & bootstrap:** `POST /api/v1/auth/csrf` provides authenticated sessions with a freshly rotated CSRF token after browser reload. Validates origin and fetch metadata (`Sec-Fetch-Site`, `Sec-Fetch-Mode`), rejects cross-site/navigation requests, stores SHA-256 digest in PostgreSQL, and returns raw token to caller with `Cache-Control: private, no-store`.
  - **A2 — User lookup:** `GET /api/v1/users/lookup?username={query}` allows authenticated users to search active users for document sharing by case-insensitive partial match with minimum length and result limits.
  - **A3 — Global security headers:** `SecurityHeadersMiddleware` centralizes CSP (`default-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, conditional HSTS, and `Cache-Control: private, no-store` on API routes, with a documented development exception for `/docs` and `/redoc`.
  - **A4 — Self-service password change:** `POST /api/v1/auth/password` allows authenticated users to update their password with Argon2id current password verification, Pydantic password policy enforcement, atomic revocation of other active sessions, and CSRF token rotation on the active session.
  - **A5 — Testing & verification:** Complete backend suite increased from 210 to **246 passed, 6 skipped** (PostgreSQL-dependent tests). Isolated PostgreSQL test runners verified: `scripts/run_phase3_pg_concurrency_test.sh` (**1 passed**), `scripts/run_phase4_pg_document_tests.sh` (**5 passed** on PostgreSQL 17.11). Ruff, Mypy (45 source files + 4 test files, 0 issues), and `git diff --check` passed cleanly.

## Phase A API Endpoints & Contracts

| Method & Path | Auth & CSRF | Purpose & Contract |
|---|---|---|
| `POST /api/v1/auth/csrf` | Active session cookie; Origin / Fetch Metadata validation | Rotates and returns fresh `{"csrf_token": "..."}` for authenticated session bootstrap. Rejects cross-site/navigation requests. Response sets `Cache-Control: private, no-store`. |
| `GET /api/v1/users/lookup?username={query}` | Active session cookie | Case-insensitive partial username search (min 2, max 32 chars). Returns `[{"id": "<uuid>", "username": "<name>"}]` for active users only (max 10 results). |
| `POST /api/v1/auth/password` | Active session cookie + `X-CSRF-Token` | Changes password (`{"current_password": "...", "new_password": "..."}`). Revokes all other user sessions, keeps current session active, rotates and returns new CSRF token. |

## Verification update — 7 November 2026

- `PYTHONPATH=backend .venv/bin/pytest backend/tests -q`: **246 passed, 6 skipped** in 12.14s.
- `scripts/run_phase3_pg_concurrency_test.sh`: **1 passed** (PostgreSQL advisory-lock administrator concurrency).
- `scripts/run_phase4_pg_document_tests.sh`: **5 passed** on **PostgreSQL 17.11** (isolated document integration, deletion tombstones, concurrent shares, failure compensation).
- `.venv/bin/ruff check backend`: passed with 0 errors.
- `MYPYPATH=backend .venv/bin/mypy backend/app backend/migrations`: passed with 0 issues in 45 files.
- `MYPYPATH=backend .venv/bin/mypy backend/tests/test_csrf_recovery.py backend/tests/test_user_lookup.py backend/tests/test_password_change.py backend/tests/test_security_headers.py`: passed with 0 issues in 4 files.
- `git diff --check`: passed with 0 issues.

## Remaining work

- **Phase B — Lightweight Frontend:** Implement single-page interface using HTML5, CSS3, Bootstrap 5, and modular vanilla JavaScript. Serve via FastAPI static files or dedicated proxy.
- **Phase C — End-to-End Browser Validation:** Validate complete workflows in browser runtime (login, document lifecycle, sharing, session reload, and negative security checks).
- **Phase D — CI/CD Pipeline & Repository Acceptance:** Expand GitHub Actions to run pytest, ruff, mypy, Grype, and Syft. Complete final repository review and push under explicit authorization.

## Known limitations

No malware scanning or PDF sanitization; no automatic orphan-file reconciliation on process crash; database and filesystem operations are not fully atomic; no public self-registration or password recovery (governed by administrator provisioning). Current Phase A work is uncommitted. Final repository review, staging, commit, and push require explicit authorization.
