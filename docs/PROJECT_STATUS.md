# DocVault project status and handover

**Inspected:** 7 November 2026. **Branch:** `feature/frontend`. Baseline checkpoint `dbf1cfa` (`feat(frontend): establish secure frontend foundation`). The worktree contains Phase B2 authentication and session management integration changes. No commit or push has been performed for Phase B2. This record distinguishes verified results from remaining limitations.

## Project and architecture

DocVault is an academic secure document management and DevSecOps project. Its backend is Python 3.14/FastAPI with SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker Compose runs PostgreSQL, a one-shot migration service, and the API. The API runs as UID/GID 10001 with a read-only root filesystem and a dedicated document volume; PostgreSQL is not host-published and the API binds to loopback. Application code is in `backend/app` (routes, configuration, database, models, security, services, storage, middleware); migrations and tests are in `backend/migrations` and `backend/tests`. Frontend code is in `frontend/` (SPA shell in `index.html`, vendored Bootstrap 5.3.3 in `static/vendor/` and `static/css/`, and modular ES2022 JavaScript in `static/js/`). CI/CD pipeline expansion and Kubernetes are subsequent roadmap items. The project is not production-ready.

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
- **Phase B1 — Frontend Foundation & FastAPI Integration (Current Worktree on `feature/frontend`):**
  - **B1.1 — SPA Shell:** Modern HTML5/CSS3 application shell with dark navy navbar (`#0f172a`), responsive sidebar, main container, global alerts area, and loading states.
  - **B1.2 — Local Vendoring:** Bootstrap v5.3.3 (`bootstrap.min.css`, `bootstrap.bundle.min.js`) locally vendored under MIT license with verified SHA-256 digests in `frontend/static/vendor/VENDOR.md`. Zero external CDN requests.
  - **B1.3 — Vanilla JS Architecture:** Modular ES2022 modules (`app.js`, `api.js`, `auth.js`, `router.js`, `components/navbar.js`, `components/alerts.js`, `components/loading.js`, `utils/dom.js`). Safe DOM construction via `textContent` and `createElement` (strictly prohibiting `innerHTML` on untrusted data).
  - **B1.4 — FastAPI Integration:** `StaticFiles` mounted at `/static`, `GET /` serving `index.html` with `Cache-Control: no-cache`, `/favicon.ico` route, and non-shadowing routing order.
  - **B1.5 — Security Headers & CSP:** Verified full inheritance of `SecurityHeadersMiddleware` (`CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`). Zero inline scripts or styles.
  - **B1.6 — Docker Image & Runtime:** Updated `backend/Dockerfile` to copy `frontend/` into `/app/frontend` with non-root ownership (UID 10001). Rebuilt image `docvault-api:local` and verified live HTTP responses over loopback.
- **Phase B2 — Authentication & Session Integration (Current Worktree on `feature/frontend`):**
  - **B2.1 — In-Memory Auth State:** `auth-state.js` maintains transient user metadata (`id`, `username`, `role`) and reactive lifecycle states (`initializing`, `anonymous`, `authenticated`, `logging_out`). Zero browser persistence (no `localStorage`, `sessionStorage`, or `IndexedDB`).
  - **B2.2 — Single-Flight CSRF Refresh & API Interception:** `api.js` provides single-flight promise deduplication for `POST /api/v1/auth/csrf` to prevent race conditions during concurrent recovery; automatically injects `X-CSRF-Token` on state-changing requests; intercepts 401 Unauthorized globally without recursive loops; synchronizes 403 CSRF token rejections.
  - **B2.3 — Login View & Safe DOM:** `views/login.js` provides an accessible card layout, username/password validation, password reveal toggle with SVG icons, client-side validation, accessible alert banners, and double-submit protection with loading spinner. All DOM manipulation uses `textContent` and `createElement` via `dom.js`.
  - **B2.4 — Reactive Role-Aware Navigation:** `components/navbar.js` renders brand, dynamic user pill (`username` + `role`), sign-out button, and role-gated navigation items (admin sees "Administration", standard user does not).
  - **B2.5 — Session Bootstrap, Route Guarding & Logout Safety:** `app.js` and `router.js` restore sessions on startup (`POST /csrf` -> `GET /me`); redirect unauthenticated route attempts to `/login`; prevent non-admin access to admin routes. `auth.js` enforces strict logout safety: clears local state only upon confirmed HTTP 204 (or reconciled 401); network and server failures retain authenticated state and display error alerts without creating false logout states.
  - **B2.6 — Zero-Automatic-Retry Policy & Explicit CSRF Handling:** `api.js` strictly prohibits automatic retries for state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`). Generic HTTP 403s are never retried and do not rotate CSRF tokens. Explicit `CSRF validation failed` responses synchronize the token in the background via single-flight `refreshCsrfToken()` for subsequent user actions while returning the error directly.
  - **B2.7 — Frontend Auth & Security Integration Test Suite:** Added `backend/tests/test_frontend_auth_integration.py` (16 test cases) testing anonymous guards, regular/admin login, session restoration, expired session failure, CSRF rotation on logout, server-side session invalidation, rate limiting (429), successful logout (204), network failure resilience, unexpected server failure (500) rollback, session restoration after failed logout, state-changing CSRF rejection without side effects, no duplicate execution, and generic 403 authorization denials without CSRF rotation.

## Phase A, B1 & B2 Endpoints & Contracts

| Method & Path | Auth & CSRF | Purpose & Contract |
|---|---|---|
| `GET /` | Public / Same-Origin | Serves frontend SPA shell (`index.html`) with `Cache-Control: no-cache` and global security headers. |
| `GET /static/*` | Public / Same-Origin | Serves locally vendored CSS, JavaScript, and asset files. |
| `GET /favicon.ico` | Public | Serves DocVault SVG favicon. |
| `POST /api/v1/auth/login` | Public (Rate limited) | Authenticates credentials (`{"username": "...", "password": "..."}`). Sets `docvault_session` cookie (`Path=/api/v1; HttpOnly; SameSite=lax`), returns `{"csrf_token": "...", "user": {"id": "...", "username": "...", "role": "..."}}`. |
| `POST /api/v1/auth/logout` | Active session cookie + `X-CSRF-Token` | Revokes server session in PostgreSQL, deletes `docvault_session` cookie (`Max-Age=0`), returns 204 No Content. |
| `GET /api/v1/auth/me` | Active session cookie | Returns authenticated user details `{"id": "...", "username": "...", "role": "..."}`. Returns 401 if unauthenticated/expired. |
| `POST /api/v1/auth/csrf` | Active session cookie; Origin / Fetch Metadata validation | Rotates and returns fresh `{"csrf_token": "..."}` for authenticated session bootstrap. Rejects cross-site/navigation requests. Response sets `Cache-Control: private, no-store`. |
| `GET /api/v1/users/lookup?username={query}` | Active session cookie | Case-insensitive partial username search (min 2, max 32 chars). Returns `[{"id": "<uuid>", "username": "<name>"}]` for active users only (max 10 results). |
| `POST /api/v1/auth/password` | Active session cookie + `X-CSRF-Token` | Changes password (`{"current_password": "...", "new_password": "..."}`). Revokes all other user sessions, keeps current session active, rotates and returns new CSRF token. |

## Verification update — 7 November 2026

- `PYTHONPATH=backend .venv/bin/pytest backend/tests -q`: **268 passed, 6 skipped** in 15.38s.
- `PYTHONPATH=backend .venv/bin/pytest backend/tests/test_frontend_auth_integration.py -v`: **16 passed** in 6.85s.
- `scripts/run_phase3_pg_concurrency_test.sh`: **1 passed** (PostgreSQL advisory-lock administrator concurrency) in 0.70s.
- `scripts/run_phase4_pg_document_tests.sh`: **5 passed** on **PostgreSQL 17.11** (isolated document integration, deletion tombstones, concurrent shares, failure compensation) in 2.52s.
- `.venv/bin/ruff check backend`: passed with 0 errors.
- `MYPYPATH=backend .venv/bin/mypy backend/app backend/migrations backend/tests/test_frontend.py backend/tests/test_frontend_auth_integration.py`: passed with 0 issues in 47 files.
- `git diff --check`: passed with 0 issues.
- `curl -fsS -i http://127.0.0.1:8000/`: HTTP 200 OK, `text/html; charset=utf-8`, `cache-control: no-cache`, security headers verified.
- `curl -fsS -i http://127.0.0.1:8000/static/css/bootstrap.min.css`: HTTP 200 OK, `text/css; charset=utf-8`, security headers verified.
- `curl -fsS -i http://127.0.0.1:8000/static/js/app.js`: HTTP 200 OK, `text/javascript; charset=utf-8`, security headers verified.
- `curl -fsS -i http://127.0.0.1:8000/static/js/auth-state.js`: HTTP 200 OK, `text/javascript; charset=utf-8`, security headers verified.
- `curl -fsS -i http://127.0.0.1:8000/static/js/views/login.js`: HTTP 200 OK, `text/javascript; charset=utf-8`, security headers verified.
- `curl -fsS http://127.0.0.1:8000/health`: `{"status":"ok"}`.
- `curl -fsS http://127.0.0.1:8000/ready`: `{"status":"ready"}`.
- Live API authentication checks over HTTP loopback:
  - `GET /api/v1/auth/me` without cookie returns 401 `{"detail":"Authentication required"}` with `Cache-Control: private, no-store`.
  - `POST /api/v1/auth/login` with invalid credentials returns 401 `{"detail":"Invalid username or password"}` with safe error message.

## Remaining work

- **Phase B3 — Document Management Workspace:** Interactive document list, drag-and-drop PDF upload modal, client validation, and direct download.
- **Phase B4 — Document Sharing & User Lookup:** User lookup debouncing and access control modals.
- **Phase B5 — Self-Service Settings:** In-session password change form.
- **Phase B6 — Administration Console:** Role-gated admin user management.
- **Phase B7 — Frontend Polish & Security Audit:** Accessibility, DOM XSS review, and final acceptance.
- **Phase C — End-to-End Browser Validation:** Playwright/browser workflow validation.
- **Phase D — CI/CD Pipeline & Acceptance:** GitHub Actions expansion and deployment.

## Known limitations

Phase B2 completes authentication and session management integration. Document management workflows, sharing, self-service password changes, and administrator management UI are roadmap items for Phases B3–B6. No malware scanning or PDF sanitization; database and filesystem operations are not fully atomic. All work is on `feature/frontend` and uncommitted. Final repository review, staging, commit, and push require explicit authorization.
