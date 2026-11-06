# DocVault project status and handover

**Inspected:** 6 November 2026. **Branch:** `main`. Latest commit is `80e42e9` (`feat: implement secure document filesystem storage`). The worktree contains uncommitted Phase 4.4 implementation and documentation changes. No commit or push has been performed for Phase 4.4. Final repository review, staging, commit, and push are still pending. This record distinguishes verified results from remaining limitations.

## Project and architecture

DocVault is an academic secure document management and DevSecOps project. Its backend is Python 3.14/FastAPI with SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker Compose runs PostgreSQL, a one-shot migration service, and the API. The API runs as UID/GID 10001 with a read-only root filesystem and a dedicated document volume; PostgreSQL is not host-published and the API binds to loopback. Application code is in `backend/app` (routes, configuration, database, models, security, services, storage, middleware); migrations and tests are in `backend/migrations` and `backend/tests`. Phase 4.4 is document API work in this repository's numbering. Frontend, CI/CD, scanners, and Kubernetes are later work. The project is not production-ready.

Security architecture includes Argon2id, PostgreSQL-backed opaque server sessions, CSRF on authenticated state changes, role checks, separate app/migrator database accounts, and private filesystem storage with generated keys. Document access must be owner or explicit sharee; administrator role alone does not imply document access. Keep secrets out of logs/docs and preserve container/network boundaries.

## Completed phases and verified record

- **Phases 0–1:** environment audit, Docker installation, and isolated Compose smoke check are documented in their phase reports. The Nginx smoke check is infrastructure validation, not DocVault application validation.
- **Phase 2A–2C:** Python development environment, PostgreSQL deployment, FastAPI health/readiness endpoints and Compose architecture are documented. Phase 2C reports prior manual HTTP 200 checks for `/health` and `/ready`; they do not validate later authentication or document revisions.
- **Phase 3:** identity, authentication, sessions, CSRF, RBAC, and administrator management are implemented. The phase report records 39 pytest tests passing (PostgreSQL concurrency test excluded), 35/35 manually executed HTTP checks, Ruff and mypy success, and prior Compose configuration parsing. It explicitly says Phase 3 image build, migration execution, live authenticated startup, and PostgreSQL advisory-lock concurrency were not verified. These are historical reported results, not rerun for this handover.
- **Phase 4.1 — validation/configuration:** committed in `eedd07b` (`eedd07b45044bd4d4ed8c4edeb30c5f562d7f5d0`): validated document storage and size settings plus filename/PDF metadata, signature, and size validation. The commit adds validation tests, but this inspection did not execute them.
- **Phase 4.2 — models/migration:** also committed in `eedd07b`: `Document` and `DocumentShare` models, user relationships, and Alembic revision `0002_documents`, with migration/constraint tests. Do not edit this applied migration; use a new revision for future schema changes.
- **Phase 4.3 — secure filesystem storage:** committed in `80e42e9` (`80e42e9cbdf84be2946aabe90c6ef51e1ad1fc75`): descriptor-relative private storage, restrictive modes, opaque UUID keys, bounded writes and file operations, storage tests, Docker mount point and Compose document volume. Test outcomes and live volume/runtime verification for Phases 4.1–4.3 are not established by the current handover inspection; do not infer results from test files or existing bytecode.

## Git milestones and publication

Verified history includes `0cd531e` — Phase 2C FastAPI/PostgreSQL foundation; `385d32d` — Phase 3 authentication/access control; `eedd07b` — Phase 4.1 and 4.2; and `80e42e9` — Phase 4.3. All four are on current `main` and `origin/main` as observed. There are no unpushed commits in the inspected status. Current Phase 4.4 changes are uncommitted and therefore not pushed.

Current working tree at inspection:

- Modified: `backend/app/main.py`, `backend/app/security/document_validation.py`, `backend/tests/test_document_validation.py`, `requirements.txt`, and `requirements-lock.txt`.
- Untracked: this handover and `AGENTS.md`; document schemas/routes, middleware, and service; PDF fixtures and document API tests; PostgreSQL document integration tests, their isolated Compose file, and runner.
- Preserve these changes. The PostgreSQL test runner does not modify application production code or migrations.

## Phase 4.4 — document API and workflow progress

The repository contains substantial, **uncommitted Phase 4.4** work; it is not unstarted. Implemented API operations are upload, list, metadata, download, deletion, share listing, share grant, and share revocation. Authentication and CSRF protect cookie-authenticated state changes. Owners and explicitly shared active recipients receive access according to the route/service checks; unrelated users and administrators without an explicit share do not receive implicit access. Inaccessible documents return 404.

- A documents router wired into the FastAPI app; upload, list/metadata, download, delete, and share operations are represented in the new route module.
- New document response schemas and DB query helpers for owner/explicit-share authorization, active recipient checks, and document access.
- Middleware for private cache/security headers, a single in-process upload admission slot, and request-body limits. Multipart dependency `python-multipart==0.0.32` was added to both requirements files.
- Streaming upload validation changes, audit events, and HTTP API tests using `httpx.ASGITransport`, SQLite, and temporary storage.
- PDF structural validation uses pinned `pypdf`, in addition to extension, media type, signature, nonempty content, and the preserved 10 MiB limit. This is structural validation only; it is not malware scanning or sanitization.
- A staging cleanup defect where `UploadFile.read()` raising `OSError` left a stage file was corrected. Cleanup is attempted on failure without masking the original upload failure. Regression tests verify the safe error response, no residual stage or new record, preservation of existing documents, and behavior when cleanup itself raises.
- Private storage uses opaque UUID keys and descriptor-relative operations with restrictive permissions and staging/promotion. Deletion commits a `deleting` tombstone before unlinking; retries and failure cases are covered. Database and filesystem operations are not fully atomic.

The implementation findings above are code-inspection findings and do not alone establish acceptance. Focused API and PostgreSQL results are recorded below. Docker build/runtime, multipart-spool behavior, private-volume runtime/persistence, full manual HTTP/security checks, and real process-crash recovery remain unverified or deferred. Review the implementation against `docs/PHASE_4_DOCUMENT_MANAGEMENT_PLAN.md`; do not equate code or tests alone with full phase acceptance.

### Verification update — 5 November 2026

- `PYTHONPATH=backend .venv/bin/pytest backend/tests/test_document_api.py backend/tests/test_document_storage.py backend/tests/test_document_validation.py -q`: **147 passed** against SQLite and temporary storage.
- Complete backend suite: **210 passed, 6 skipped**.
- `scripts/run_phase4_pg_document_tests.sh`: **5 passed** against **PostgreSQL 17.11**. The isolated Compose project used a per-run generated PostgreSQL username and password, loopback-only random port, and tmpfs database directory. The fixture created and dropped a uniquely named database after applying the repository migrations.
- PostgreSQL concurrency evidence: simultaneous API grant requests using independent sessions returned exactly one `201` and one `409`, with one share row. Two independent concurrent inserts on a separate document produced one successful commit and one unique-constraint conflict, with one row remaining.
- PostgreSQL deletion ordering evidence: while the deletion thread was paused immediately before unlink, an independent database session observed the committed `deleting` state and the file was still readable. Concurrent download and grant requests during that pause returned `404`.
- PostgreSQL failure evidence: a filesystem failure left a committed, inaccessible tombstone. A test-only deferred constraint trigger forced the final DB cleanup transaction to fail at commit after file unlink; the tombstone remained inaccessible, and a retry completed after the trigger was removed.
- Cleanup: the runner exited successfully; verification found no matching test container, network, or private runner directory. Its DB lived only in the disposable container's tmpfs. Document test files were stored in pytest temporary storage.
- `.venv/bin/ruff check backend`: passed. `MYPYPATH=backend .venv/bin/mypy backend/app backend/migrations`: no issues in 43 files. `git diff --check`: passed after the upload cleanup correction.
- Isolated Docker HTTP workflow: **41 checks passed**. Runtime observations verified API UID/GID 10001, expected document storage ownership and permissions, read-only root filesystem, dropped capabilities, no-new-privileges, intended private volume mount, and PostgreSQL isolation from public host exposure.
- Persistence after API restart was verified: `/ready` returned HTTP 200, the previously uploaded dummy document downloaded with HTTP 200, and its SHA-256 matched the pre-restart hash. The earlier apparent readiness failure was caused by the test harness continuing to use a stale ephemeral host port after container restart. Using the refreshed port succeeded. `/health` was not re-polled on the refreshed port in that final persistence diagnostic; `/ready` and Docker health checks passed.
- No Phase 4.4 commit or push has been made. Current branch is `main`; current worktree includes the pre-existing uncommitted implementation and documentation files. Final comprehensive repository review, staging, commit, and push remain pending.
- **Process-crash recovery remains deferred.** These tests inject filesystem and PostgreSQL transaction failures; they do not kill a process or API container, prove recovery after a real crash, or add startup orphan reconciliation. No development API container was killed.

## Remaining work

- Complete and validate Phase 4.4 against the Phase 4 plan; record exact automated/static/runtime results and limitations.
- **Frontend:** not started in inspected repository; build the planned browser interface after API contract stabilizes.
- **CI/CD:** Jenkins pipeline and planned Semgrep, Gitleaks, Grype, Syft, Checkov, and ZAP integration are not implemented/verified.
- **Security testing:** complete the authorization/IDOR, upload-abuse, failure/retry, audit-redaction, and PostgreSQL concurrency checks; retain truthful evidence.
- **Kubernetes deployment:** Minikube/Helm/Calico deployment and NetworkPolicy enforcement are planned, not implemented/verified.
- **Final validation:** run the required end-to-end and operational checks, verify build/migrations/runtime on the intended isolated environment, document residual risks, and update project records.

## Exact next actions

1. Perform the final comprehensive Phase 4.4 repository review, including the full diff, dependencies, configuration, tests, secret/artifact checks, and current project plan requirements.
2. Run the final required validation for the reviewed state (backend suite, isolated PostgreSQL integration, Ruff, Mypy, Compose validation, and `git diff --check`); do not infer results from this handover if files change.
3. Resolve and document review findings without disturbing unrelated work. Review/stage only intended Phase 4.4 files after confirming the full worktree contents.
4. Commit and push only when explicitly authorized. At the time of this handover no Phase 4.4 commit or push exists.

Deferred limitations remain: no malware scanning or PDF sanitization, no automatic orphan-file reconciliation, no dedicated process-crash recovery mechanism, and filesystem/database operations are not fully atomic. Frontend, CI/CD, security testing beyond the completed document/API coverage, Kubernetes deployment, and final validation remain future work.
