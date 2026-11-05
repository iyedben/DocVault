# DocVault Project Execution Log

**Project:** DocVault — Secure Document Management Platform  
**Record status:** Living project history; development is ongoing.  
**Evidence basis:** Repository documentation and Git history inspected on 5 November 2026.

## 1. Purpose and record policy

This log is the central technical history and evidence index for the academic DevSecOps project. It consolidates completed implementation phases, architecture and security decisions, actual validation results, known limits, deferred work, and Git milestones. Phase reports remain the detailed records for their respective work; this document links to them rather than replacing them.

Only observed or reported outcomes are recorded as results. Proposed capabilities, planned tools, and unexecuted checks are identified as such. The repository documentation distinguishes evidence obtained in the standalone Ubuntu VM from observations made in the restricted audit or development shell; this log preserves that distinction. No evidence filename is implied where none has been supplied.

## 2. Project status and scope

The implemented foundation includes container infrastructure, PostgreSQL, a FastAPI backend, identity, authentication, sessions, and administrator user management. Document upload, storage, retrieval, download, sharing, browser frontend, Jenkins CI/CD, security scanning, and Kubernetes deployment are not implemented in this recorded scope. The project is under development and is not production-ready.

The architecture documents include a broader academic roadmap and vulnerability scenarios. Those are project plans, not evidence of implemented or validated features.

## 3. Environment and constraints — Phase 0

The target environment described in the project records is an Ubuntu Server 26.04.1 LTS guest hosted by Oracle VirtualBox and accessed over SSH/MobaXterm. The standalone VM evidence confirms the virtualization environment but does not supply its CPU, memory, storage, kernel, or network measurements. Those VM resource details therefore remain unverified.

The Phase 0 audit shell reported x86_64 Ubuntu 26.04.1 LTS, four CPUs, approximately 7.3 GiB RAM, 4 GiB swap, and a 97 GB root filesystem with 84 GB available. The audit explicitly says that this restricted shell is not the standalone VM baseline. Its failed DNS/GitHub resolution and missing tools likewise must not be generalized to the VM. Phase 2A later reports Python 3.14.4 and a project virtual environment. The standalone VM's Docker installation is recorded separately in Phase 1.

**Constraints documented:** limited resources for a future combined scanner/Kubernetes workload; network or DNS restrictions in the audit context; missing Python packaging tools in the initial restricted shell; approval and compatibility decisions around the academic scope and planned toolchain. No unsupported VM network or capacity assumptions are made here.

## 4. Completed implementation history

### Phase 1 — Infrastructure and containerization

Docker Engine **29.9.3**, Docker Compose plugin **5.7.0**, and Buildx **0.38.1** were installed from Docker's official Ubuntu APT repository and verified on the standalone VM. The Docker service was active and the `hello-world` smoke test succeeded.

An isolated Nginx Compose check used Nginx 1.31.8. The container became healthy, `http://127.0.0.1:8080/` returned HTTP 200 and the default welcome page, and `docker compose down --remove-orphans` removed the test container and network. The project-scoped Compose listing was empty afterward. This was infrastructure validation only; it did not test DocVault, PostgreSQL, or application health endpoints. The exact raw command/output for several validation steps was not supplied in the phase report.

### Phase 2 — Backend and database foundation

**Development environment (2A).** Python 3.14.4 and an isolated `.venv` were used; project packages were installed in that environment rather than the externally managed system Python. FastAPI, Uvicorn, Pydantic, SQLAlchemy, psycopg, Alembic, pytest, Ruff, and mypy were among the verified imports/tools.

**PostgreSQL (2B).** The Compose deployment uses the official `postgres:17-bookworm` image and a persistent named volume. The database is on an internal bridge network and PostgreSQL does not publish a host port. The `docvault_app` role is limited to normal application DML; `docvault_migrator` owns the `public` schema and is reserved for schema changes. The bootstrap PostgreSQL account is not used by the application. Manual VM checks reported a healthy container, database readiness, successful authentication by the application and migration accounts, role attribute inspection, and persistence of the roles after a container restart. Backup and restore were not verified.

**FastAPI (2C).** The backend uses FastAPI, SQLAlchemy 2.x, psycopg, and environment-backed settings. A cached SQLAlchemy engine uses `pool_pre_ping`; request-scoped sessions are closed after use. `GET /health` is process liveness and does not require the database. `GET /ready` executes `SELECT 1` and returns a generic 503 on database failure. Alembic was established later with the identity schema in Phase 3.

Compose separates `docvault_database` (internal, with PostgreSQL only) from `docvault_api_access` (ordinary bridge for the API host binding). The API joins both; PostgreSQL stays only on the database network. The API binds to loopback on port 8000, runs as UID/GID 10001, has a read-only root filesystem, drops Linux capabilities, enables `no-new-privileges`, and uses a temporary `/tmp` filesystem and resource limits. The ordinary API network permits outbound traffic subject to host routing/firewall; it is not an egress-isolation control. The API image is based on `python:3.14-slim` and excludes `.env` from its build context.

Phase 2C reports manual host HTTP 200 responses for `/health` and `/ready`, and confirms the two-network attachment. The Phase 3 report separately states that the Phase 3 image build, migration execution, and live startup have not been runtime-verified; Phase 2 runtime results must not be read as validation of Phase 3 authentication deployment.

### Phase 3 — Identity, authentication, and access control

Alembic revision `0001_identity_sessions` creates:

| Entity | Recorded design |
|---|---|
| `roles` | Unique role name; database check permits `user` and `administrator`; migration seeds both idempotently. |
| `users` | UUID key, canonical lowercase unique username, Argon2id password hash, active state, role reference, timestamps, and normalization check. |
| `auth_sessions` | SHA-256 digest of opaque session identifier as key, CSRF digest, user reference, creation/expiry/activity timestamps, and revocation timestamp. |

The one-shot Compose `migrate` service uses `docvault_migrator` to run `alembic upgrade head` before API startup. The API receives only the `docvault_app` credentials. Initial administrator creation is an interactive `python -m app.cli bootstrap-admin` operation; it prompts for the password, creates no default credentials, checks for an existing administrator, and uses a transaction-scoped PostgreSQL advisory lock.

Passwords use `argon2-cffi` Argon2id defaults (time cost 3, 65,536 KiB memory, parallelism 4, 32-byte hash, 16-byte salt). Authentication uses PostgreSQL-backed server-side sessions with 256-bit opaque values. Raw session IDs are cookie-only; session and CSRF token digests are stored. Cookies are HttpOnly, SameSite=Lax, path-scoped, and have a configurable Secure flag. Authenticated state-changing requests require the synchronizer token in `X-CSRF-Token`.

The documented identity controls include normalized username handling, generic authentication failures and a dummy password-hash verification for unknown users, account active-state enforcement, and process-local login throttling. Throttling allows five failures per normalized username/source-IP pair and thirty per source IP in a 15-minute window, subject to the documented process-local and proxy-address limitations.

Role-based access control recognizes `user` and `administrator`. Administrative list/create/status/role endpoints resolve the role from the database session; write operations require CSRF validation. Users cannot self-register or set their own role through authentication/profile endpoints. A transaction-scoped PostgreSQL advisory lock protects active-administrator roster changes, and the final active administrator cannot be deactivated or demoted. Deactivation revokes active sessions. The PostgreSQL concurrency harness exists but has not been run; concurrency behavior is not runtime-verified.

## 5. Architecture and security decisions

This section records documented design choices. Reasons phrased as rationale are design interpretation, not claimed historical decision records.

| Decision | Implemented approach | Rationale and evidence boundary |
|---|---|---|
| Application vs migration database access | Separate `docvault_app` and `docvault_migrator` accounts; API and migration service receive their respective credentials. | The phase documentation specifies least privilege: routine API queries do not need schema ownership/DDL access, while migrations do. This reduces privileges available to the long-running application. |
| Authentication state | PostgreSQL-backed server sessions with opaque, hashed identifiers; no browser localStorage JWT. | The documented architecture excludes localStorage authentication tokens and stores only token digests server-side. This supports revocation and server-side expiry/activity checks. The latter is design rationale. |
| Password storage | Argon2id password hashes. | Passwords are not stored as plaintext; Argon2id is the implemented password-hashing algorithm. Exact parameters are recorded above. |
| CSRF | Synchronizer token, digest stored with session, header required for authenticated state changes. | Cookie-based authentication is automatically attached by the browser; token validation is the documented control for cross-site state-changing requests. |
| Container privilege | API runs non-root with read-only root filesystem, all capabilities dropped, and `no-new-privileges`. | These are documented hardening controls that reduce container process privilege and writable surface. |
| Network separation | Internal DB network plus separate API access bridge; PostgreSQL has no host port. | The database remains isolated from direct host-published access while the API can be published on loopback. The second bridge was introduced after the reported host-port publishing issue on an internal-only network. |
| Administrator operations | Restricted administrative endpoints, server-resolved role checks, CSRF for writes, fixed role set, and final-active-administrator safeguard. | These controls constrain account/privilege changes and preserve an active administrator. The source documents the behavior; no additional historical motivation is asserted. |

## 6. Validation record

The categories below are separate. Results are those reported in the repository documentation; this log does not represent a new execution of those checks.

### Automated tests

| Check | Result | Scope/limitation |
|---|---|---|
| `PYTHONPATH=backend .venv/bin/pytest -q --ignore=backend/tests/test_admin_roster_postgres_concurrency.py` | **39 passed** | The PostgreSQL concurrency test was explicitly excluded. Tests primarily use isolated SQLite/direct route or dependency calls; this is not full HTTP transport coverage. |

### Manually executed HTTP runtime checks

| Check group | Result |
|---|---:|
| Authentication/session | **10/10 passed** |
| User management/RBAC | **14/14 passed** |
| Final active-administrator protection | **11/11 passed** |
| **Total** | **35/35 passed** |

These checks were manually executed against the isolated running DocVault application instance and are distinct from pytest. They do not verify PostgreSQL advisory-lock concurrency.

### Static and configuration validation

| Check | Result |
|---|---|
| Ruff: `.venv/bin/ruff check backend scripts` | Passed; all checks passed. |
| Mypy: `MYPYPATH=backend .venv/bin/mypy backend/app backend/migrations` | Passed; no issues in 32 source files. |
| Shell syntax: `bash -n scripts/run_phase3_pg_concurrency_test.sh` | Passed. |
| Python AST parsing | Passed for the reviewed Python files, as reported in Phase 3. |
| `git diff --check` | Reported passed in the Phase 3 final review; this execution log also receives a fresh check below. |

Compose configuration parsing was previously reported successful (`docker compose config -q`). It is not a substitute for building or running the Phase 3 image and migration service.

### Deferred validation and known limitations

- The isolated PostgreSQL advisory-lock concurrency test harness (`backend/tests/test_admin_roster_postgres_concurrency.py` and `scripts/run_phase3_pg_concurrency_test.sh`) is implemented and has not been executed. Concurrent active-administrator behavior is therefore **not runtime-verified**.
- Phase 3 Docker image build, live migration execution, and live authenticated runtime startup remain unverified in the Phase 3 report.
- Automated tests do not provide end-to-end HTTP transport coverage; the documented TestClient hangs in the execution environment.
- The in-process login limiter does not coordinate across API replicas and resets at process restart.
- Security-event output is structured stdout, without tamper-proof storage or an external retention/shipping system in this phase.
- Session cleanup scheduling, HTTPS deployment settings, backup/restore, frontend integration, MFA, password reset, email verification, document workflows, CI/CD, security scans, and Kubernetes validation remain future or unverified work as described by the phase reports and README.

## 7. Git milestones

The current repository history records these milestones (short hashes shown; use Git history for full hashes):

| Commit | Date | Milestone |
|---|---|---|
| `12d018f` | 2026-11-04 | Initial DocVault DevSecOps baseline, project architecture/specification, Phase 0 audit, and Phase 1 reports. |
| `dab5ef4` | 2026-11-04 | GitHub repository setup documentation. |
| `0cd531e` | 2026-11-04 | FastAPI backend and PostgreSQL integration, including Phase 2A/2B/2C reports. |
| `385d32d` | 2026-11-04 | Authentication and access control implementation, Phase 3 evidence, tests, and isolated concurrency harness. |
| `a981138` | 2026-11-04 | README project overview and status. |

This execution log is being added after those milestones. Its publication commit hash should be entered in the next update after the document is committed; no commit is made as part of this task.

## 8. Evidence index

| Phase / evidence area | Detailed record |
|---|---|
| Phase 0 — Environment audit and project constraints | [PHASE_0_ENVIRONMENT_AUDIT.md](PHASE_0_ENVIRONMENT_AUDIT.md) |
| Phase 1B — Docker installation | [PHASE_1_DOCKER_INSTALLATION.md](PHASE_1_DOCKER_INSTALLATION.md) |
| Phase 1C — Nginx Compose validation and cleanup | [PHASE_1_COMPOSE_VALIDATION.md](PHASE_1_COMPOSE_VALIDATION.md) |
| Phase 2A — Development environment | [PHASE_2A_DEVELOPMENT_ENVIRONMENT.md](PHASE_2A_DEVELOPMENT_ENVIRONMENT.md) |
| Phase 2B — PostgreSQL deployment | [PHASE_2B_POSTGRESQL_DEPLOYMENT.md](PHASE_2B_POSTGRESQL_DEPLOYMENT.md) |
| Phase 2C — FastAPI backend foundation | [PHASE_2C_FASTAPI_BACKEND.md](PHASE_2C_FASTAPI_BACKEND.md) |
| Phase 3 — Identity, authentication, and user management | [PHASE_3_AUTHENTICATION_AND_USER_MANAGEMENT.md](PHASE_3_AUTHENTICATION_AND_USER_MANAGEMENT.md) |
| Current project scope and test summary | [README.md](../README.md) |

### Reserved evidence register for future phases

Add references only when evidence is actually captured and retained. No filenames or evidence artifacts are asserted here.

| Evidence type | Reference / status |
|---|---|
| Screenshots | Reserved — add captured paths and context. |
| Command outputs / runtime transcripts | Reserved — add redacted, retained evidence references. |
| Test reports | Reserved — link the actual report and command/run context. |
| CI/CD execution results | Reserved — pipeline is not yet implemented. |
| Security scan reports | Reserved — scanners are planned/pending. |
| Deployment verification | Reserved — record target, version, commands, and observed outcome. |
| Kubernetes validation | Reserved — Kubernetes deployment and policy validation are not yet recorded. |

## 9. Future maintenance policy

After every future project phase, update this log to:

1. Record implementation details and the phase scope.
2. Record changed architecture and configuration, including relevant security decisions.
3. Record actual test commands and results, clearly separating automated tests, manual verification, static checks, and deferred validation.
4. Record manual verification and links to retained evidence.
5. Record unresolved issues, limitations, and deferred validation.
6. Record the relevant full Git commit hash after the work is published.

Preserve prior milestones and evidence status when updating the log. Do not convert plans, inferred rationale, or unexecuted test harnesses into completed results.

## 10. Source documents inspected

The project records consulted for this log were [README.md](../README.md), [Phase 0](PHASE_0_ENVIRONMENT_AUDIT.md), [Phase 1B](PHASE_1_DOCKER_INSTALLATION.md), [Phase 1C](PHASE_1_COMPOSE_VALIDATION.md), [Phase 2A](PHASE_2A_DEVELOPMENT_ENVIRONMENT.md), [Phase 2B](PHASE_2B_POSTGRESQL_DEPLOYMENT.md), [Phase 2C](PHASE_2C_FASTAPI_BACKEND.md), and [Phase 3](PHASE_3_AUTHENTICATION_AND_USER_MANAGEMENT.md). Relevant Git history was inspected from the initial baseline through the README milestone listed above.
