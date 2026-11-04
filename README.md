# DocVault — Secure Document Management Platform

DocVault is an academic engineering project exploring secure document management, controlled access, and practical application-security and DevSecOps principles. The current implementation establishes the API, PostgreSQL integration, identity, authentication, and user administration that future document workflows will build on.

## Project status

Development is ongoing. Phase 3 identity, authentication, and access control are implemented. Document upload, storage, retrieval, sharing, and other document workflows are **not implemented**. The planned browser frontend and DevSecOps pipeline are also not implemented yet. This project is not production-ready.

## Architecture

### Implemented

- **API:** FastAPI with SQLAlchemy 2.x database access.
- **Database and migrations:** PostgreSQL with Alembic-managed schema migrations.
- **Containers:** Docker and Docker Compose orchestrate PostgreSQL, a one-shot migration service, and the API.
- **Current API capabilities:** liveness and readiness checks, login/logout/current-user endpoints, and administrator-only user management.

### Planned

- **Frontend:** HTML, CSS, Bootstrap, and JavaScript. No frontend files are present in the repository yet.
- **Document workflows:** upload, storage, retrieval, download, and controlled sharing.

## Security features

The following features are present in the current source and configuration:

- Passwords are hashed with **Argon2id** using `argon2-cffi`.
- Authentication uses PostgreSQL-backed server-side sessions. Opaque session identifiers are sent in an HttpOnly cookie; only their SHA-256 digests are stored.
- Authenticated state-changing requests require a synchronizer CSRF token.
- Role-based access control supports `user` and `administrator` roles.
- Login attempts are throttled in process memory. This limiter does not coordinate between API replicas.
- The final-active-administrator guard uses a PostgreSQL transaction-scoped advisory lock. **Concurrent PostgreSQL behavior has not yet been runtime-validated; see Testing.**
- The API container runs as a non-root user and uses a read-only root filesystem, drops Linux capabilities, enables `no-new-privileges`, and has resource limits.
- PostgreSQL uses separate `docvault_app` and `docvault_migrator` accounts. The API receives application credentials; the migration service receives migration credentials.
- PostgreSQL is not published to a host port. The API is published on loopback (`127.0.0.1:8000`).

## DevSecOps roadmap

These tools and controls are **planned or pending**, not represented as implemented CI/CD or scan results:

- Jenkins CI/CD.
- Semgrep static application security testing (SAST).
- Gitleaks secret scanning.
- Grype vulnerability scanning.
- Syft software bill of materials (SBOM) generation.
- Checkov infrastructure-as-code scanning.
- OWASP ZAP dynamic application security testing (DAST).
- Minikube and Kubernetes deployment.
- Calico NetworkPolicies; policy enforcement must be verified in the target cluster before it is claimed.

## Technology stack

| Area | Technologies | Status |
|---|---|---|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy 2.x, Alembic | Implemented |
| Database | PostgreSQL, psycopg | Implemented |
| Containerization | Docker, Docker Compose | Implemented; Phase 3 image and migration runtime still need validation |
| Application security | Argon2id, server-side sessions, CSRF, RBAC, login throttling | Implemented |
| Planned frontend | HTML, CSS, Bootstrap, JavaScript | Planned |
| Future infrastructure and security tooling | Jenkins, Semgrep, Gitleaks, Grype, Syft, Checkov, OWASP ZAP, Minikube, Kubernetes, Calico | Planned or pending |

## Repository structure

This is a concise view of the current repository, omitting tests and documentation subtrees for brevity.

```text
.
├── README.md
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/       # authentication, user administration, health
│   │   ├── core/             # environment-backed settings
│   │   ├── db/               # SQLAlchemy engine and session dependency
│   │   ├── models/            # users, roles, server-side sessions
│   │   ├── security/          # passwords, tokens, identities, throttling
│   │   ├── services/          # user and administrator safeguards
│   │   ├── cli.py             # interactive administrator bootstrap
│   │   └── main.py
│   ├── migrations/            # Alembic environment and revisions
│   └── tests/
├── docker/
│   └── postgres/init/         # PostgreSQL role initialization
├── docs/                      # phase reports and project setup notes
├── scripts/                   # manual HTTP checks and isolated PG test runner
├── compose.yaml
├── alembic.ini
├── requirements.txt
├── requirements-dev.txt
└── requirements-lock.txt
```

## Getting started

### Prerequisites

- Docker Engine with the Docker Compose plugin and permission to use its daemon.
- Python 3.14 and `curl` for local tests and endpoint checks.
- A terminal editor for configuring the local environment file.

The project environment report records Python 3.14.4, Docker Engine 29.9.3, and Compose 5.7.0 on the documented Ubuntu host. The Phase 3 Docker image build and live migration startup have not been verified, so the first Compose run should be treated as an environment validation step.

### Configure and start

Create `.env` from the placeholder template if it does not already exist, restrict its permissions, and replace every password placeholder with a distinct strong value using a local editor. Do not commit or print `.env`.

```bash
if [ ! -e .env ]; then cp .env.example .env; fi
chmod 600 .env
nano .env
```

For local HTTP development, `AUTH_COOKIE_SECURE=false` is used with the loopback-only API binding. Set it to `true` when serving through HTTPS. Then request the existing services:

```bash
docker compose up -d --build postgres migrate api
docker compose ps
```

Compose waits for PostgreSQL health, runs the migration service, and starts the API after migrations complete successfully. This is the configured startup flow; Phase 3 image building and migration execution have not yet been runtime-verified. Do not remove or recreate the PostgreSQL volume as part of setup.

After the API is available, its interactive bootstrap command creates the initial administrator through the application database account:

```bash
docker compose exec -it api python -m app.cli bootstrap-admin
```

The command prompts for the username and password; the password is not passed as an argument. The initial bootstrap is refused when an administrator already exists.

The current health endpoints are implemented as follows:

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/ready
```

`/health` checks that the API process responds. `/ready` executes a lightweight database query and succeeds only when PostgreSQL is reachable. Both endpoints have been manually checked over HTTP in the reported isolated application runtime.

## Testing

- **Automated:** 39 pytest tests passed in the latest reported run. The PostgreSQL concurrency integration test was explicitly excluded from that run.
- **Manually executed HTTP checks against the running isolated DocVault application instance:**
  - Authentication and session: **10/10 passed**.
  - User management and RBAC: **14/14 passed**.
  - Final active-administrator protection: **11/11 passed**.
  - Total: **35/35 passed**.
- **Deferred:** PostgreSQL advisory-lock concurrency validation has not been executed. The presence of the lock and an isolated test harness does not establish runtime concurrency safety.

The automated suite primarily uses isolated SQLite databases and direct route/dependency calls; it does not substitute for PostgreSQL concurrency testing or full HTTP transport coverage. See [Phase 3 authentication and user management](docs/PHASE_3_AUTHENTICATION_AND_USER_MANAGEMENT.md) for the detailed results and limitations.

## Project documentation

- [Phase 0 — Environment audit](docs/PHASE_0_ENVIRONMENT_AUDIT.md)
- [Phase 1 — Docker installation](docs/PHASE_1_DOCKER_INSTALLATION.md)
- [Phase 1 — Compose validation](docs/PHASE_1_COMPOSE_VALIDATION.md)
- [Phase 2A — Development environment](docs/PHASE_2A_DEVELOPMENT_ENVIRONMENT.md)
- [Phase 2B — PostgreSQL deployment](docs/PHASE_2B_POSTGRESQL_DEPLOYMENT.md)
- [Phase 2C — FastAPI backend](docs/PHASE_2C_FASTAPI_BACKEND.md)
- [Phase 3 — Authentication and user management](docs/PHASE_3_AUTHENTICATION_AND_USER_MANAGEMENT.md)
- [Technical architecture and project baseline](DocVault_Technical_Architecture_and_Project_Baseline-v2.md)
- [Project specifications](DocVault_Project_Specifications.pdf)
- [Changelog and STRIDE threat model](DocVault%20v2.1%20%E2%80%94%20Changelog%20and%20STRIDE%20Threat%20Model.md)

No license file is currently present in the repository.

## Disclaimer

DocVault is an academic and educational project. It is under active development and is **not yet production-ready**. Security controls and runtime results are documented with their validation status; unimplemented roadmap items and deferred PostgreSQL concurrency validation should not be treated as completed capabilities.
