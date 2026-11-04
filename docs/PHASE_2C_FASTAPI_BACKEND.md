# DocVault — Phase 2C FastAPI Backend Foundation

**Date:** 4 November 2026
**Scope:** Initial FastAPI process, environment-driven PostgreSQL connectivity, liveness/readiness routes, Compose integration, and automated tests. No application tables or business features are introduced.

## Backend structure

```text
backend/
├── Dockerfile
├── app/
│   ├── main.py
│   ├── core/config.py
│   ├── db/base.py
│   ├── db/session.py
│   └── api/routes/health.py
└── tests/
    ├── test_health.py
    └── test_database.py
```

Package `__init__.py` files mark the application, database, API, routes, and tests as Python packages. `Base` is only a declarative base for later models; this phase creates no tables and does not run migrations.

## Dependencies and configuration

The project already pins FastAPI, Uvicorn, SQLAlchemy 2.x, psycopg, pytest, and HTTPX. The runtime requirement now specifies `psycopg[binary]` so the existing binary driver is installed in the minimal container image; the corresponding `psycopg-binary` version was already present in `requirements-lock.txt`. Runtime dependencies remain pinned by the existing `requirements.txt`; test and lint dependencies remain in `requirements-dev.txt`.

Database settings are read from `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`, and `DATABASE_PASSWORD`. Local defaults provide the Compose hostname, port, database, and least-privilege `docvault_app` account; password defaults to an empty value and should be explicitly set in deployed environments. Compose supplies the password from `POSTGRES_APP_PASSWORD` and does not pass the bootstrap or migration credentials to the API.

## SQLAlchemy connection design

`backend/app/db/session.py` builds a `postgresql+psycopg` SQLAlchemy URL with `URL.create()`, which safely handles punctuation and spaces in passwords. It exposes one cached engine and one cached session factory per process. `get_db` yields a request-scoped ORM session and closes it in a `finally` block. The engine uses `pool_pre_ping` to detect stale pooled connections.

Application queries use the `docvault_app` account only. The `docvault_migrator` account remains reserved for schema changes, and `postgres` is not used by the API. No live connection is made when the application module is imported.

## Health and readiness routes

- `GET /health` returns `{"status":"ok"}` and does not request a database session.
- `GET /ready` executes `SELECT 1` through the request-scoped session and returns `{"status":"ready"}` on success. A SQLAlchemy database failure returns HTTP 503 with a generic `Database unavailable` detail; the response does not include exception text, credentials, or a connection URL.

Compose uses `/ready` for the API health check, so API health requires the database to be reachable.

## Compose and container security

The API joins two networks: the existing internal `docvault_database` network for database access and a new ordinary bridge named `docvault_api_access` for host-facing port publishing. PostgreSQL remains attached exclusively to `docvault_database`, which stays `internal: true`; it is not connected to the new network and port 5432 remains unpublished. The API retains the `127.0.0.1:8000:8000` mapping, starts after PostgreSQL is healthy, runs as UID/GID 10001, uses a read-only root filesystem, drops all Linux capabilities, enables `no-new-privileges`, and has a small `/tmp` tmpfs. Existing resource limits, health check, PostgreSQL configuration, and persistent volume are preserved.

### Docker Engine 29 host-port publishing diagnosis

In the reported deployment, Compose requested the localhost port mapping and the API answered internally, but Docker showed `NetworkSettings.Ports` as `{"8000/tcp":null}`, `docker port` returned no mapping, and host port 8000 had no listener. The API was attached only to the `internal: true` database bridge. This matches the reported Docker Engine 29 behavior where host-port publishing can silently fail for a container attached exclusively to an internal network. The separate ordinary bridge provides the API with a non-internal network attachment while retaining its internal path to PostgreSQL.

The ordinary `docvault_api_access` bridge allows outbound network connectivity from the API container, subject to host routing and firewall configuration. It is not an egress-isolation network, and this Compose topology does not block outbound traffic. PostgreSQL remains isolated on the internal database network.

The API image uses `python:3.14-slim`, installs the pinned direct runtime requirements, copies only the application package, and does not copy `.env`. The root `.dockerignore` excludes environment files, virtual environments, Git metadata, reports, and local test artifacts from the build context. The existing `.gitignore` continues to exclude `.env`.

## Security decisions and limits

- No credentials are embedded in source or Dockerfile instructions. Compose injects only the application username and password required by the API.
- The application role remains separate from the bootstrap and migration roles. PostgreSQL privileges and the initialization script were not changed.
- `/health` is process liveness; `/ready` is database readiness. Neither endpoint reveals internal database errors.
- Authentication, authorization, uploads, document entities, migrations, and business logic are outside this phase.
- The base image tag is not digest-pinned. Runtime dependencies are directly pinned, while transitive packages are not all locked in the runtime image because the existing full lock also includes development tools.

## Automated checks (Codex)

Tests use synthetic sessions and environment-variable overrides, so they do not require PostgreSQL or Docker. Results in the current environment:

| Check | Result |
|---|---|
| `PYTHONPATH=backend .venv/bin/pytest -q` | **Passed:** 5 tests. |
| `.venv/bin/ruff check backend` | **Passed:** all checks passed. |
| `MYPYPATH=backend .venv/bin/mypy backend/app` | **Passed:** no issues in 10 source files. |
| `docker compose config --quiet` | **Passed:** Compose configuration parsed; quiet mode avoided printing interpolated values. |
| `git diff --check` | **Passed:** no whitespace errors. |

The installed Starlette/httpx `TestClient` hangs in this execution environment even with a minimal FastAPI app. The endpoint tests therefore call the route functions directly, verify the declared HTTP 200 codes, and verify the generic HTTP 503 exception behavior; they do not claim end-to-end HTTP transport coverage. The test suite did not connect to PostgreSQL. Compose parsing was checked by Codex after the two-network change; Codex did not build or start containers or make host HTTP requests.

## Manually verified runtime results

The following results were manually checked in the normal Ubuntu SSH terminal and supplied for this update; they were not run by Codex:

- The API container was recreated with the corrected two-network Compose configuration.
- The API is attached to both `docvault_database` and `docvault_api_access`. PostgreSQL remains attached only to the internal `docvault_database` network.
- The API host mapping is configured/intended as `127.0.0.1:8000:8000`. No host port inspection output was supplied for this run, so this document does not claim that a port inspection confirmed the binding.
- A host request to `http://127.0.0.1:8000/health` returned HTTP 200 with `{"status":"ok"}`. A host request to `/ready` returned HTTP 200.
- An earlier request from inside the API container to `/health` returned `{"status":"ok"}`. Internal `/ready` health checks returned HTTP 200.
- PostgreSQL had previously been verified healthy, and both the application and migration accounts had authenticated successfully. The PostgreSQL persistent volume configuration was preserved during the API recreation.

This verifies host HTTP access to the API and successful readiness responses as reported. It does not include a supplied host-port inspection result or claim backup/restore testing. The ordinary `docvault_api_access` bridge allows outbound connectivity subject to host routing and firewall configuration; outbound traffic is not blocked by this Compose topology.

## Remaining limitations and next steps

This foundation does not define application models or Alembic migrations. Runtime results above are manual evidence; the Codex test suite still exercises route handlers directly rather than HTTP transport because the installed TestClient hangs in this environment. Authentication and business features remain future scope.
