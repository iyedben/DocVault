# DocVault — Phase 3 Identity, Authentication and Access Control

**Date:** 4 November 2026

**Scope:** Identity schema, password authentication, server-side sessions, CSRF defenses, login throttling, administrator bootstrap, and administrator-only user management. Document workflows, frontend, Kubernetes, Jenkins, and CI/CD are outside this phase.

The v2.0 architecture roadmap uses “Phase 3” for Jenkins and security tooling. This implementation milestone follows the Phase 3 identity scope requested for the current work; it implements authentication and access-control requirements from the architecture's core-application phase and does not advance Jenkins work.

## Database schema and migration

Alembic revision `0001_identity_sessions` creates three tables:

| Table | Fields and safeguards |
|---|---|
| `roles` | Integer primary key; unique role name; database check permits only `user` and `administrator`. The migration seeds both rows with `ON CONFLICT DO NOTHING`. |
| `users` | UUID primary key; normalized lowercase unique username; Argon2id hash; active flag; role foreign key; creation and update timestamps. A check constraint prevents non-lowercase identities from bypassing application normalization. |
| `auth_sessions` | SHA-256 digest of the opaque cookie token as primary key; SHA-256 digest of the CSRF token; user foreign key; creation, expiry, last activity, and revocation timestamps. |

The application uses `docvault_app` for normal queries. The one-shot `migrate` Compose service uses `docvault_migrator` to run `alembic upgrade head` before the API starts. It shares the backend image, joins only `docvault_database`, and has its own environment containing only migration connection credentials. The API receives only the application credentials. The PostgreSQL service, role privileges, initialization script, and persistent named volume are unchanged.

The initial administrator is not seeded by the migration. After the migration completes, run the interactive bootstrap inside the API container:

```bash
docker compose exec -it api python -m app.cli bootstrap-admin
```

The command prompts for a username and prompts twice for the password using `getpass`; it accepts no password command-line argument. It uses the API database settings and therefore the application account. A PostgreSQL transaction-scoped advisory lock and an existing-administrator check prevent duplicate bootstrap attempts. No default credentials are created.

## User identity, roles and passwords

Usernames are normalized with Unicode NFKC and case-folding, then constrained to 3–32 lowercase ASCII letters, digits, dots, underscores, or hyphens. Only the canonical value is stored and it has a unique database constraint. Roles are fixed to `user` and `administrator`; no request can change the current user's role through login or `/me`.

Passwords are hashed with pinned `argon2-cffi==25.1.0` using its `PasswordHasher` Argon2id defaults (time cost 3, 65,536 KiB memory, parallelism 4, 32-byte hash, and 16-byte random salt). The [Argon2-cffi API documentation](https://argon2-cffi.readthedocs.io/en/stable/api.html) documents these defaults and its verification behavior. New passwords must be 12–128 printable characters and use at least three of lowercase, uppercase, digits, and non-alphanumeric characters. Password inputs use Pydantic `SecretStr`; the API also strips submitted values from 422 validation responses. Password hashes and plaintext passwords are never included in profile responses or security events.

Hashing and verification are limited to two concurrent Argon2 operations per process to keep the configured API memory limit from being consumed by a burst of hash requests. A dummy Argon2id hash is verified for unknown usernames so missing accounts and wrong passwords share the same generic 401 message.

## Authentication endpoints

| Endpoint | Behavior |
|---|---|
| `POST /api/v1/auth/login` | Verifies username/password, rejects inactive accounts, applies throttling, revokes a presented prior session, creates a fresh session, sets the cookie, and returns a safe user profile plus a CSRF token. |
| `POST /api/v1/auth/logout` | Requires a valid session and CSRF header, revokes the server-side session, and clears the cookie. |
| `GET /api/v1/auth/me` | Resolves the account and role from a valid server-side session and returns only safe profile fields. |

There is no public self-registration. Administrators create accounts through the protected management endpoint.

## Session lifecycle, cookie and CSRF

The API creates 256-bit opaque URL-safe session and CSRF values. It stores only SHA-256 digests of both values; the raw session identifier is sent only in the cookie and never returned in JSON. The raw CSRF token is returned once in the successful login JSON response for use in the `X-CSRF-Token` header on authenticated state-changing requests.

Sessions have an eight-hour absolute lifetime and a 30-minute idle timeout. Authenticated requests update `last_activity_at`. Expired, idle, revoked, or inactive-account sessions are rejected; logout and account deactivation revoke stored sessions. A fresh random identifier is issued after every successful login, preventing reuse of a pre-authentication cookie value.

The `docvault_session` cookie uses `HttpOnly`, `SameSite=Lax`, `Path=/api/v1`, and a configurable `Secure` flag. `AUTH_COOKIE_SECURE=false` supports the current local HTTP setup; set it to `true` when serving through HTTPS. The synchronizer token is hashed in the session row and compared with `hmac.compare_digest`. Missing or invalid CSRF headers are rejected with HTTP 403. No JWT or browser `localStorage` authentication is used.

## Login throttling

The process-local limiter allows five failed attempts per normalized username/source-IP pair and thirty failed attempts per source IP in a 15-minute window. Bucket keys are HMACed with a per-process random key, stored in a bounded 10,000-entry map, and cleared after the relevant window or successful authentication (identity bucket only). Throttled requests receive HTTP 429. No username or password is written to the event log.

This limiter is intentionally local to one API process. It resets on restart and does not coordinate across multiple API replicas; a future multi-instance deployment needs a shared rate-limit store. The current API uses the direct client address; deployments behind a proxy must configure trusted proxy handling before using forwarded client addresses.

## Authorization and administrator user management

All administrative routes resolve the administrator role from the database session; client-supplied roles are not trusted:

- `GET /api/v1/admin/users` lists safe profile fields.
- `POST /api/v1/admin/users` creates an account and may assign either allowed role.
- `PATCH /api/v1/admin/users/{user_id}/status` deactivates or reactivates an account.
- `PATCH /api/v1/admin/users/{user_id}/role` assigns one of the two allowed roles.

Writes require both administrator authorization and CSRF validation. Responses never include password hashes or session rows. Duplicate usernames return 409; missing users return 404; invalid payloads return 422; ordinary users receive 403. The PostgreSQL service methods acquire a transaction-scoped advisory lock before counting or changing active administrators. The final active administrator cannot be deactivated or demoted. Deactivation also revokes that user's active sessions. The current automated guard tests use SQLite and do not exercise PostgreSQL advisory-lock behavior; PostgreSQL concurrency safety has not been runtime-verified.

## Security event logging

Security events are emitted as structured JSON records to standard output. Events cover authentication success/failure/throttling, logout, account creation/deactivation/reactivation, role changes, CSRF failures, and authorization denials. The logger accepts only an allow-list of event, result, actor/target IDs, source IP, and fixed reason fields; it does not log request bodies, usernames, passwords, cookies, session tokens, or CSRF tokens.

Standard-output logs are not tamper-proof and their retention depends on the container/runtime logging configuration. This phase does not add a database audit table or external log shipping.

## Tests and checks

| Check | Result |
|---|---|
| `PYTHONPATH=backend .venv/bin/pytest -q --ignore=backend/tests/test_admin_roster_postgres_concurrency.py` | **Passed during final review:** 39 tests. The PostgreSQL concurrency test was excluded and was not executed. |
| `.venv/bin/ruff check backend scripts` | **Passed during final review:** all checks passed. |
| `MYPYPATH=backend .venv/bin/mypy backend/app backend/migrations` | **Passed during final review:** no issues in 32 source files. |
| `bash -n scripts/run_phase3_pg_concurrency_test.sh` and Python AST parsing | **Passed during final review.** |
| `docker compose config -q` | **Previously passed:** configuration parsed without printing interpolated credentials. It was not rerun during the final review. |
| `git diff --check` | **Passed during final review** after the documentation update. |

Tests use isolated in-memory SQLite databases or direct route/dependency calls. The migration test applies the Alembic revision to SQLite and calls the role seed repeatedly to verify idempotence. The installed Starlette/httpx `TestClient` hangs in this execution environment, so these tests do not claim end-to-end HTTP transport coverage. No production database was used. The test suite was run with the PostgreSQL concurrency integration test explicitly ignored; the count above does not include that test.

### Manually executed Phase 3 HTTP runtime checks

The following results were supplied for checks manually executed against the running isolated DocVault application instance. They are separate from the automated pytest results above:

| Runtime check group | Result |
|---|---|
| Authentication and session checks | **Passed:** 10/10. |
| User management and RBAC checks | **Passed:** 14/14. |
| Final active-administrator protection checks | **Passed:** 11/11. |
| **Total manually executed HTTP runtime checks** | **Passed:** 35/35. |

These results record the supplied HTTP checks only. They do not include or validate PostgreSQL advisory-lock concurrency.

### Deferred PostgreSQL concurrency validation

The transaction-scoped advisory-lock implementation remains in `backend/app/services/users.py`. PostgreSQL concurrency validation is explicitly deferred: `backend/tests/test_admin_roster_postgres_concurrency.py` and its isolated test runner have not been executed, and concurrency safety has not been runtime-verified. The test harness was statically reviewed and corrected, but still requires a later isolated PostgreSQL runtime validation. The SQLite unit and endpoint tests verify the final-administrator guard behavior sequentially; they cannot establish that simultaneous PostgreSQL operations serialize correctly. Do not interpret the presence of the test or the advisory lock as evidence of completed concurrency validation.

## Runtime status and remaining limitations

Compose configuration was previously validated, but Docker image build, migration service execution, live PostgreSQL migration, API startup, and live cookie/session tests were not run by Codex. The manually executed Phase 3 HTTP results above were supplied separately and are not Codex test results. Earlier manual Phase 2B/2C runtime checks remain documented in their phase reports; they do not verify this Phase 3 schema or authentication runtime. PostgreSQL concurrency validation is deferred as described above.

The API's one-shot migration service must complete before it starts. The application uses the existing least-privilege database roles and does not change PostgreSQL privileges or the persistent volume. Session cleanup for expired rows is not scheduled, the login limiter is process-local, log retention is external, and production HTTPS must set `AUTH_COOKIE_SECURE=true`. Frontend integration, password reset, MFA, account email verification, document workflows, and broader deployment work remain out of scope.
