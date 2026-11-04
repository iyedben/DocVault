# DocVault — Phase 2B PostgreSQL Deployment

**Prepared:** 4 November 2026
**Scope:** PostgreSQL deployment and runtime validation on the standalone Ubuntu VM, including container health, database readiness, account authentication, and role privilege inspection.

## Image and version choice

The Compose service uses the official `postgres:17-bookworm` image. PostgreSQL 17 is the selected major release, keeping the deployment on a supported major line while allowing upstream security and bug-fix updates within that major. Before a production deployment, pin and review an image digest; updating to another PostgreSQL major must be planned as a database upgrade. The container was deployed and reached `healthy` status during the manual SSH validation recorded below.

The Compose service initializes the fixed `docvault` database. The official image's bootstrap `postgres` account is a superuser used only for initialization and administrative access. The application connects as `docvault_app`, a separate login role with no superuser, database-creation, role-creation, or schema-creation privilege. It receives only schema usage and DML on tables/sequences. Alembic or other schema changes must use the separate `docvault_migrator` login. The migration role owns the `public` schema; default privileges give the application DML on objects it creates. Do not use either bootstrap or migration credentials in normal application runtime.

The initialization script runs only when PostgreSQL initializes an empty data directory. Changing `.env` credentials later does not rotate passwords already stored in the database and does not rerun initialization. Rotate database role passwords explicitly and update the protected environment file as one coordinated operation.

### Initialization script security review

`docker/postgres/init/01-create-roles.sh` reads `POSTGRES_APP_USER`, `POSTGRES_APP_PASSWORD`, `POSTGRES_MIGRATION_USER`, and `POSTGRES_MIGRATION_PASSWORD` with psql `\getenv`. Passwords are not supplied as psql command-line arguments or echoed by the script. The psql session disables statement logging and suppresses error query text while it handles the password-bearing role statements. The script also uses `--no-psqlrc`, quiet mode, `ON_ERROR_STOP`, and Bash strict error handling so local psql configuration cannot enable query echoing and SQL failures stop initialization.


The script rejects identical application and migration role names. Both roles are created with explicit `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, and `NOBYPASSRLS` attributes. The migration role owns `public`, which permits it to create and manage migration objects there without database-wide create or role-management privileges. The application role receives database `CONNECT`, schema `USAGE`, table `SELECT`/`INSERT`/`UPDATE`/`DELETE`, and sequence `USAGE`/`SELECT`; it receives no schema `CREATE` privilege. Default privileges scoped to objects created by the migration role grant the same table DML and sequence use to the application role.

SQL names and password literals are produced with PostgreSQL `format()` using `%I` and `%L`. `\getenv` is supported by the psql client distributed with the official PostgreSQL 17 image. Runtime inspection confirmed that both application and migration accounts authenticate to `docvault`; both were reported with all six false Boolean role attributes in the inspection query. The supplied evidence names five attributes (`rolsuper`, `rolcreatedb`, `rolcreaterole`, `rolreplication`, `rolbypassrls`) but does not identify the sixth, so this document does not infer its name. Runtime evidence does not independently validate every grant or the script's logging behavior. Host administrators with Docker access can inspect container environment variables; protect `.env` and Docker access accordingly. External logging systems or separately changed server logging configuration are outside this script's control.

## Storage and network

- `postgres_data` is a persistent named volume (`docvault_postgres_data`) mounted at the PostgreSQL data directory. Removing or recreating the container does not remove this volume. `docker compose down -v` does remove it and permanently deletes the database contents.
- The `database` bridge network (`docvault_database`) is marked internal and has no external route. The service publishes no host port. The future application service should join this network; do not add a public database port mapping.
- Compose applies a 768 MiB memory limit, one CPU limit and a 128-process limit. These values are starting constraints and should be adjusted based on observed VM capacity and database workload.
- The service uses `restart: unless-stopped`.

## Credential handling

`.env.example` contains placeholders only. Copy it to `.env`, replace every secret with a distinct, randomly generated value, and set mode `0600`. The existing `.gitignore` excludes `.env` and allows `.env.example`. Never put actual passwords in Compose, documentation, shell history, Git, or image layers. The bootstrap password must be retained only for controlled administration; the application receives only its application role credential. Treat access to `.env` and Docker inspection access as sensitive because Compose environment variables are available to host administrators.

## Health check

Compose runs `pg_isready -U postgres -d docvault` every 10 seconds, with a 5-second timeout, five retries and a 20-second start period. This checks server readiness; it does not validate application credentials, grants, schema migrations, or application-to-database connectivity.

## Credential preparation (deployment record)

The following instructions describe the credential preparation procedure used for deployment. Docker and PostgreSQL checks were performed manually in the normal Ubuntu VM SSH terminal.

From the repository root, create a private environment file and edit it locally in that SSH session:

```bash
cd /home/docvault/DocVault
cp .env.example .env
chmod 600 .env
openssl rand -base64 36
```

Generate a distinct value for each of the three password fields, then enter them in `.env` with a terminal editor such as `nano .env`. Keep the values out of command arguments and shell history. Do not run `cat .env` or share its contents.

## Deployment and runtime validation

The PostgreSQL service was started from the normal Ubuntu SSH terminal using the `postgres:17-bookworm` image. The following checks were performed there:

```bash
cd /home/docvault/DocVault
docker compose pull postgres
docker compose up -d postgres
docker compose ps
docker compose exec -T postgres pg_isready -U postgres -d docvault
docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q postgres)"
```

Observed results:

- The PostgreSQL container started successfully and reported health status `healthy`.
- `pg_isready -U postgres -d docvault` returned `/var/run/postgresql:5432 - accepting connections`.
- `docvault_app` and `docvault_migrator` each authenticated successfully to `docvault`.
- Role inspection confirmed `postgres` has administrative privileges. `docvault_app` and `docvault_migrator` have no elevated role attributes; the six Boolean attributes in the inspection output were false for each. The evidence provided explicitly names five (`rolsuper`, `rolcreatedb`, `rolcreaterole`, `rolreplication`, `rolbypassrls`); the sixth is not named here because its name was not included in the supplied output.
- A manual PostgreSQL container restart completed successfully. The container returned to `healthy`, readiness succeeded, and inspection confirmed all three roles (`postgres`, `docvault_app`, and `docvault_migrator`) remained present after restart.

These checks establish container health, server readiness, successful authentication for the listed accounts, and role persistence across the tested restart. `pg_isready` alone does not validate grants, schema migrations, or application-to-database connectivity. If initialization fails in a future deployment, inspect `docker compose logs --tail=100 postgres` in the SSH terminal; redact sensitive output before sharing it.

To verify the container has no published host port and the volume/network are attached, run in the SSH terminal:

```bash
docker inspect --format 'ports={{json .NetworkSettings.Ports}} mounts={{json .Mounts}} networks={{json .NetworkSettings.Networks}}' "$(docker compose ps -q postgres)"
```

The `ports` mapping should show no host binding. Avoid `docker compose config` in shared terminals because rendered configuration includes interpolated credentials.

## Persistence and backups

The named volume preserves database files across container replacement, but it is not a backup. Take regular PostgreSQL logical backups and store them outside the VM or on separately protected storage. For example, from the authorized SSH terminal, this streams a logical dump to the current host directory; choose a protected backup path and encrypt/transfer it according to the project’s data-handling policy:

```bash
umask 077
docker compose exec -T postgres pg_dump -U postgres -d docvault --format=custom > docvault-$(date +%F).dump
```

Test restoration into a separate database or disposable environment before relying on backups. Include backup retention, encryption, access control, and recovery testing in the operational plan. Never remove the named volume as part of routine container cleanup.

## Preparation validation and status

The Compose file, example environment, initialization script, and this document were reviewed in conjunction with the PostgreSQL deployment. The repository’s existing `.gitignore` excludes `.env` and explicitly permits `.env.example`, so it was not changed. Runtime evidence above confirms container startup and health, database readiness, both named account logins, role attribute inspection, and role persistence after a successful container restart. Backup creation/restoration and application connectivity have not been established by the evidence recorded here. The initialization script's shell syntax was validated after the password-handling correction.
