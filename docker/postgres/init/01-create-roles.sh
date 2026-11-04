#!/usr/bin/env bash
set -Eeuo pipefail

# Runs only when the official image initializes an empty data directory.
# psql reads custom credentials directly from its environment with \getenv;
# they are not placed in psql command-line arguments or echoed by this script.
if [[ "$POSTGRES_APP_USER" == "$POSTGRES_MIGRATION_USER" ]]; then
  printf '%s\n' 'Application and migration roles must be distinct' >&2
  exit 1
fi

psql \
  --no-psqlrc \
  --quiet \
  --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_user POSTGRES_APP_USER
\getenv app_password POSTGRES_APP_PASSWORD
\getenv migration_user POSTGRES_MIGRATION_USER
\getenv migration_password POSTGRES_MIGRATION_PASSWORD
\getenv database_name POSTGRES_DB

SET log_statement = 'none';
SET log_min_error_statement = 'panic';

SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
  :'app_user', :'app_password'
) \gexec
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
  :'migration_user', :'migration_password'
) \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database_name', :'app_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database_name', :'migration_user') \gexec
SELECT format('ALTER SCHEMA public OWNER TO %I', :'migration_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app_user') \gexec
SELECT format(
  'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I',
  :'app_user'
) \gexec
SELECT format(
  'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I',
  :'app_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
  :'migration_user', :'app_user'
) \gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I',
  :'migration_user', :'app_user'
) \gexec
SQL
