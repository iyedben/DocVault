#!/usr/bin/env bash

# Run document integration tests against a disposable, uniquely named
# PostgreSQL instance with no persistent database or document volume.
set -eu

if ! command -v timeout >/dev/null 2>&1; then
  printf '%s\n' "The timeout utility is required for bounded startup and cleanup." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/compose.phase4-postgres-test.yaml"
project_name="docvault-p4-documents-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
private_dir="$(mktemp -d "${TMPDIR:-/tmp}/docvault-p4-test.XXXXXXXX")"
chmod 700 "$private_dir"
env_file="$private_dir/test.env"
umask 077
test_user="dv4test_$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
test_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(36))')"
printf 'PHASE4_TEST_POSTGRES_USER=%s\nPHASE4_TEST_POSTGRES_PASSWORD=%s\n' \
  "$test_user" "$test_password" >"$env_file"
unset test_password

compose() {
  docker compose \
    --project-directory "$private_dir" \
    --project-name "$project_name" \
    --env-file "$env_file" \
    --file "$compose_file" \
    "$@"
}

cleanup() {
  result=$?
  trap - EXIT INT TERM
  timeout 40s docker compose \
    --project-directory "$private_dir" \
    --project-name "$project_name" \
    --env-file "$env_file" \
    --file "$compose_file" \
    down --timeout 10 >/dev/null 2>&1 || result=1
  rm -f -- "$env_file"
  rmdir -- "$private_dir" || result=1
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

timeout 150s docker compose \
  --project-directory "$private_dir" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  up --detach --wait --wait-timeout 90 phase4-test-postgres >/dev/null
published_address="$(timeout 15s docker compose \
  --project-directory "$private_dir" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  port phase4-test-postgres 5432)"
case "$published_address" in
  127.0.0.1:*)
    test_port="${published_address##*:}"
    ;;
  *)
    printf '%s\n' "The disposable PostgreSQL port was not published on loopback." >&2
    exit 1
    ;;
esac

printf 'PostgreSQL version: '
timeout 15s docker compose \
  --project-directory "$private_dir" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  exec -T phase4-test-postgres \
  psql -U "$test_user" -d postgres -Atc 'SHOW server_version'

export PHASE4_TEST_PG_HOST=127.0.0.1
export PHASE4_TEST_PG_PORT="$test_port"
export PHASE4_TEST_PG_USER="$test_user"
export PHASE4_TEST_PG_PASSWORD="$(sed -n 's/^PHASE4_TEST_POSTGRES_PASSWORD=//p' "$env_file")"
export PYTHONPATH="$repo_root/backend${PYTHONPATH:+:$PYTHONPATH}"
cd "$repo_root"
"$repo_root/.venv/bin/pytest" -v backend/tests/test_document_postgres_integration.py
