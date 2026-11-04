#!/usr/bin/env bash

# Starts only the dedicated disposable PostgreSQL test project, runs the
# opt-in integration test, and removes that uniquely named project afterward.
set -eu

if ! command -v timeout >/dev/null 2>&1; then
  printf '%s\n' "The timeout utility is required for bounded startup and cleanup." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/compose.phase3-concurrency-test.yaml"
project_name="docvault-p3-concurrency-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
private_dir="$(mktemp -d "${TMPDIR:-/tmp}/docvault-p3-test.XXXXXXXX")"
chmod 700 "$private_dir"
env_file="$private_dir/test.env"
umask 077
test_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(36))')"
printf 'PHASE3_TEST_POSTGRES_PASSWORD=%s\n' "$test_password" >"$env_file"
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
  up --detach --wait --wait-timeout 90 phase3-test-postgres >/dev/null
published_address="$(timeout 15s docker compose \
  --project-directory "$private_dir" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  port phase3-test-postgres 5432)"
case "$published_address" in
  127.0.0.1:*)
    test_port="${published_address##*:}"
    ;;
  *)
    printf '%s\n' "The disposable PostgreSQL port was not published on loopback." >&2
    exit 1
    ;;
esac

export PHASE3_TEST_PG_HOST=127.0.0.1
export PHASE3_TEST_PG_PORT="$test_port"
export PHASE3_TEST_PG_USER=phase3_test_admin
export PHASE3_TEST_PG_PASSWORD="$(sed -n 's/^PHASE3_TEST_POSTGRES_PASSWORD=//p' "$env_file")"
export PYTHONPATH="$repo_root/backend${PYTHONPATH:+:$PYTHONPATH}"
cd "$repo_root"
"$repo_root/.venv/bin/pytest" -q backend/tests/test_admin_roster_postgres_concurrency.py
