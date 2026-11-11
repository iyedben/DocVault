#!/usr/bin/env bash

# Run Playwright browser end-to-end tests against a dedicated, isolated
# Docker Compose stack with tmpfs PostgreSQL and tmpfs document storage.
set -euo pipefail

if ! command -v timeout >/dev/null 2>&1; then
  printf '%s\n' "The timeout utility is required for bounded startup and cleanup." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/compose.e2e.yaml"
e2e_port="${E2E_PORT:-8001}"
project_name="docvault-e2e-$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
private_dir="$(mktemp -d "${TMPDIR:-/tmp}/docvault-e2e.XXXXXXXX")"
chmod 700 "$private_dir"
env_file="$private_dir/test.env"
umask 077

# Generate disposable credentials for isolated test database and initial test admin
postgres_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
app_user="dv_app_$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
app_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
migration_user="dv_mig_$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
migration_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
admin_username="e2e_admin_$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
admin_password="Admin$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')!Aa1"

cat >"$env_file" <<EOF
E2E_PORT=${e2e_port}
E2E_POSTGRES_PASSWORD=${postgres_password}
E2E_APP_USER=${app_user}
E2E_APP_PASSWORD=${app_password}
E2E_MIGRATION_USER=${migration_user}
E2E_MIGRATION_PASSWORD=${migration_password}
EOF

# Ensure Playwright finds extracted shared libraries and font configurations if present
playwright_libs="$HOME/.local/lib/playwright-libs/usr/lib/x86_64-linux-gnu"
if [[ -d "$playwright_libs" ]]; then
  export LD_LIBRARY_PATH="${playwright_libs}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

fontconfig_dir="$HOME/.local/etc/fonts"
if [[ -d "$fontconfig_dir" ]]; then
  export FONTCONFIG_PATH="$fontconfig_dir"
  export FONTCONFIG_FILE="$fontconfig_dir/fonts.conf"
fi


cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  printf '\nCleaning up isolated E2E containers and temporary resources...\n'
  timeout 30s docker compose \
    --project-directory "$repo_root" \
    --project-name "$project_name" \
    --env-file "$env_file" \
    --file "$compose_file" \
    down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
  rm -rf -- "$private_dir"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Starting isolated DocVault E2E environment on 127.0.0.1:%s...\n' "$e2e_port"

timeout 120s docker compose \
  --project-directory "$repo_root" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  up --detach --wait --wait-timeout 90 e2e-api >/dev/null

printf 'Isolated DocVault API is ready. Bootstrapping test administrator...\n'

timeout 20s docker compose \
  --project-directory "$repo_root" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  exec -T e2e-api python -c "
from app.db.session import get_session_factory
from app.services.users import bootstrap_first_admin
db = get_session_factory()()
try:
    bootstrap_first_admin(db, '${admin_username}', '${admin_password}')
finally:
    db.close()
" < /dev/null

printf 'Administrator bootstrapped: %s\n' "$admin_username"

export DOCVAULT_BASE_URL="http://127.0.0.1:${e2e_port}"
export DOCVAULT_ADMIN_USER="$admin_username"
export DOCVAULT_ADMIN_PASSWORD="$admin_password"
export DOCVAULT_E2E_ENABLE=1
export PYTHONPATH="$repo_root/backend${PYTHONPATH:+:$PYTHONPATH}"

pytest_cmd="${PYTEST_BIN:-}"
if [[ -z "$pytest_cmd" ]]; then
  if [[ -x "$repo_root/.venv/bin/pytest" ]]; then
    pytest_cmd="$repo_root/.venv/bin/pytest"
  else
    pytest_cmd="pytest"
  fi
fi

cd "$repo_root"
printf 'Executing Playwright E2E test suite...\n'
if [ "$#" -gt 0 ]; then
  "$pytest_cmd" -v "$@"
else
  "$pytest_cmd" -v backend/tests/e2e
fi
