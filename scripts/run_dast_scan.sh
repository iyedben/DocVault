#!/usr/bin/env bash

# DocVault Dynamic Application Security Testing (DAST) Scan Orchestrator
# Builds the production container image, boots an isolated ephemeral DocVault
# stack on loopback port 8002 using tmpfs storage, executes an OWASP ZAP passive
# baseline scan, validates findings against .github/security/dast-exceptions.json
# using scripts/validate_dast_scan.py, preserves scan reports, and guarantees
# complete cleanup.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Configurable options with secure defaults
dast_port="${DAST_PORT:-8002}"
report_dir="${DAST_REPORT_DIR:-$repo_root}"
report_html="${DAST_REPORT_HTML:-$report_dir/zap-report.html}"
report_json="${DAST_REPORT_JSON:-$report_dir/zap-report.json}"
exceptions_file="${DAST_EXCEPTIONS:-$repo_root/.github/security/dast-exceptions.json}"
summary_file="${GITHUB_STEP_SUMMARY:-}"
compose_file="${COMPOSE_FILE:-$repo_root/compose.e2e.yaml}"
dockerfile_path="${DOCKERFILE_PATH:-$repo_root/backend/Dockerfile}"
validator_script="${VALIDATOR_SCRIPT:-$repo_root/scripts/validate_dast_scan.py}"
docvault_image="${DOCVAULT_IMAGE:-docvault-api:local}"
skip_image_build="${SKIP_IMAGE_BUILD:-0}"
docker_bin="${DOCKER_BIN:-docker}"
readiness_timeout="${DAST_READINESS_TIMEOUT:-90}"
readiness_retries="${DAST_READINESS_RETRIES:-15}"
compose_timeout="${DAST_COMPOSE_TIMEOUT:-120}"
zap_max_mins="${ZAP_MAX_MINS:-2}"

# Official immutable multi-arch digest for OWASP ZAP stable image
ZAP_IMAGE_DEFAULT="ghcr.io/zaproxy/zaproxy:stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
zap_image="${ZAP_IMAGE:-$ZAP_IMAGE_DEFAULT}"

show_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Orchestrates an isolated OWASP ZAP passive baseline DAST scan against DocVault.

Options:
  -p, --port <port>        Host loopback port for the DocVault API (default: 8002)
  -o, --report-dir <dir>   Directory to store report artifacts (default: repo root)
  -r, --report-html <path> Path to output HTML report (default: <dir>/zap-report.html)
  -j, --report-json <path> Path to output JSON report (default: <dir>/zap-report.json)
  -e, --exceptions <path>  Path to DAST exceptions register (default: .github/security/dast-exceptions.json)
  -s, --summary <path>     Path to GitHub Step Summary markdown output
  --no-build               Skip container image build step
  -h, --help               Show this help message and exit
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--port)
      dast_port="$2"
      shift 2
      ;;
    -o|--report-dir)
      report_dir="$2"
      shift 2
      ;;
    -r|--report-html)
      report_html="$2"
      shift 2
      ;;
    -j|--report-json)
      report_json="$2"
      shift 2
      ;;
    -e|--exceptions)
      exceptions_file="$2"
      shift 2
      ;;
    -s|--summary)
      summary_file="$2"
      shift 2
      ;;
    --no-build)
      skip_image_build=1
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      printf '[ERROR] Unrecognized argument: %s\n' "$1" >&2
      show_help >&2
      exit 2
      ;;
  esac
done

printf '=== DocVault Dynamic Application Security Testing (DAST) ===\n'
printf 'Target port:        127.0.0.1:%s\n' "$dast_port"
printf 'Report dir:         %s\n' "$report_dir"
printf 'HTML report:        %s\n' "$report_html"
printf 'JSON report:        %s\n' "$report_json"
printf 'Exception register: %s\n' "$exceptions_file"
printf 'Skip image build:   %s\n\n' "$skip_image_build"

# 1. Verify required host utilities
if ! command -v timeout >/dev/null 2>&1; then
  printf '[ERROR] The "timeout" utility is required for bounded execution.\n' >&2
  exit 2
fi

if ! command -v "$docker_bin" >/dev/null 2>&1; then
  printf '[ERROR] Docker binary "%s" is not available on PATH.\n' "$docker_bin" >&2
  exit 2
fi

python_bin="${PYTHON_BIN:-}"
if [[ -z "$python_bin" ]]; then
  if [[ -x "$repo_root/.venv/bin/python" ]]; then
    python_bin="$repo_root/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  else
    printf '[ERROR] Python 3 runtime is required but was not found.\n' >&2
    exit 2
  fi
fi

if ! command -v "$python_bin" >/dev/null 2>&1 && [[ ! -x "$python_bin" ]]; then
  printf '[ERROR] Python binary "%s" is not executable.\n' "$python_bin" >&2
  exit 2
fi

# 2. Verify required repository paths
if [[ ! -f "$compose_file" ]]; then
  printf '[ERROR] Docker Compose file not found: %s\n' "$compose_file" >&2
  exit 2
fi

if [[ "$skip_image_build" -ne 1 && ! -f "$dockerfile_path" ]]; then
  printf '[ERROR] Dockerfile not found: %s\n' "$dockerfile_path" >&2
  exit 2
fi

if [[ ! -f "$validator_script" ]]; then
  printf '[ERROR] Validator script not found: %s\n' "$validator_script" >&2
  exit 2
fi

if [[ ! -f "$exceptions_file" ]]; then
  printf '[ERROR] Exception register not found: %s\n' "$exceptions_file" >&2
  exit 2
fi

# 3. Setup ephemeral environment and resources
project_name="docvault-dast-$("$python_bin" -c 'import secrets; print(secrets.token_hex(6))')"
private_dir="$(mktemp -d "${TMPDIR:-/tmp}/docvault-dast.XXXXXXXX")"
chmod 700 "$private_dir"
env_file="$private_dir/test.env"
umask 077

postgres_password="$("$python_bin" -c 'import secrets; print(secrets.token_urlsafe(32))')"
app_user="dv_dast_app_$("$python_bin" -c 'import secrets; print(secrets.token_hex(4))')"
app_password="$("$python_bin" -c 'import secrets; print(secrets.token_urlsafe(32))')"
migration_user="dv_dast_mig_$("$python_bin" -c 'import secrets; print(secrets.token_hex(4))')"
migration_password="$("$python_bin" -c 'import secrets; print(secrets.token_urlsafe(32))')"

cat >"$env_file" <<EOF
E2E_PORT=${dast_port}
E2E_POSTGRES_PASSWORD=${postgres_password}
E2E_APP_USER=${app_user}
E2E_APP_PASSWORD=${app_password}
E2E_MIGRATION_USER=${migration_user}
E2E_MIGRATION_PASSWORD=${migration_password}
EOF

# 4. Cleanup trap handler (idempotent, preserves original exit status)
zap_pid=""
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  printf '\nCleaning up isolated DAST containers and temporary resources...\n'
  if [[ -n "${zap_pid:-}" ]] && kill -0 "$zap_pid" 2>/dev/null; then
    kill "$zap_pid" 2>/dev/null || true
  fi

  if [[ -n "${project_name:-}" && -f "${env_file:-}" && -f "${compose_file:-}" ]]; then
    timeout 30s "$docker_bin" compose \
      --project-directory "$repo_root" \
      --project-name "$project_name" \
      --env-file "$env_file" \
      --file "$compose_file" \
      down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
  fi

  if [[ -n "${private_dir:-}" && -d "$private_dir" ]]; then
    rm -rf -- "$private_dir"
  fi

  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 5. Build production container image if requested
if [[ "$skip_image_build" -ne 1 ]]; then
  printf 'Building production DocVault container image (%s)...\n' "$docvault_image"
  if ! "$docker_bin" build -t "$docvault_image" -f "$dockerfile_path" "$repo_root"; then
    printf '[ERROR] Docker build failed for %s.\n' "$docvault_image" >&2
    exit 2
  fi
else
  printf 'Skipping container build (SKIP_IMAGE_BUILD=1). Using: %s\n' "$docvault_image"
fi

# 6. Start isolated Docker Compose stack
printf 'Starting isolated DocVault stack on 127.0.0.1:%s (project: %s)...\n' "$dast_port" "$project_name"

if ! timeout "${compose_timeout}s" "$docker_bin" compose \
  --project-directory "$repo_root" \
  --project-name "$project_name" \
  --env-file "$env_file" \
  --file "$compose_file" \
  up --detach --wait --wait-timeout "$readiness_timeout" e2e-api; then
  printf '[ERROR] Docker Compose stack failed to start or achieve readiness within %ss.\n' "$readiness_timeout" >&2
  exit 2
fi

# 7. Bounded verification of API readiness endpoint from host
printf 'Verifying DocVault API readiness endpoint at http://127.0.0.1:%s/ready...\n' "$dast_port"
api_ready=0
for _ in $(seq 1 "$readiness_retries"); do
  if "$python_bin" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${dast_port}/ready', timeout=2)" >/dev/null 2>&1; then
    api_ready=1
    break
  fi
  sleep 1
done

if [[ "$api_ready" -ne 1 ]]; then
  printf '[ERROR] DocVault API readiness check failed on http://127.0.0.1:%s/ready.\n' "$dast_port" >&2
  exit 2
fi
printf 'DocVault API is healthy and serving requests on 127.0.0.1:%s.\n' "$dast_port"

# 8. Ensure report directory exists
mkdir -p "$report_dir"
mkdir -p "$(dirname "$report_html")"
mkdir -p "$(dirname "$report_json")"

report_html_basename="$(basename "$report_html")"
report_json_basename="$(basename "$report_json")"
report_dir_abs="$(cd "$report_dir" && pwd)"
zap_target="http://127.0.0.1:${dast_port}"

# 9. Execute OWASP ZAP Baseline Scan (Passive-Only)
printf '\n================================================================\n'
printf '        Executing OWASP ZAP Passive Baseline DAST Scan          \n'
printf '================================================================\n'
printf 'Target URL:         %s\n' "$zap_target"
printf 'ZAP Container:      %s\n' "$zap_image"
printf 'HTML Report:        %s\n' "$report_html"
printf 'JSON Report:        %s\n' "$report_json"
printf 'Spider Max Mins:    %s\n' "$zap_max_mins"
printf '%s\n' '----------------------------------------------------------------'

scanner_status=0
if [[ -n "${ZAP_CMD:-}" ]]; then
  # Testing / mocking hook for ZAP command execution
  bash -c "$ZAP_CMD" &
  zap_pid=$!
  wait "$zap_pid" || scanner_status=$?
  zap_pid=""
else
  # Official OWASP ZAP container execution
  # -u $(id -u):$(id -g) ensures written reports have host runner file ownership
  # --network host connects directly to host loopback 127.0.0.1:${dast_port}
  # -I ensures ZAP does not return failure on findings, allowing scripts/validate_dast_scan.py
  # to serve as the authoritative policy decision engine
  "$docker_bin" run --rm \
    --network host \
    -u "$(id -u):$(id -g)" \
    -v "$report_dir_abs:/zap/wrk/:rw" \
    "$zap_image" \
    zap-baseline.py \
    -t "$zap_target" \
    -r "$report_html_basename" \
    -J "$report_json_basename" \
    -m "$zap_max_mins" \
    -I &
  zap_pid=$!
  wait "$zap_pid" || scanner_status=$?
  zap_pid=""
fi

if [[ -f "$report_dir_abs/$report_html_basename" && "$report_dir_abs/$report_html_basename" != "$report_html" ]]; then
  cp "$report_dir_abs/$report_html_basename" "$report_html" 2>/dev/null || true
fi
if [[ -f "$report_dir_abs/$report_json_basename" && "$report_dir_abs/$report_json_basename" != "$report_json" ]]; then
  cp "$report_dir_abs/$report_json_basename" "$report_json" 2>/dev/null || true
fi

printf 'ZAP scanner completed with execution status: %s\n' "$scanner_status"

# 10. Invoke D7.2 Validator Engine
printf '\n================================================================\n'
printf '      Validating DAST Scan Report against Policy Register       \n'
printf '================================================================\n'

validator_cmd=(
  "$python_bin" "$validator_script"
  --report "$report_json"
  --exceptions "$exceptions_file"
  --scanner-status "$scanner_status"
)

if [[ -n "$summary_file" ]]; then
  validator_cmd+=(--summary "$summary_file")
fi

validator_status=0
"${validator_cmd[@]}" || validator_status=$?

printf 'Validator evaluation finished with status: %s\n' "$validator_status"

if [[ "$validator_status" -eq 0 ]]; then
  printf '[SUCCESS] DAST scan passed policy validation.\n'
  exit 0
elif [[ "$validator_status" -eq 1 ]]; then
  printf '[FAIL] DAST policy violation detected (exit code 1).\n' >&2
  exit 1
else
  printf '[ERROR] DAST operational or configuration failure (exit code %s).\n' "$validator_status" >&2
  exit 2
fi
