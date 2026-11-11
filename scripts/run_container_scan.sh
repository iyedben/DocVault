#!/usr/bin/env bash

# DocVault Local Container Vulnerability Scanner Helper
# Runs Grype vulnerability scan on an existing local DocVault image and
# evaluates the findings using scripts/validate_container_scan.py.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_tag="${1:-docvault-api:local}"
report_file="${2:-$repo_root/grype-report.json}"
exceptions_file="$repo_root/.github/security/container-exceptions.json"

printf '=== DocVault Local Container Vulnerability Scanner ===\n'
printf 'Target image:       %s\n' "$image_tag"
printf 'Report output:      %s\n' "$report_file"
printf 'Exception register: %s\n\n' "$exceptions_file"

# 1. Verify Docker availability
if ! command -v docker >/dev/null 2>&1; then
  printf '[ERROR] Docker is required to inspect and scan local images.\n' >&2
  exit 2
fi

# 2. Verify that the target image exists locally
if ! docker image inspect "$image_tag" >/dev/null 2>&1; then
  printf '[ERROR] Image "%s" not found in local Docker cache.\n' "$image_tag" >&2
  printf 'Please build the image first using:\n' >&2
  printf '  docker build -t %s -f backend/Dockerfile .\n' "$image_tag" >&2
  exit 2
fi

# 3. Determine Grype execution method (local binary or ephemeral container)
grype_cmd=()
if command -v grype >/dev/null 2>&1; then
  printf 'Using host Grype binary: %s\n' "$(command -v grype)"
  grype_cmd=(grype "docker:$image_tag" -o json --file "$report_file")
elif docker image inspect anchore/grype:latest >/dev/null 2>&1 || docker image inspect anchore/grype >/dev/null 2>&1; then
  printf 'Using containerized Grype via local anchore/grype image...\n'
  grype_cmd=(
    docker run --rm
    -v /var/run/docker.sock:/var/run/docker.sock:ro
    -v "$repo_root:/repo"
    -w /repo
    anchore/grype:latest
    "docker:$image_tag" -o json --file "/repo/$(basename "$report_file")"
  )
else
  printf '[ERROR] Grype was not found on PATH and container image "anchore/grype" is not present.\n' >&2
  printf 'To run container vulnerability scans, please install Grype:\n' >&2
  printf '  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin\n' >&2
  printf 'Or pull the container image:\n' >&2
  printf '  docker pull anchore/grype:latest\n' >&2
  exit 2
fi

# 4. Execute scan and capture status
printf 'Executing Grype vulnerability scan on %s...\n' "$image_tag"
scanner_status=0
"${grype_cmd[@]}" || scanner_status=$?

# 5. Invoke Python validation engine
printf '\nValidating scan report against container exception register...\n'
validator_script="$repo_root/scripts/validate_container_scan.py"
python_bin="python3"
if [[ -f "$repo_root/.venv/bin/python" ]]; then
  python_bin="$repo_root/.venv/bin/python"
fi

"$python_bin" "$validator_script" \
  --report "$report_file" \
  --exceptions "$exceptions_file" \
  --scanner-status "$scanner_status"
