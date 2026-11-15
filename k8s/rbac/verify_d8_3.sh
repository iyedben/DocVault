#!/usr/bin/env bash
# DocVault — Phase D8.3 RBAC & Admission Control Verification Script
# Remediated per read-only security review (13 November 2026).
# Must be executed on docvault-srv with cluster administrator privileges (sudo).
#
# NOTE: This script applies live Kubernetes resources to the cluster when executed!
# It executes preflight dry-run validation before mutating cluster state.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo "================================================================="
echo " DocVault D8.3 — RBAC & Admission Policy Verification Suite     "
echo " Remediated Admission Guardrails & Scoped CD RBAC Verification  "
echo "================================================================="
echo

# -----------------------------------------------------------------------------
# STEP 0: Preflight Validation (BEFORE ANY CLUSTER APPLICATION)
# -----------------------------------------------------------------------------
echo "[0/5] Executing Preflight Checks & Pre-Application Dry-Run..."

# 0.1 Check kubectl availability
if ! command -v kubectl >/dev/null 2>&1; then
  echo "FATAL [PREFLIGHT]: 'kubectl' command not found in PATH." >&2
  exit 2
fi

# 0.2 Check kubeconfig readability
if [ ! -r "$KUBECONFIG" ]; then
  echo "FATAL [PREFLIGHT]: Kubeconfig '$KUBECONFIG' is not readable. Run with sudo or set valid KUBECONFIG." >&2
  exit 2
fi

# 0.3 Check cluster connectivity
if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "FATAL [PREFLIGHT]: Unable to communicate with Kubernetes API server via '$KUBECONFIG'." >&2
  exit 2
fi

# 0.4 Confirm namespace docvault exists
if ! kubectl get namespace docvault >/dev/null 2>&1; then
  echo "FATAL [PREFLIGHT]: Namespace 'docvault' does not exist in cluster. Provision it before applying D8.3." >&2
  exit 2
fi
echo "  [PASS] Cluster connectivity and namespace 'docvault' confirmed."

# 0.5 Confirm ValidatingAdmissionPolicy API support
VAP_SUPPORT=$(kubectl api-resources --api-group=admissionregistration.k8s.io -o name 2>/dev/null || true)
if ! echo "$VAP_SUPPORT" | grep -q "validatingadmissionpolicies"; then
  echo "FATAL [PREFLIGHT]: API server does not support 'ValidatingAdmissionPolicy' in admissionregistration.k8s.io/v1." >&2
  exit 2
fi
if ! echo "$VAP_SUPPORT" | grep -q "validatingadmissionpolicybindings"; then
  echo "FATAL [PREFLIGHT]: API server does not support 'ValidatingAdmissionPolicyBinding' in admissionregistration.k8s.io/v1." >&2
  exit 2
fi
echo "  [PASS] ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding APIs supported."

# 0.6 Pre-Application Server-Side Dry-Run Validation of Both Manifests
echo "  Testing server-side dry-run of manifests before any application..."
PREFLIGHT_RBAC_ERR=""
if ! PREFLIGHT_RBAC_ERR=$(kubectl apply --dry-run=server -f "${SCRIPT_DIR}/jenkins-deployer-rbac.yaml" 2>&1); then
  echo "FATAL [PREFLIGHT]: Server-side dry-run validation failed for RBAC manifest! Aborting without applying any resources." >&2
  echo "$PREFLIGHT_RBAC_ERR" | sed 's/^/    /' >&2
  exit 2
fi

PREFLIGHT_POLICY_ERR=""
if ! PREFLIGHT_POLICY_ERR=$(kubectl apply --dry-run=server -f "${SCRIPT_DIR}/jenkins-admission-policy.yaml" 2>&1); then
  echo "FATAL [PREFLIGHT]: Server-side dry-run validation failed for Admission Policy manifest! Aborting without applying any resources." >&2
  echo "$PREFLIGHT_POLICY_ERR" | sed 's/^/    /' >&2
  exit 2
fi
echo "  [PASS] Both manifests validated cleanly via server-side dry-run."
echo "PASS: Preflight checks succeeded completely. Proceeding to live application."
echo

# -----------------------------------------------------------------------------
# STEP 1: Safe Manifest Application & Verification of Created Resources
# -----------------------------------------------------------------------------
echo "[1/5] Applying RBAC and Admission Policy manifests..."

RBAC_APPLIED=false
if kubectl apply -f "${SCRIPT_DIR}/jenkins-deployer-rbac.yaml"; then
  RBAC_APPLIED=true
  echo "  [PASS] RBAC manifest applied successfully."
else
  echo "FATAL: Failed to apply RBAC manifest (${SCRIPT_DIR}/jenkins-deployer-rbac.yaml)." >&2
  exit 1
fi

if kubectl apply -f "${SCRIPT_DIR}/jenkins-admission-policy.yaml"; then
  echo "  [PASS] Admission policy manifest applied successfully."
else
  echo "FATAL: Failed to apply Admission Policy manifest (${SCRIPT_DIR}/jenkins-admission-policy.yaml)!" >&2
  if [ "$RBAC_APPLIED" = "true" ]; then
    echo "CRITICAL: PARTIAL APPLICATION STATE DETECTED!" >&2
    echo "  RBAC resources were applied, but Admission Policy application failed." >&2
    echo "  To roll back partial RBAC state, execute:" >&2
    echo "    kubectl delete -f ${SCRIPT_DIR}/jenkins-deployer-rbac.yaml" >&2
  fi
  exit 3
fi

# Verify expected resources exist on cluster
echo "  Verifying that all expected resources exist on the cluster..."
kubectl get serviceaccount jenkins-deployer -n docvault >/dev/null 2>&1 || { echo "ERROR: ServiceAccount jenkins-deployer not found" >&2; exit 1; }
kubectl get role docvault-deployer-role -n docvault >/dev/null 2>&1 || { echo "ERROR: Role docvault-deployer-role not found" >&2; exit 1; }
kubectl get rolebinding docvault-deployer-binding -n docvault >/dev/null 2>&1 || { echo "ERROR: RoleBinding docvault-deployer-binding not found" >&2; exit 1; }
kubectl get validatingadmissionpolicy docvault-deployer-workload-guardrails >/dev/null 2>&1 || { echo "ERROR: ValidatingAdmissionPolicy docvault-deployer-workload-guardrails not found" >&2; exit 1; }
kubectl get validatingadmissionpolicybinding docvault-deployer-workload-guardrails-binding >/dev/null 2>&1 || { echo "ERROR: ValidatingAdmissionPolicyBinding docvault-deployer-workload-guardrails-binding not found" >&2; exit 1; }
kubectl get validatingadmissionpolicy docvault-deployer-service-guardrails >/dev/null 2>&1 || { echo "ERROR: ValidatingAdmissionPolicy docvault-deployer-service-guardrails not found" >&2; exit 1; }
kubectl get validatingadmissionpolicybinding docvault-deployer-service-guardrails-binding >/dev/null 2>&1 || { echo "ERROR: ValidatingAdmissionPolicyBinding docvault-deployer-service-guardrails-binding not found" >&2; exit 1; }
echo "PASS: All RBAC and split Admission Policy resources confirmed present on cluster."
echo

# -----------------------------------------------------------------------------
# STEP 2: Positive RBAC Impersonation Checks
# -----------------------------------------------------------------------------
echo "[2/5] Testing Positive RBAC Permissions (jenkins-deployer)..."
POSITIVE_TESTS=(
  "create deployments docvault"
  "get deployments docvault"
  "create jobs docvault"
  "create services docvault"
  "create configmaps docvault"
  "get pods docvault"
  "get pods/log docvault"
)

for test_case in "${POSITIVE_TESTS[@]}"; do
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  verb=$(echo "$test_case" | awk '{print $1}')
  resource=$(echo "$test_case" | awk '{print $2}')
  ns=$(echo "$test_case" | awk '{print $3}')

  raw_output=$(kubectl auth can-i "$verb" "$resource" -n "$ns" --as=system:serviceaccount:docvault:jenkins-deployer 2>&1) || true
  decision=$(echo "$raw_output" | grep -v '^Warning:' | tr -d '[:space:]')
  if [ "$decision" = "yes" ]; then
    echo "  [PASS] Allowed: $verb $resource (namespace: $ns)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  else
    echo "  [FAIL] Expected yes, got '$raw_output' (decision: '$decision') for: $verb $resource"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi
done
echo

# -----------------------------------------------------------------------------
# STEP 3: Negative RBAC Impersonation Checks
# -----------------------------------------------------------------------------
echo "[3/5] Testing Negative RBAC Denials (jenkins-deployer)..."
NEGATIVE_TESTS=(
  "get secrets docvault"
  "list secrets docvault"
  "watch secrets docvault"
  "create secrets docvault"
  "delete persistentvolumeclaims docvault"
  "delete jobs docvault"
  "create serviceaccounts docvault"
  "create roles docvault"
  "create rolebindings docvault"
  "create pods/exec docvault"
  "create pods/portforward docvault"
  "get pods kube-system"
  "get nodes none"
  "create clusterroles none"
  "create clusterrolebindings none"
)

for test_case in "${NEGATIVE_TESTS[@]}"; do
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  verb=$(echo "$test_case" | awk '{print $1}')
  resource=$(echo "$test_case" | awk '{print $2}')
  ns=$(echo "$test_case" | awk '{print $3}')

  if [ "$ns" = "none" ]; then
    raw_output=$(kubectl auth can-i "$verb" "$resource" --as=system:serviceaccount:docvault:jenkins-deployer 2>&1) || true
  else
    raw_output=$(kubectl auth can-i "$verb" "$resource" -n "$ns" --as=system:serviceaccount:docvault:jenkins-deployer 2>&1) || true
  fi

  # Filter out Warning lines (e.g. cluster-scoped resource warnings emitted by kubectl) to extract the authorization decision
  decision=$(echo "$raw_output" | grep -v '^Warning:' | tr -d '[:space:]')

  if [ "$decision" = "no" ]; then
    echo "  [PASS] Denied: $verb $resource (namespace: $ns)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  else
    echo "  [FAIL] Expected no, got '$raw_output' (decision: '$decision') for: $verb $resource"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi
done
echo

# -----------------------------------------------------------------------------
# STEP 4: ValidatingAdmissionPolicy Server-Side Dry-Run Tests
# -----------------------------------------------------------------------------
echo "[4/5] Testing ValidatingAdmissionPolicy Guardrails (Server-Side Dry-Run)..."

# Helper function to execute admission dry-run test
# Args:
#   $1: Test description
#   $2: Expected outcome: "ALLOW" or "DENY"
#   $3: If DENY, expected message substring; if ALLOW, ignored
#   $4: Impersonate user (e.g., "system:serviceaccount:docvault:jenkins-deployer", or "admin" for no impersonation)
#   $5: YAML manifest string
#   $6: Optional expected policy name (e.g. "docvault-deployer-workload-guardrails" or "docvault-deployer-service-guardrails")
run_admission_test() {
  local test_name="$1"
  local expected="$2"
  local expected_msg="$3"
  local as_user="$4"
  local yaml_payload="$5"
  local expected_policy="${6:-}"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  local output=""
  local exit_code=0

  local as_flag=()
  if [ "$as_user" != "admin" ]; then
    as_flag=("--as=${as_user}")
  fi

  output=$(echo "$yaml_payload" | kubectl apply --dry-run=server -f - "${as_flag[@]}" 2>&1) || exit_code=$?

  if [ "$expected" = "ALLOW" ]; then
    if [ $exit_code -eq 0 ]; then
      echo "  [PASS] $test_name (Allowed as expected)"
      PASSED_TESTS=$((PASSED_TESTS + 1))
      return 0
    else
      echo "  [FAIL] $test_name: Expected ALLOW, but command failed (exit code $exit_code):"
      echo "$output" | sed 's/^/    /'
      FAILED_TESTS=$((FAILED_TESTS + 1))
      return 1
    fi
  elif [ "$expected" = "DENY" ]; then
    if [ $exit_code -eq 0 ]; then
      echo "  [FAIL] $test_name: Expected DENY, but workload was unexpectedly ACCEPTED!"
      FAILED_TESTS=$((FAILED_TESTS + 1))
      return 1
    fi

    # Verify that rejection was produced by admission policy rather than syntax/operational error
    local is_policy_rejection=false
    if [ -n "$expected_policy" ]; then
      if echo "$output" | grep -q "$expected_policy"; then
        is_policy_rejection=true
      fi
    else
      if echo "$output" | grep -qE "docvault-deployer-(workload|service)-guardrails"; then
        is_policy_rejection=true
      elif echo "$output" | grep -iq -E "ValidatingAdmissionPolicy.*denied|admission.*denied"; then
        is_policy_rejection=true
      fi
    fi

    if [ "$is_policy_rejection" = "true" ]; then
      if [ -n "$expected_msg" ] && ! echo "$output" | grep -qF "$expected_msg"; then
        echo "  [FAIL] $test_name: Denied by admission policy (${expected_policy:-unknown}), but expected message '$expected_msg' not found in output:"
        echo "$output" | sed 's/^/    /'
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
      fi
      local pol_label="${expected_policy:-admission policy}"
      echo "  [PASS] $test_name (Correctly DENIED by $pol_label: '$expected_msg')"
      PASSED_TESTS=$((PASSED_TESTS + 1))
      return 0
    else
      echo "  [FAIL] $test_name: Failed with schema/operational error or wrong policy (expected '${expected_policy:-admission policy}'), NOT admission policy denial (exit code $exit_code):"
      echo "$output" | sed 's/^/    /'
      FAILED_TESTS=$((FAILED_TESTS + 1))
      return 1
    fi
  fi
}

AS_DEPLOYER="system:serviceaccount:docvault:jenkins-deployer"
POLICY_WORKLOAD="docvault-deployer-workload-guardrails"
POLICY_SERVICE="docvault-deployer-service-guardrails"

# --- Test 4.1: Positive Compliant Deployment ---
COMPLIANT_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-compliant-app
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-compliant
  template:
    metadata:
      labels:
        app: test-compliant
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            capabilities:
              drop:
                - ALL
EOF
)
run_admission_test "Compliant Deployment" "ALLOW" "" "$AS_DEPLOYER" "$COMPLIANT_DEPLOYMENT" || true

# --- Test 4.2: Positive Compliant Batch Job ---
COMPLIANT_JOB=$(cat << 'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: test-compliant-job
  namespace: docvault
spec:
  template:
    metadata:
      labels:
        app: test-compliant-job
    spec:
      restartPolicy: OnFailure
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: migration
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            capabilities:
              drop:
                - ALL
EOF
)
run_admission_test "Compliant Job" "ALLOW" "" "$AS_DEPLOYER" "$COMPLIANT_JOB" || true

# --- Test 4.2b: Positive Compliant Migration Job with Allowlisted Alembic Command ---
COMPLIANT_ALEMBIC_JOB=$(cat << 'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: test-compliant-alembic-job
  namespace: docvault
spec:
  template:
    metadata:
      labels:
        app: test-alembic-job
    spec:
      restartPolicy: OnFailure
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: migration
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          command: ["alembic", "-c", "alembic.ini", "upgrade", "head"]
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            capabilities:
              drop:
                - ALL
EOF
)
run_admission_test "Compliant Migration Job (Allowlisted Alembic Command)" "ALLOW" "" "$AS_DEPLOYER" "$COMPLIANT_ALEMBIC_JOB" || true

# --- Test 4.3: Positive Compliant Service (ClusterIP) ---
COMPLIANT_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-compliant-svc
  namespace: docvault
spec:
  type: ClusterIP
  selector:
    app: test-compliant
  ports:
    - name: http
      port: 8000
      targetPort: 8000
EOF
)
run_admission_test "Compliant Service (ClusterIP)" "ALLOW" "" "$AS_DEPLOYER" "$COMPLIANT_SERVICE" || true

# --- Test 4.4: Administrator Bypass (Non-Jenkins Actor) ---
ADMIN_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-admin-app
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-admin
  template:
    metadata:
      labels:
        app: test-admin
    spec:
      containers:
        - name: admin-app
          image: busybox:latest
          command: ["sh", "-c", "sleep 3600"]
EOF
)
run_admission_test "Administrator Bypass (Policy MatchCondition Exemption)" "ALLOW" "" "admin" "$ADMIN_DEPLOYMENT" || true

# --- Workload Negative Tests (Deployments & Jobs) ---

# --- Test 4.5: Negative - Privileged Container ---
PRIVILEGED_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-privileged
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-priv
  template:
    metadata:
      labels:
        app: test-priv
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: true
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Privileged Container" "DENY" "Privileged mode is prohibited" "$AS_DEPLOYER" "$PRIVILEGED_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.6: Negative - AllowPrivilegeEscalation: true ---
ESCALATION_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-escalation
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-esc
  template:
    metadata:
      labels:
        app: test-esc
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: true
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit AllowPrivilegeEscalation" "DENY" "allowPrivilegeEscalation must be false" "$AS_DEPLOYER" "$ESCALATION_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.7: Negative - Pod Missing runAsNonRoot: true ---
MISSING_NONROOT_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-missing-nonroot
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-nonroot
  template:
    metadata:
      labels:
        app: test-nonroot
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Require Pod runAsNonRoot: true" "DENY" "Pod spec must enforce runAsNonRoot: true" "$AS_DEPLOYER" "$MISSING_NONROOT_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.8: Negative - Container Override runAsNonRoot: false ---
CONTAINER_ROOT_OVERRIDE_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-root-override
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-root-ovr
  template:
    metadata:
      labels:
        app: test-root-ovr
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsNonRoot: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Container runAsNonRoot: false Override" "DENY" "no container or initContainer may override runAsNonRoot to false" "$AS_DEPLOYER" "$CONTAINER_ROOT_OVERRIDE_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.9: Negative - Missing capabilities.drop: ALL ---
MISSING_CAP_DROP_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-cap-drop
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-cap-drop
  template:
    metadata:
      labels:
        app: test-cap-drop
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
EOF
)
run_admission_test "Require Capabilities Drop ALL" "DENY" "Containers and initContainers must drop ALL capabilities" "$AS_DEPLOYER" "$MISSING_CAP_DROP_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.10: Negative - Added Capabilities ---
ADDED_CAPS_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-added-caps
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-added-caps
  template:
    metadata:
      labels:
        app: test-added-caps
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
              add: ["NET_ADMIN"]
EOF
)
run_admission_test "Prohibit Added Capabilities" "DENY" "cannot add capabilities" "$AS_DEPLOYER" "$ADDED_CAPS_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.11: Negative - Host Namespaces (hostNetwork: true) ---
HOSTNET_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-hostnet
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-hn
  template:
    metadata:
      labels:
        app: test-hn
    spec:
      hostNetwork: true
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Host Network" "DENY" "Host namespaces (hostNetwork, hostPID, hostIPC) are prohibited" "$AS_DEPLOYER" "$HOSTNET_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.12: Negative - Host Namespaces (hostPID: true) ---
HOSTPID_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-hostpid
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-hpid
  template:
    metadata:
      labels:
        app: test-hpid
    spec:
      hostPID: true
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Host PID" "DENY" "Host namespaces (hostNetwork, hostPID, hostIPC) are prohibited" "$AS_DEPLOYER" "$HOSTPID_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.13: Negative - hostPath Volume ---
HOSTPATH_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-hostpath
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-hp
  template:
    metadata:
      labels:
        app: test-hp
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      volumes:
        - name: host-root
          hostPath:
            path: /
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit hostPath Volume" "DENY" "hostPath volumes are prohibited" "$AS_DEPLOYER" "$HOSTPATH_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.14: Negative - Direct Secret Volume Mount ---
SECRET_MOUNT_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-secret-vol
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-sec
  template:
    metadata:
      labels:
        app: test-sec
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      volumes:
        - name: secret-vol
          secret:
            secretName: db-creds
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Direct Secret Volume Mount" "DENY" "Direct or projected Secret volume mounts are prohibited" "$AS_DEPLOYER" "$SECRET_MOUNT_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.15: Negative - Projected Secret Source ---
PROJECTED_SECRET_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-proj-sec
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-psec
  template:
    metadata:
      labels:
        app: test-psec
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      volumes:
        - name: proj-vol
          projected:
            sources:
              - secret:
                  name: db-creds
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Projected Secret Volume Source" "DENY" "Direct or projected Secret volume mounts are prohibited" "$AS_DEPLOYER" "$PROJECTED_SECRET_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.16: Negative - Secret-Backed Env Var (secretKeyRef) ---
SECRET_ENV_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-secret-env
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-senv
  template:
    metadata:
      labels:
        app: test-senv
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-creds
                  key: password
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Secret-Backed Env Var (secretKeyRef)" "DENY" "Secret-backed environment variables" "$AS_DEPLOYER" "$SECRET_ENV_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.17: Negative - Secret-Backed envFrom (secretRef) ---
SECRET_ENVFROM_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-secret-envfrom
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-sef
  template:
    metadata:
      labels:
        app: test-sef
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          envFrom:
            - secretRef:
                name: db-creds
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Secret-Backed envFrom (secretRef)" "DENY" "Secret-backed environment variables" "$AS_DEPLOYER" "$SECRET_ENVFROM_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.18: Negative - Host Port ---
HOSTPORT_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-hostport
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-hp
  template:
    metadata:
      labels:
        app: test-hp
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          ports:
            - containerPort: 8000
              hostPort: 8080
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Host Ports" "DENY" "Host ports are prohibited" "$AS_DEPLOYER" "$HOSTPORT_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.19: Negative - Omitted automountServiceAccountToken ---
OMITTED_TOKEN_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-omitted-token
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-otok
  template:
    metadata:
      labels:
        app: test-otok
    spec:
      serviceAccountName: docvault-app
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Omitted automountServiceAccountToken" "DENY" "automountServiceAccountToken: false" "$AS_DEPLOYER" "$OMITTED_TOKEN_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.20: Negative - automountServiceAccountToken: true ---
ENABLED_TOKEN_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-enabled-token
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-etok
  template:
    metadata:
      labels:
        app: test-etok
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: true
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit automountServiceAccountToken: true" "DENY" "automountServiceAccountToken: false" "$AS_DEPLOYER" "$ENABLED_TOKEN_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.21: Negative - Unapproved ServiceAccount (default) ---
UNAPPROVED_SA_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-unapproved-sa
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-usa
  template:
    metadata:
      labels:
        app: test-usa
    spec:
      serviceAccountName: default
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Unapproved ServiceAccount (default)" "DENY" "serviceAccountName: docvault-app" "$AS_DEPLOYER" "$UNAPPROVED_SA_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.22: Negative - Projected ServiceAccount Token Volume ---
PROJECTED_TOKEN_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-projected-token
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-ptok
  template:
    metadata:
      labels:
        app: test-ptok
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      volumes:
        - name: token-vol
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 3600
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Projected ServiceAccount Token Volume" "DENY" "zero projected serviceAccountToken volumes" "$AS_DEPLOYER" "$PROJECTED_TOKEN_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.23: Negative - Init Containers Present ---
INIT_CONTAINER_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-init-containers
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-init
  template:
    metadata:
      labels:
        app: test-init
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      initContainers:
        - name: init-setup
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Init Containers for Deployment Identity" "DENY" "initContainers are prohibited for deployment identity" "$AS_DEPLOYER" "$INIT_CONTAINER_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.24: Negative - Unapproved Image Repository ---
UNAPPROVED_IMAGE_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-unapproved-image
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-img
  template:
    metadata:
      labels:
        app: test-img
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: malicious/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Unapproved Image Repository" "DENY" "Container image must be from iyedbnaissa/docvault-api with an immutable sha256 digest" "$AS_DEPLOYER" "$UNAPPROVED_IMAGE_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.25: Negative - Mutable Image Tag Without Digest ---
MUTABLE_TAG_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-mutable-tag
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-tag
  template:
    metadata:
      labels:
        app: test-tag
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api:latest
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Mutable Image Tag Without Digest" "DENY" "Container image must be from iyedbnaissa/docvault-api with an immutable sha256 digest" "$AS_DEPLOYER" "$MUTABLE_TAG_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.26: Negative - Command Override ---
COMMAND_OVERRIDE_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-cmd-override
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-cmd
  template:
    metadata:
      labels:
        app: test-cmd
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          command: ["/bin/sh", "-c", "echo pwned"]
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Container Command Override" "DENY" "Container command and args overrides are prohibited" "$AS_DEPLOYER" "$COMMAND_OVERRIDE_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.27: Negative - Args Override ---
ARGS_OVERRIDE_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-args-override
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-args
  template:
    metadata:
      labels:
        app: test-args
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          args: ["--help"]
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit Container Args Override" "DENY" "Container command and args overrides are prohibited" "$AS_DEPLOYER" "$ARGS_OVERRIDE_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Test 4.28: Negative - imagePullSecrets ---
PULL_SECRETS_DEPLOYMENT=$(cat << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-fail-pull-secrets
  namespace: docvault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-pullsec
  template:
    metadata:
      labels:
        app: test-pullsec
    spec:
      serviceAccountName: docvault-app
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      imagePullSecrets:
        - name: registry-secret
      containers:
        - name: app
          image: iyedbnaissa/docvault-api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
EOF
)
run_admission_test "Prohibit imagePullSecrets on Workload Template" "DENY" "imagePullSecrets are prohibited on deployment templates" "$AS_DEPLOYER" "$PULL_SECRETS_DEPLOYMENT" "$POLICY_WORKLOAD" || true

# --- Service Negative Tests ---

# --- Test 4.29: Negative Service - NodePort Type ---
NODEPORT_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-nodeport
  namespace: docvault
spec:
  type: NodePort
  selector:
    app: test-nodeport
  ports:
    - name: http
      port: 80
      targetPort: 8000
EOF
)
run_admission_test "Prohibit Service NodePort Type" "DENY" "Services must be of type ClusterIP" "$AS_DEPLOYER" "$NODEPORT_SERVICE" "$POLICY_SERVICE" || true

# --- Test 4.30: Negative Service - LoadBalancer Type ---
LOADBALANCER_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-lb
  namespace: docvault
spec:
  type: LoadBalancer
  selector:
    app: test-lb
  ports:
    - name: http
      port: 80
      targetPort: 8000
EOF
)
run_admission_test "Prohibit Service LoadBalancer Type" "DENY" "Services must be of type ClusterIP" "$AS_DEPLOYER" "$LOADBALANCER_SERVICE" "$POLICY_SERVICE" || true

# --- Test 4.31: Negative Service - ExternalName Type ---
EXTERNALNAME_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-extname
  namespace: docvault
spec:
  type: ExternalName
  externalName: api.example.com
EOF
)
run_admission_test "Prohibit Service ExternalName Type" "DENY" "Services must be of type ClusterIP" "$AS_DEPLOYER" "$EXTERNALNAME_SERVICE" "$POLICY_SERVICE" || true

# --- Test 4.32: Negative Service - externalIPs Specified ---
EXTERNALIPS_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-extips
  namespace: docvault
spec:
  type: ClusterIP
  selector:
    app: test-extips
  externalIPs:
    - 198.51.100.1
  ports:
    - name: http
      port: 8000
      targetPort: 8000
EOF
)
run_admission_test "Prohibit Service externalIPs" "DENY" "externalIPs are prohibited on Services" "$AS_DEPLOYER" "$EXTERNALIPS_SERVICE" "$POLICY_SERVICE" || true

# --- Test 4.33: Negative Service - Explicit nodePort Value Specified ---
# NOTE ON KUBERNETES SCHEMA & VAP SEQUENTIAL EVALUATION:
# Kubernetes core schema validation forbids explicit nodePort on type: ClusterIP ('spec.ports[0].nodePort:
# Forbidden: may not be used when type is ClusterIP') before admission policies evaluate.
# On type: NodePort, Kubernetes schema accepts it, but Rule 1 ('Services must be of type ClusterIP')
# is evaluated first by Kubernetes VAP engine and short-circuits with 'Services must be of type ClusterIP',
# preventing Rule 3 ('Explicit nodePort values are prohibited on Services') from executing.
# Therefore, on the live cluster, an explicit nodePort Service is guaranteed to be denied by
# docvault-deployer-service-guardrails (Rule 1). Rule 3's independent CEL expression is verified
# via static unit testing (test_cel_service_explicit_nodeport_denied).
EXPLICIT_NODEPORT_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-expnp
  namespace: docvault
spec:
  type: NodePort
  selector:
    app: test-expnp
  ports:
    - name: http
      port: 8000
      targetPort: 8000
      nodePort: 32000
EOF
)
run_admission_test "Prohibit Explicit Service nodePort" "DENY" "Services must be of type ClusterIP" "$AS_DEPLOYER" "$EXPLICIT_NODEPORT_SERVICE" "$POLICY_SERVICE" || true

# --- Test 4.34: Negative Service - externalName Field Specified ---
EXTNAME_FIELD_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-extfield
  namespace: docvault
spec:
  type: ClusterIP
  selector:
    app: test-extfield
  externalName: malicious.domain.internal
  ports:
    - name: http
      port: 8000
      targetPort: 8000
EOF
)
run_admission_test "Prohibit Service externalName Field" "DENY" "externalName is prohibited on Services" "$AS_DEPLOYER" "$EXTNAME_FIELD_SERVICE" "$POLICY_SERVICE" || true

# --- Test 4.35: Negative Service - LoadBalancer Configuration Specified ---
LB_CONFIG_SERVICE=$(cat << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: test-fail-svc-lbconfig
  namespace: docvault
spec:
  type: ClusterIP
  selector:
    app: test-lbconfig
  loadBalancerIP: 198.51.100.1
  ports:
    - name: http
      port: 8000
      targetPort: 8000
EOF
)
run_admission_test "Prohibit Service LoadBalancer Configuration" "DENY" "LoadBalancer configuration is prohibited on Services" "$AS_DEPLOYER" "$LB_CONFIG_SERVICE" "$POLICY_SERVICE" || true

# -----------------------------------------------------------------------------
# STEP 5: Verification Summary & Exit Status
# -----------------------------------------------------------------------------
echo
echo "================================================================="
echo " VERIFICATION SUMMARY                                           "
echo " Total Tests:  $TOTAL_TESTS"
echo " Passed Tests: $PASSED_TESTS"
echo " Failed Tests: $FAILED_TESTS"
echo "================================================================="

if [ $FAILED_TESTS -gt 0 ]; then
  echo "OVERALL STATUS: FAILED ($FAILED_TESTS failures detected)"
  exit 1
else
  echo "OVERALL STATUS: ALL TESTS PASSED SUCCESSFULLY!"
  exit 0
fi
