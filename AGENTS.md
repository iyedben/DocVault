# Instructions for Codex sessions

## Project

DocVault is an academic secure document management and DevSecOps project. It is under active development and is not production-ready. The backend stack is Python 3.13, FastAPI, Pydantic, SQLAlchemy 2.x, PostgreSQL 17, psycopg, and Alembic. Docker and Docker Compose provide the local runtime. The planned browser client uses HTML, CSS, Bootstrap, and JavaScript; CI/CD and security/deployment tooling are roadmap items unless repository evidence shows otherwise.

## Repository conventions and architecture

- `backend/app/api/routes/`: FastAPI route modules; `api/dependencies.py` contains request authentication/authorization dependencies and `api/*schemas.py` contains request/response schemas.
- `backend/app/core/`: environment-backed configuration.
- `backend/app/db/`: SQLAlchemy base, engine, and session management.
- `backend/app/models/`: ORM models; `backend/migrations/versions/`: Alembic revisions.
- `backend/app/security/`: authentication and validation controls; `services/`: business rules; `storage/`: private file operations; `middleware/`: request-wide controls.
- `backend/tests/`: backend automated tests. `scripts/`: explicit operational or runtime validation helpers. `docs/`: phase records, plans, and handovers.
- Keep database schema changes in a new Alembic migration. Do not edit an already applied migration to change schema.
- Follow the existing small-module and typed Python style, pinned dependency conventions, and evidence-recording style. Keep phase plans distinct from results.

## Security requirements

- Inspect existing code and the current session/authentication model before implementing anything. Enforce authentication and authorization on the server for every protected operation; derive actor and owner from the authenticated session, never request-supplied identity, role, or permission data.
- Preserve least privilege: the API uses the application database role, while schema migrations use the separate migrator role. Use parameterized SQL/ORM operations.
- Preserve Argon2id password hashing, server-side opaque sessions, CSRF checks for cookie-authenticated state changes, and existing role safeguards.
- Treat filenames, IDs, MIME types, and file contents as untrusted. Keep document bytes outside the public web root, use opaque server-generated storage keys, bound request and file sizes, and avoid unsafe path operations.
- Return safe errors and avoid logging passwords, credentials, session/CSRF tokens, document bytes, or filesystem paths. Do not expose secrets in docs, command output, or generated artifacts.
- Do not grant administrators implicit document access unless an explicit project requirement and implementation authorize it.

## Coding and validation

- Read relevant docs, source, tests, Git status, and history before editing. Treat repository state as authoritative over stale summaries.
- Preserve existing user changes. Avoid unnecessary refactoring and keep edits within the requested scope.
- Add or adjust focused tests for behavior changes when requested or necessary to implement the task. Do not run broad/full suites unless asked; report exactly what was run and its actual result. Separate automated tests, static checks, and manual runtime evidence.
- Use the isolated project environment when available. Never infer that a passing test or runtime check occurred from test files, bytecode, or prior plans.
- Before finishing documentation or code changes, inspect the diff and run `git diff --check` when appropriate.

## Docker and runtime constraints

- Preserve the API container's non-root UID/GID 10001, read-only root filesystem, dropped capabilities, `no-new-privileges`, resource limits, and dedicated private persistent document volume.
- PostgreSQL is not host-published; it is on the internal database network. The API is loopback-published and uses its separate application access network. Do not weaken these boundaries casually.
- Keep `.env` and credentials out of Git, image build contexts, logs, and documentation. Do not remove or recreate persistent database/document volumes during setup or cleanup.
- Runtime observations are environment-specific. Verify Compose configuration or runtime only when relevant and safe; do not treat prior Phase 2 checks as validation of later application revisions.

## Git and change safety

- Never commit, push, reset, amend, or discard changes without explicit user authorization.
- Never overwrite or clean uncommitted user work. Inspect `git status` and diffs before edits and after them.
- Do not modify application source or migrations when a task is documentation-only. Keep generated or temporary files out of the repository unless explicitly required.

## Current verified project status — Phase D7.3.1, D7.4, D8.1–D8.6 & D9

Phase C (Playwright End-to-End Browser Testing), Phase D1/D2 (CI Foundation & Automated Quality Gates), Phase D3 (Dependency Vulnerability Audit), Phase D4 (Container Security & Artifact Gate), Phase D5 (Headless Browser E2E in CI), and Python 3.13 Runtime Migration are merged to `main` (commit `43718a6`). Active development is on dedicated branch `feature/dast-integration`. Phase D7.1 (DAST Architecture & Read-Only Assessment), Phase D7.2 (DAST Policy Validator & Exception Register), Phase D7.3 (DAST Scan Orchestrator), Phase D7.3.1 (ZAP Container Permission & Isolated Workspace Remediation), Phase D7.4 (GitHub Actions DAST Workflow Integration), Phase D8.1 (Jenkins CD + K3s Architecture Assessment), Phase D8.2 (Secure Jenkins Controller Installation), Phase D8.3 (K3s Preflight & Jenkins Scoped RBAC Architecture), Phase D8.4 (Minimal Jenkins-to-K3s Delivery Foundation), Phase D8.5 (Minimal Helm Deployment Through Jenkins to K3s), Phase D8.6 (Minimal Registry and Database Integration), and Phase D9 (End-to-End Deployment Verification) are implemented.

Phase D7.2 adds:
- **Dedicated Machine-Readable DAST Exception Register (`.github/security/dast-exceptions.json`):**
  - Strict JSON schema requiring `version: "1.0"` and `exceptions: [...]`.
  - Initially empty exception array (`"exceptions": []`) with zero speculative suppressions.
  - Strict field validation: `zap_rule_id` (numeric or string), `alert_name`, `target_url_pattern` (targeted regex path pattern), `severity` (`CRITICAL`, `HIGH`, `MEDIUM`), `reason` (minimum 10 characters), and canonical `expires_at` (`YYYY-MM-DD` through 23:59:59 UTC).
  - Explicit rejection of wildcard blanket suppressions (`.*`, `.+`, root wildcards) to ensure targeted endpoint scoping.
  - Automatic duplicate exception rejection and policy violation triggers for expired exceptions.
- **OWASP ZAP DAST Scan Validator (`scripts/validate_dast_scan.py`):**
  - Parses OWASP ZAP JSON reports robustly (`site[].alerts[]` or top-level `alerts[]`).
  - Evaluates alert instances with targeted URI regex matching to avoid broad suppression across unrelated endpoints sharing the same rule ID.
  - Normalizes ZAP risk codes (0–3) and risk descriptions (`High`, `Medium`, `Low`, `Informational`), strictly failing on unrecognized or missing severities.
  - Enforces severity policy: blocks on unapproved `CRITICAL`, `HIGH`, and `MEDIUM` findings; monitors `LOW` and `INFORMATIONAL` non-blocking.
  - Deterministic exit codes: 0 = pass/compliant, 1 = policy violation (unapproved High/Medium findings or expired exceptions), 2 = operational error (malformed report, invalid register schema, blanket suppressions, duplicate exceptions, scanner failures).
  - Emits console diagnostics and GitHub Step Summary (`$GITHUB_STEP_SUMMARY`) on all execution paths.
- **Automated DAST Validator Test Suite (`backend/tests/test_dast_scan_validator.py`):**
  - 24 automated unit and integration tests covering helper parsing, UTC date semantics, blanket suppression detection, severity normalization, clean reports, unapproved High/Medium findings, Low/Informational monitoring, valid exception matches, mismatched rule IDs, mismatched endpoint patterns, expired exceptions, duplicate exceptions, blanket suppression rejection, invalid report/register JSON, missing files, malformed alert structures, unknown severities, GitHub Step Summary output, scanner error statuses, and multi-instance partial matches.

Phase D7.3 & D7.3.1 adds:
- **Dedicated DAST Scan Orchestrator (`scripts/run_dast_scan.sh`):**
  - Builds production image from `backend/Dockerfile` locally without publishing (`SKIP_IMAGE_BUILD=1` supported for testing and pre-built image reuse).
  - Deploys an isolated disposable Docker Compose project on loopback port `8002` (`compose.e2e.yaml` foundation with tmpfs PostgreSQL and disposable volumes).
  - Bounded readiness verification polling `/ready` over host loopback with configurable bounded retries (`DAST_READINESS_RETRIES`).
  - Executes OWASP ZAP passive baseline scan using official pinned multi-arch immutable image `ghcr.io/zaproxy/zaproxy:stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`.
  - Enforces passive-only scanning (`zap-baseline.py` in host network mode, `-I`, bounded duration, scope strictly restricted to disposable target, zero active attack payloads, zero credentials).
  - **ZAP Container Permission & Workspace Remediation (D7.3.1):** Omits host runner identity (`-u 1001:1001`) to allow the container to run as default user `zap` (UID 1000) with write access to `/home/zap/zap.yaml`. Creates a dedicated temporary workspace directory (`$zap_work_dir`, mode `0777`) mounted at `/zap/wrk/:rw` (avoiding mounting repository source code or credentials), copies generated reports to `$DAST_REPORT_DIR` with `0644` permissions, rescues reports in `cleanup()` upon scanner error or interruption, and guarantees cleanup of temporary workspaces.
  - Invokes authoritative D7.2 policy validator (`scripts/validate_dast_scan.py`) against generated JSON report and exception register (`.github/security/dast-exceptions.json`).
  - Preserves ZAP HTML and JSON reports on all paths (success, failure, timeout).
  - Idempotent cleanup via traps on `EXIT`, `INT` (exit code 130), and `TERM` (exit code 143), tearing down compose stack with `down --volumes --remove-orphans` and deleting temporary test environments while preserving original exit status.
- **Automated DAST Orchestrator Test Suite (`backend/tests/test_dast_orchestrator.py`):**
  - 18 automated unit and integration tests covering missing host utilities, missing compose/dockerfile/exceptions paths, image build failure, compose startup failure and cleanup, readiness timeout, ZAP execution failure, validator operational failure on malformed report, unapproved High finding policy failure, unapproved Medium finding policy failure, approved Medium exception suppression, Low/Informational non-blocking monitoring, end-to-end success with report preservation, SIGTERM termination cleanup, SIGINT interruption cleanup, container invocation without runner UID forcing and isolated wrk mounting, scanner failure report preservation with 0644 mode, and workspace report rescue on SIGTERM.

Phase D7.4 adds:
- **Dedicated GitHub Actions DAST Workflow (`.github/workflows/dast.yml`):**
  - Triggers on `pull_request` targeting `main`, `push` to `main` and `feature/dast-integration`, and `workflow_dispatch`.
  - Minimal read-only permissions (`contents: read`), zero secrets exposure, strict prohibition of `pull_request_target`.
  - Concurrency group `dast-${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true`.
  - Exact check name: `OWASP ZAP Dynamic Security Scan`.
  - Bounded 15-minute job timeout on `ubuntu-latest`.
  - Pinned immutable action commit SHAs for checkout (`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`), python setup (`actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0`), and artifact upload (`actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1 # v4.6.1`).
  - Executes existing orchestrator `scripts/run_dast_scan.sh` without duplicating scan logic in YAML.
  - Safe artifact upload with `if: always()`, unique naming (`dast-reports-${{ github.run_id }}-${{ github.run_attempt }}`), bounded 7-day retention, and `if-no-files-found: error` (never silently ignored).
- **Automated DAST Workflow Test Suite (`backend/tests/test_dast_workflow.py`):**
  - 13 automated unit tests validating triggers, branches, minimal permissions, absence of secrets, prohibition of pull_request_target, exact check name, action commit SHA pinning, orchestrator invocation without duplicated logic, artifact upload retention and unique naming, expression validity, and absence of deployment/publishing steps.

Phase D8.1 & D8.2 adds:
- **Phase D8.1 — Jenkins CD + K3s Architecture Assessment:**
  - Completed strictly read-only technical assessment and architecture design (`docs/reports/D8.1_JENKINS_CD_ASSESSMENT.md`).
  - Formulated authoritative CI (GitHub Actions) vs CD (Jenkins) separation, digest-pinned image provenance (`@sha256:`), single-node K3s runtime, Helm deployment model, and 12-stage declarative CD pipeline.
- **Phase D8.2 — Secure Jenkins Controller Installation:**
  - Deployed official Jenkins LTS (`jenkins/jenkins:lts-jdk21@sha256:74401de6a6f92e1afe1b02d1c8e3d0c33f263bfb5275dd8813f9150355f2367b`) via dedicated Docker Compose in `/home/docvault/docvault-jenkins/` (mode `0700`, compose `0600`).
  - Strict loopback network binding: `127.0.0.1:8080`, unmapped agent port 50000, zero LAN/public exposure, dedicated bridge network `docvault_jenkins_network`.
  - Security boundaries enforced: `privileged: false`, `cap_drop: [ALL]`, `no-new-privileges: true`, `pids_limit: 256`, zero Docker socket mounts, zero host filesystem mounts, unprivileged `jenkins` container user.
  - Resource limits: `mem_limit: 1536m`, `cpus: 1.0`, JVM opts `-Xms512m -Xmx1024m -XX:+UseG1GC`.
  - Storage persistence verified across container restarts via dedicated named volume `docvault_jenkins_home`.
  - DocVault application containers verified untouched and continuously healthy (`/ready` 200 OK).
  - Setup wizard enabled for secure administrative onboarding over SSH tunnel (`docs/reports/D8.2_JENKINS_CONTROLLER_INSTALLATION.md`).
- **Phase D8.3 — K3s Cluster, Scoped Jenkins RBAC & Remediated Admission Policy:**
  - Completed comprehensive Phase A system preflight (Ubuntu 26.04.1, 4 vCPUs, 5.6 GiB available RAM, cgroup v2, subuid/subgid configured, port 6443/10250 free).
  - Selected official pinned stable release `v1.37.2+k3s1`.
  - Authored declarative manifests for namespace `docvault`, ServiceAccount `jenkins-deployer`, and least-privilege `Role`/`RoleBinding` (zero Secret get/list/watch, zero cluster-admin, zero cross-namespace access).
  - Remediated findings F-01 through F-10 plus Service restrictions: established two-policy architecture (`docvault-deployer-workload-guardrails` for `deployments` & `jobs`; `docvault-deployer-service-guardrails` for `services`) to ensure strict CEL schema type safety, scoped both to `system:serviceaccount:docvault:jenkins-deployer` via `matchConditions` on `request.userInfo.username` (exempting admin deployments), enforced mandatory `automountServiceAccountToken: false` and approved ServiceAccount `docvault-app`, prohibited initContainers, command/args overrides on Deployments (allowing exact allowlisted Alembic migration command on Jobs only), imagePullSecrets, projected SA tokens, and non-root overrides, enforced strict image provenance pinning `iyedbnaissa/docvault-api` with immutable sha256 digests (`@sha256:[a-f0-9]{64}`), and restricted Services to ClusterIP prohibiting externalIPs, nodePort, externalName, and LoadBalancer configurations.
  - Completed read-only network assessment confirming K3s Flannel VXLAN CNI and active `kube-router` NetworkPolicy controller (`npc_iptables`); documented future egress policy design and acknowledged current lack of egress isolation by admission policies alone.
  - Remediated `k8s/rbac/verify_d8_3.sh` with safe 5-stage preflight validation (including server-side dry-run abort before applying), partial-application detection and rollback instructions, deployer impersonation, stderr capture, policy-specific denial message verification, 5 positive admission tests (including allowlisted migration job), and 31 negative admission tests (24 workload + 7 service).
  - Implemented automated Python test suite (`backend/tests/test_d8_3_admission_rbac.py`) with 46 passing unit, schema separation, preflight sequencing, and script structure tests.
  - Preserved execution boundary: manifests remain unapplied to live cluster and live verification awaits authorized administrator execution (`docs/reports/D8.3_K3S_CLUSTER_AND_JENKINS_RBAC.md`).
- **Phase D8.4 — Minimal Jenkins-to-K3s Delivery Foundation:**
  - Implemented Jenkinsfile delivery pipeline (`jenkins/Jenkinsfile`) implementing Stages 1–5: target commit resolution on `main`, evaluation of all 8 mandatory GitHub Actions CI gates via Checks API, retrieval of published immutable image digest from CI artifact `scanned-image-metadata`, K3s API TLS authentication, and namespace isolation verification.
  - Hardened Jenkins-to-K3s authentication: uses `docvault-k3s-token` (short-lived TokenRequest bearer token for `system:serviceaccount:docvault:jenkins-deployer`), `docvault-k3s-ca` (K3s CA certificate `CN=k3s-server-ca@1794608986` validating SAN `IP:172.23.0.1`), and `docvault-github-token` (read-only token for Checks/Actions API). Zero insecure flags (`--insecure-skip-tls-verify`), zero cluster-admin credentials, zero Secret read permissions, and zero Docker socket mounts.
  - Verified immutable image provenance: extracted published image reference `iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687` from verified commit `14178f7dc0ff89fe16cd72bdbbe38cb90c838612`.
  - Delivered standalone CLI verification script (`scripts/verify_jenkins_delivery_foundation.py`) passing all 9 focused runtime checks across network, TLS, authentication, namespace authorization, CI gates, and image digest provenance.
  - Added automated Python test suite (`backend/tests/test_d8_4_delivery_foundation.py`) with 17 passing unit and structural tests.
  - Preserved strict non-deployment invariant: zero application workloads, Pods, Deployments, Services, Jobs, or Helm releases were created or deployed (`docs/reports/D8.4_JENKINS_K3S_DELIVERY_FOUNDATION.md`).
- **Phase D8.5 — Minimal Helm Deployment Through Jenkins to K3s:**
  - Designed and packaged production-compliant Helm chart (`helm/docvault/`) with templates for Deployment, Service (ClusterIP), ConfigMap, and PersistentVolumeClaim (`local-path`, 1Gi), strictly enforcing all 18 D8.3 admission policy rules. Zero Secret templates authored.
  - Configured Helm v3.16.3 with `HELM_DRIVER=configmap` on host and inside Dockerized Jenkins controller (`docvault-jenkins`), enabling release tracking without Kubernetes Secret read/write permissions.
  - Extended Jenkins pipeline (`jenkins/Jenkinsfile`) through Stages 6–8 (Helm chart linting, Helm upgrade/install, rollout status check).
  - Verified server-side admission dry-run: `helm template docvault helm/docvault | kubectl apply --dry-run=server --as=system:serviceaccount:docvault:jenkins-deployer -n docvault -f -` passed cleanly with 0 errors across all resources.
  - Verified Helm deployer dry-run: `HELM_DRIVER=configmap helm install docvault helm/docvault --dry-run ...` succeeded with code 0 (`STATUS: pending-install`).
  - Activated Section 4 Critical Feasibility Stop Condition: stopped before scheduling live failing workloads due to blocked database reachability (internal Docker Compose network), prohibited plain database credentials under admission rules, unprovisioned private registry pull authorization (`docvault-app` SA and pull secret missing), and unmigrated database schema.
  - Formulated the 4 smallest administrator actions needed to safely unblock live execution without compromising security boundaries (`docs/reports/D8.5_HELM_DEPLOYMENT_JENKINS_K3S.md`).
  - Added automated Python test suite (`backend/tests/test_d8_5_helm_deployment.py`) with 9 passing unit, chart structure, and pipeline integration tests.
- **Phase D8.6 — Minimal Registry and Database Integration:**
  - Resolved all four D8.5 deployment blockers out-of-band without granting Jenkins Secret read access or weakening RBAC boundaries.
  - Image-Pull Authorization: Provisioned administrator-managed Secret `docvault-registry-creds` (`kubernetes.io/dockerconfigjson`) and `ServiceAccount/docvault-app` (`automountServiceAccountToken: false`); verified image pull of `iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687` (`PULL_SUCCESS`).
  - PostgreSQL Connectivity: Established administrator-managed ClusterIP Service & Endpoints `docvault-postgres` on port 5432; verified CoreDNS resolution and TCP socket handshake (`SVC_RES: 0`).
  - Database Schema & Credentials: Provisioned `docvault-migration-db-creds` (`docvault_migrator`) and executed authorized initial Alembic migration Job `docvault-migrate-test` (exit code 0; schema verified at `head` / `0002_documents`).
  - Application Readiness: Provisioned `docvault-app-db-creds` (`docvault_app`); verified test application pod `test-app-readiness` booted, authenticated with PostgreSQL, executed `SELECT 1`, and answered 10 consecutive `/ready` probes with HTTP 200 OK.
  - Admission Guardrail Stop Condition: Formulated narrow CEL Rule 7 exception allowing only the approved triple `(docvault-app-db-creds, DATABASE_PASSWORD, database-password)`, preserving Jenkins zero-Secret RBAC boundary and halting before mutating live admission policy in accordance with Scope Item 7 and Stop Conditions (`docs/reports/D8.6_REGISTRY_AND_DATABASE_INTEGRATION.md`).
  - Added automated Python test suite (`backend/tests/test_d8_6_registry_database_integration.py`) with 12 passing unit, contract, and live cluster tests.
- **Phase D9 — End-to-End Deployment Verification:**
  - Automated Jenkins Pipeline Execution: Configured and executed pipeline job `docvault-delivery-pipeline` in Dockerized Jenkins controller (`docvault-jenkins`, loopback `127.0.0.1:8080`). Build #7 (initial run) and Build #8 (repeatable run) executed to full completion with status `SUCCESS`.
  - Delivery Gates & Provenance: Evaluated all 8 mandatory GitHub Actions CI gates on commit `14178f7dc0ff89fe16cd72bdbbe38cb90c838612`, downloaded CI artifact `scanned-image-metadata`, extracted immutable digest `sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687`, authenticated to K3s over TLS via TokenRequest bearer token for `system:serviceaccount:docvault:jenkins-deployer`, verified 5 namespace isolation boundaries (Pods/Deployments 200 OK; Secrets/kube-system/Nodes 403 Forbidden), and upgraded Helm release `docvault` via `HELM_DRIVER=configmap` (Revision 2 and Revision 3 deployed).
  - Application Readiness & Smoke Tests: DocVault API Pod achieved `1/1 Ready`. Endpoint `GET /health` returned HTTP 200 OK (`{"status": "healthy"}`); endpoint `GET /ready` returned HTTP 200 OK (`{"status": "ready", "database": "connected"}`). Verified authentication lifecycle (login, `docvault_session` cookie, `/auth/me`, explicit logout `204`, post-logout `401 Unauthorized`) and cross-user document tenant isolation (unauthorized access returned HTTP 404).
  - Document Integrity & Pod Restart Persistence: Uploaded valid PDF, inspected metadata, and verified downloaded document SHA-256 byte digest (`47b21aaed0c5fc1a4e4a4e5f9a8083fdf17247baf780155d08b6163b76a67fc2`) matched source file 100%. Executed controlled rollout restart (`kubectl rollout restart deployment/docvault -n docvault`); replacement Pod achieved `1/1 Ready`, re-attached to persistent volume claim `docvault-documents`, and served the document with matching SHA-256 integrity.
  - Automated Verification Harness & Tests: Added `backend/tests/test_d9_deployment_verification.py` (13 tests passing in ~24s). Total test suite spanning D8.3 through D9: 97 passed in 25.72s. Total automated security test suite: 152 passed in ~47s (`docs/reports/D9_END_TO_END_DEPLOYMENT_VERIFICATION.md`).

Latest verified validation:
- Exception register JSON parsing: **clean** (Python `json.tool` validated, 0 entries / empty baseline).
- Validator test suite (`test_dast_scan_validator.py`): **24 passed**.
- Orchestrator test suite (`test_dast_orchestrator.py`): **18 passed**.
- Workflow test suite (`test_dast_workflow.py`): **13 passed**.
- Total DAST test suite: **55 passed in ~17.1s**.
- Admission policy & scoped RBAC test suite (`test_d8_3_admission_rbac.py`): **46 passed in ~0.42s**.
- Jenkins delivery foundation test suite (`test_d8_4_delivery_foundation.py`): **17 passed in ~0.16s**.
- Helm deployment test suite (`test_d8_5_helm_deployment.py`): **9 passed in ~0.86s**.
- Registry & database integration test suite (`test_d8_6_registry_database_integration.py`): **12 passed in ~2.05s**.
- End-to-end deployment verification test suite (`test_d9_deployment_verification.py`): **13 passed in ~24s**.
- Total K3s/Jenkins test suite: **97 passed in 25.72s**.
- Total automated security test suite: **152 passed in ~47s**.
- Jenkins controller health: **healthy** (`HTTP/1.1 200 OK` on `127.0.0.1:8080/login`).
- Python development runtime: **Python 3.13.18** across user shell (`~/.local/bin/python`), project `.venv`, container (`docvault-api`), and CI workflows; Ubuntu system interpreter preserved (`/usr/bin/python3` -> 3.14.4).
- Bytecode compilation (`compileall`): **compiled cleanly across `backend/app`, `backend/tests`, and `scripts` with 0 errors**.
- Ruff linter check (`ruff check .`): **0 errors / clean**.
- Mypy static type checking (`mypy backend/app scripts/validate_dast_scan.py scripts/verify_jenkins_delivery_foundation.py backend/tests/test_dast_orchestrator.py backend/tests/test_dast_workflow.py backend/tests/test_d8_3_admission_rbac.py backend/tests/test_d8_4_delivery_foundation.py backend/tests/test_d8_5_helm_deployment.py backend/tests/test_d8_6_registry_database_integration.py backend/tests/test_d9_deployment_verification.py scripts/setup_jenkins_pipeline.py scripts/trigger_clean_build.py scripts/trigger_jenkins_pipeline.py`): **Success (0 issues in 52 source files)**.
- Whitespace check (`git diff --check`): **passed cleanly**.

Phase D roadmap:
- **D1:** GitHub Actions CI Foundation (Merged).
- **D2:** Static Analysis, Linting & Backend Automated Test CI Gates (Merged).
- **D3:** DevSecOps Security Pipeline (Dependency Vulnerability Scanning & Exception Management) (Merged).
- **D4:** Container Image Build & Artifact Security Validation (Merged).
- **D5:** Headless Browser E2E Testing in CI (Merged).
- **D6:** PR Verification Policies & Quality Gates (Active ruleset ID `27123717` requiring 7 checks).
- **D7:** OWASP ZAP DAST Integration & Pipeline Hardening (D7.1, D7.2, D7.3 & D7.4 Implemented).
- **D8:** Jenkins CD Pipeline Orchestration & Deployment (D8.1 Assessment, D8.2 Controller Installed, D8.3 RBAC Designed, D8.4 Delivery Foundation, D8.5 Helm Deployment Path & D8.6 Registry/Database Integration Implemented).
- **D9:** End-to-End Deployment Verification (Automated Jenkins Pipeline, Live K3s Pod Readiness, Auth/Doc Smoke Tests, PVC Persistence Across Restart, Repeatable CD Deployment Implemented & Verified).

Known limitations: Upstream Debian base OS packages in `python:3.13.18-slim` contain unpatched vulnerabilities covered by reviewed temporary exceptions in `.github/security/container-exceptions.json` through `2027-02-09`; application dependencies in `requirements-prod-lock.txt` have 0 known vulnerabilities; CVE-2026-119170 is completely absent on Python 3.13; Docker Hub publishing requires an authorized push event to `main` with configured repository secrets; DAST exceptions register starts empty; no malware scanning or sanitization; filesystem and database operations are not fully atomic. Active development is on `feature/dast-integration`. Never commit, push, reset, or amend without explicit authorization.
