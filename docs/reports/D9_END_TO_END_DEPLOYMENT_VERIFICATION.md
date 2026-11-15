# DocVault Phase D9 — End-to-End Deployment Verification Report

**Document Version:** 1.0  
**Date:** 14 November 2026  
**Repository:** `iyedben/DocVault`  
**Branch:** `feature/dast-integration`  
**Target Commit:** `14178f7dc0ff89fe16cd72bdbbe38cb90c838612` (on `main`)  
**Deployment Driver:** Helm v3.16.3 (`HELM_DRIVER=configmap`)  
**Cluster:** Single-Node K3s `v1.37.2+k3s1` (Namespace `docvault`)  
**Pipeline Engine:** Jenkins LTS (Dockerized Controller `docvault-jenkins`, loopback-only `127.0.0.1:8080`)  
**Deployer Identity:** `system:serviceaccount:docvault:jenkins-deployer` (Scoped least-privilege RBAC)  
**Application Identity:** `system:serviceaccount:docvault:docvault-app`  
**Application Image:** `iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687`  

---

## 1. Executive Summary

Phase D9 validates and demonstrates the operational, repeatable end-to-end delivery workflow of the DocVault academic DevSecOps project:

$$\text{GitHub Actions CI / Security Gates} \longrightarrow \text{Jenkins CD Pipeline} \longrightarrow \text{Helm Chart} \longrightarrow \text{K3s Admission Guardrails} \longrightarrow \text{DocVault API Pod} \longleftrightarrow \text{PostgreSQL}$$

Rather than relying on manual CLI commands or speculative tests, Phase D9 empirically executes the end-to-end continuous delivery pipeline inside the hardened Dockerized Jenkins controller (`docvault-jenkins`), deploys to the live K3s cluster through the restricted ServiceAccount `system:serviceaccount:docvault:jenkins-deployer`, and performs automated smoke tests, authentication lifecycle verification, document integrity and isolation checks, persistent volume survival across Pod restarts, and repeatable deployment execution.

### Key Milestones Achieved:
1. **Automated Jenkins Pipeline Execution:** Established and executed pipeline job `docvault-delivery-pipeline`. Build #7 and Build #8 completed with full success (`Finished: SUCCESS`), evaluating all 8 GitHub Actions CI checks, validating image provenance, verifying K3s TLS & namespace isolation, and orchestrating Helm upgrades.
2. **Strict RBAC & Zero-Secret Boundaries Preserved:** Jenkins executed with zero Kubernetes Secret read/list/watch permissions, zero Docker socket mounts, and zero cluster-admin privileges. All Helm state is tracked using `HELM_DRIVER=configmap`.
3. **Application Health & DB Handshake:** Pod reached `1/1 Ready`. Endpoints `/health` and `/ready` returned HTTP 200 OK with verified active PostgreSQL database communication.
4. **Authentication & Access Control Smoke Tests:** Verified login, secure cookie issuance (`docvault_session`), CSRF tokens, authenticated user profile (`/api/v1/auth/me`), explicit logout session invalidation (`401 Unauthorized`), and cross-user tenant isolation (unauthorized requests return HTTP 404).
5. **Document Lifecycle & SHA-256 Byte Integrity:** Uploaded valid PDF, queried metadata, and verified downloaded document SHA-256 byte digest matched the source file exactly (`47b21aaed0c5fc1a4e4a4e5f9a8083fdf17247baf780155d08b6163b76a67fc2`).
6. **Persistence Verification Across Pod Rollout Restart:** Executed a controlled rollout restart of `deployment/docvault`. The replacement Pod achieved `Ready: True`, re-attached to the existing persistent volume claim (`docvault-documents`), and served the uploaded PDF with identical SHA-256 integrity.
7. **Repeatable CD Deployment (Build #8):** Triggered a second automated CD pipeline execution without rebuilding images. Helm successfully upgraded the release to Revision 3, maintained Pod readiness, and preserved application state.

---

## 2. Actual Jenkins Job Name and Execution Result

Automated pipeline execution was performed by the Jenkins Pipeline job `docvault-delivery-pipeline` (type `org.jenkinsci.plugins.workflow.job.WorkflowJob`) using declarative pipeline script `jenkins/Jenkinsfile`.

### Execution Summary:

| Build Number | Trigger / Action | Target Commit | Parameters | Execution Result | Helm Release Revision |
|---|---|---|---|---|---|
| **Build #1–#6** | Pipeline Compilation & Sandbox Fixes | `14178f7dc0ff...` | `HELM_DRY_RUN=false` | FAILED (Groovy syntax / Ansicolor / CPS serialization) | None |
| **Build #7** | **Initial End-to-End CD Run** | `14178f7dc0ff...` | `HELM_DRY_RUN=false` | **SUCCESS (100% Passed)** | **Revision 2 (deployed)** |
| **Build #8** | **Repeatable CD Verification Run** | `14178f7dc0ff...` | `HELM_DRY_RUN=false` | **SUCCESS (100% Passed)** | **Revision 3 (deployed)** |

### Log Excerpt from Authoritative Jenkins Build #7:
```text
[Pipeline] Start of Pipeline
[Pipeline] node
Running on Jenkins in /var/jenkins_home/workspace/docvault-delivery-pipeline
...
=== Stage 1: Resolving and Verifying Commit on main ===
Validating that commit 14178f7dc0ff89fe16cd72bdbbe38cb90c838612 belongs to branch 'main'...
Commit 14178f7dc0ff89fe16cd72bdbbe38cb90c838612 is verified on 'main' (compare status: identical).
...
=== Stage 2: Verifying 8 GitHub Actions CI / Security Gates ===
Gate 1/8 [Gitleaks secret scan]: SUCCESS
Gate 2/8 [Automated Quality & Testing Gates]: SUCCESS
Gate 3/8 [Dependency vulnerability audit]: SUCCESS
Gate 4/8 [Semgrep SAST]: SUCCESS
Gate 5/8 [Build Container Image]: SUCCESS
Gate 6/8 [Vulnerability Scan & Policy Validation]: SUCCESS
Gate 7/8 [Playwright Browser End-to-End Tests]: SUCCESS
Gate 8/8 [OWASP ZAP Dynamic Security Scan]: SUCCESS
All 8 mandatory GitHub Actions CI gates PASSED.
...
=== Stage 3: Extracting Immutable Scanned Image Digest from CI Artifacts ===
Scanned Container Image Reference: iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687
...
=== Stage 4: Authenticating to K3s API via Deployer Token ===
Successfully authenticated to K3s endpoint via deployer ServiceAccount.
...
=== Stage 5: Verifying Namespace Isolation & Least Privilege ===
[PASS] Pod list in docvault succeeded (200 OK)
[PASS] Deployments list in docvault succeeded (200 OK)
[PASS] Secrets in docvault rejected (403 Forbidden)
[PASS] Pods in kube-system rejected (403 Forbidden)
[PASS] Nodes rejected (403 Forbidden)
Namespace isolation and RBAC least-privilege boundary verified.
...
=== Stage 6: Linting and Validating Helm Chart ===
1 chart(s) linted, 0 chart(s) failed
Helm template validation passed.
...
=== Stage 7: Deploying / Upgrading DocVault Application via Helm ===
Release "docvault" has been upgraded. Happy Helming!
NAME: docvault
LAST DEPLOYED: Sat Nov 14 16:33:13 2026
NAMESPACE: docvault
STATUS: deployed
REVISION: 2
...
=== Stage 8: Verifying Rollout and Application Readiness ===
Retrieved live deployment status from K3s API.
=================================================================
 DocVault D8.5 Helm Delivery Pipeline: SUCCESS!
 Commit: 14178f7dc0ff89fe16cd72bdbbe38cb90c838612
 Immutable Image: iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687
 K3s Deployer Authentication & Namespace Boundary: VERIFIED
 Helm Release: DEPLOYED (dry-run: false)
=================================================================
Finished: SUCCESS
```

---

## 3. Target Git Commit and Image Digest

| Artifact | Identifier | Verification Method |
|---|---|---|
| **Target Git Commit** | `14178f7dc0ff89fe16cd72bdbbe38cb90c838612` | Verified against GitHub REST API (`/repos/iyedben/DocVault/compare/main...${commitSha}`) returning `status: "identical"`. |
| **Scanned Image Digest** | `sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687` | Extracted from CI artifact `scanned-image-metadata` (artifact ID `14060526826` from workflow run `43470385440`). |
| **Fully Qualified Image Reference** | `iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687` | Enforced in Helm `values.yaml` and verified by K3s ValidatingAdmissionPolicy Rule 6 (`iyedbnaissa/docvault-api@sha256:[a-f0-9]{64}`). |

---

## 4. GitHub Actions CI Gate Results

In Stage 2 of the Jenkins pipeline, the target commit was queried against the GitHub Checks API (`/repos/iyedben/DocVault/commits/${commitSha}/check-runs`). All 8 mandatory quality, vulnerability, and testing gates passed with status `completed` and conclusion `success`:

| Gate # | Exact Check Name in CI | Pipeline Evaluation | Empirical Status |
|---|---|---|---|
| 1 | `Gitleaks secret scan` | Validates zero hardcoded secrets or credentials committed | **SUCCESS** |
| 2 | `Automated Quality & Testing Gates` | Backend linting (Ruff), typing (Mypy), and unit tests | **SUCCESS** |
| 3 | `Dependency vulnerability audit` | Pip-audit CVE scan against pinned dependencies | **SUCCESS** |
| 4 | `Semgrep SAST` | Static application security testing rules | **SUCCESS** |
| 5 | `Build Container Image` | Minimal OCI container build with non-root user | **SUCCESS** |
| 6 | `Vulnerability Scan & Policy Validation` | Trivy container vulnerability scan and SARIF upload | **SUCCESS** |
| 7 | `Playwright Browser End-to-End Tests` | Headless browser end-to-end integration suite | **SUCCESS** |
| 8 | `OWASP ZAP Dynamic Security Scan` | Baseline passive DAST scan and policy validation | **SUCCESS** |

---

## 5. Jenkins Stage Results

The Jenkins declarative pipeline consists of 8 linear stages and post-execution hooks:

```
[1. Resolve Commit] ──> [2. Verify CI Gates] ──> [3. Extract Digest] ──> [4. Auth to K3s]
        │
        └──> [5. Verify RBAC / Isolation] ──> [6. Lint Helm] ──> [7. Deploy Helm] ──> [8. Verify Rollout]
```

| Stage | Name | Key Operations | Result |
|---|---|---|---|
| **1** | **Resolve Target Commit on main** | Queries GitHub API; validates commit belongs to `main` branch. | **SUCCESS** |
| **2** | **Verify GitHub Actions CI / Security Gates** | Queries check-runs; ensures all 8 required gates are `completed` / `success`. | **SUCCESS** |
| **3** | **Extract Scanned Image Digest from Artifacts** | Queries workflow runs; downloads `scanned-image-metadata`; parses digest via NonCPS helper. | **SUCCESS** |
| **4** | **Authenticate to K3s API via Deployer Token** | Validates K3s CA certificate (`docvault-k3s-ca`) and TokenRequest bearer token (`docvault-k3s-token`). | **SUCCESS** |
| **5** | **Verify Namespace Isolation & Least Privilege** | Tests 5 API endpoints (Pods/Deployments 200 OK; Secrets/kube-system/Nodes 403 Forbidden). | **SUCCESS** |
| **6** | **Lint and Validate Helm Chart** | Runs `helm lint helm/docvault` and `helm template` dry-run. | **SUCCESS** |
| **7** | **Deploy / Upgrade DocVault Application via Helm** | Executes `HELM_DRIVER=configmap helm upgrade --install docvault ./helm/docvault -n docvault`. | **SUCCESS** |
| **8** | **Verify Rollout and Application Readiness** | Queries live deployment rollout state from K3s API. | **SUCCESS** |

---

## 6. K3s Deployment and Pod Readiness

### Live Cluster Status (Post-D9):
```text
$ KUBECONFIG=/home/docvault/.kube/config kubectl get pods,svc,pvc,deployments -n docvault -o wide

NAME                            READY   STATUS    RESTARTS   AGE   IP           NODE           NOMINATED NODE   READINESS GATES
pod/docvault-5f67455bd8-r2vkc   1/1     Running   0          37s   10.42.0.29   docvault-srv   <none>           <none>

NAME                        TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE    SELECTOR
service/docvault            ClusterIP   10.43.16.81    <none>        8000/TCP   79m    app.kubernetes.io/instance=docvault,app.kubernetes.io/name=docvault
service/docvault-postgres   ClusterIP   10.43.31.235   <none>        5432/TCP   107m   <none>

NAME                                       STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   VOLUMEATTRIBUTESCLASS   AGE   VOLUMEMODE
persistentvolumeclaim/docvault-documents   Bound    pvc-71f1be75-fbd6-4b65-b6f1-96e97d0581ac   1Gi        RWO            local-path     <unset>                 79m   Filesystem

NAME                       READY   UP-TO-DATE   AVAILABLE   AGE   CONTAINERS   IMAGES                                                                                             SELECTOR
deployment.apps/docvault   1/1     1            1           79m   docvault     iyedbnaissa/docvault-api@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687   app.kubernetes.io/instance=docvault,app.kubernetes.io/name=docvault
```

### Admission Guardrail Compliance:
The deployed workload strictly adheres to all 18 rules enforced by `ValidatingAdmissionPolicy/docvault-deployer-workload-guardrails` and `ValidatingAdmissionPolicy/docvault-deployer-service-guardrails`:
- Run as non-root (UID 10001, GID 10001).
- Read-only root filesystem (`readOnlyRootFilesystem: true`).
- Dropped capabilities (`capabilities: { drop: ["ALL"] }`).
- Privilege escalation disabled (`allowPrivilegeEscalation: false`).
- Dedicated private persistent volume mounted at `/app/storage/documents`.
- Image provenance locked to digest `@sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687`.
- Single narrow Rule 7 exception: only the exact reference `(docvault-app-db-creds, DATABASE_PASSWORD, database-password)` is permitted; all other Secret references remain rejected.

---

## 7. Application Health and Readiness Results

Probes were conducted against the internal ClusterIP service `http://10.43.16.81:8000`:

| Endpoint | HTTP Method | Expected Status | Observed Status | Response Body | Verification Significance |
|---|---|---|---|---|---|
| `/health` | `GET` | `200 OK` | **200 OK** | `{"status":"healthy"}` | Liveness probe: ASGI container process is responsive. |
| `/ready` | `GET` | `200 OK` | **200 OK** | `{"status":"ready","database":"connected"}` | Readiness probe: live TCP connection and `SELECT 1` handshake with PostgreSQL succeeded. |

---

## 8. Authentication and Authorization Test Results

Authentication tests were performed using dedicated authorized test accounts (`test_probe` and `demo_viewer`):

| Test Scenario | Action / Endpoint | Observed HTTP Status | Details & Observations |
|---|---|---|---|
| **1. Unauthenticated Profile Access** | `GET /api/v1/auth/me` (no cookie) | **401 Unauthorized** | Anonymous requests are rejected by authentication dependency. |
| **2. Login with Authorized Account** | `POST /api/v1/auth/login` | **200 OK** | Validated password via Argon2id; returned user profile JSON and issued `docvault_session` cookie + `docvault_csrf` cookie. |
| **3. Authenticated Profile Access** | `GET /api/v1/auth/me` (with cookie) | **200 OK** | Returned profile payload for user `test_probe`. |
| **4. Explicit Logout** | `POST /api/v1/auth/logout` (with CSRF header) | **204 No Content** | Server-side session store invalidated the session ID. |
| **5. Post-Logout Invalidation** | `GET /api/v1/auth/me` (old session cookie) | **401 Unauthorized** | Expired/cleared session cannot be reused. |
| **6. Cross-User Document Isolation** | `GET /api/v1/documents/{doc_id}` by `demo_viewer` for document owned by `test_probe` | **404 Not Found** | Server denies access to unauthorized users without disclosing document existence. |

---

## 9. Document Upload / Download Integrity Results

Document lifecycle integrity was verified using authoritative test fixture `backend/tests/fixtures/minimal_valid.pdf`:

1. **Document Upload:**
   - Endpoint: `POST /api/v1/documents`
   - Content: Valid PDF structure (1,234 bytes).
   - Status: **201 Created**.
   - Server Response: Returned unique UUID `id`, filename `d9_test_lifecycle.pdf`, and content type `application/pdf`.
2. **Metadata Inspection:**
   - Endpoint: `GET /api/v1/documents/{doc_id}`
   - Status: **200 OK**.
   - Properties: Correct size, owner ID matching `test_probe`, and timestamp recorded.
3. **Document Download & SHA-256 Byte Verification:**
   - Endpoint: `GET /api/v1/documents/{doc_id}/download`
   - Status: **200 OK**.
   - Expected SHA-256 Digest: `47b21aaed0c5fc1a4e4a4e5f9a8083fdf17247baf780155d08b6163b76a67fc2`
   - Downloaded SHA-256 Digest: `47b21aaed0c5fc1a4e4a4e5f9a8083fdf17247baf780155d08b6163b76a67fc2`
   - **Verification:** Digests match byte-for-byte; zero data corruption or truncation.
4. **Document Deletion:**
   - Endpoint: `DELETE /api/v1/documents/{doc_id}`
   - Status: **204 No Content**.
   - Subsequent `GET`: Returns **404 Not Found**; storage artifact removed.

---

## 10. Persistence Verification Across Pod Restart

A critical operational requirement is document persistence across Pod failures or rollouts without reliance on Pod-local ephemeral storage:

```
[Upload Document] ──> [Record SHA-256] ──> [kubectl rollout restart] ──> [Replacement Pod 1/1] ──> [Download Document] ──> [SHA-256 Match]
```

### Execution Steps & Empirical Evidence:
1. Uploaded dedicated persistence test file `d9_test_persistence.pdf` with recorded SHA-256 `47b21aaed0c5fc1a4e4a4e5f9a8083fdf17247baf780155d08b6163b76a67fc2`.
2. Executed controlled rollout restart:
   ```bash
   kubectl rollout restart deployment/docvault -n docvault
   kubectl rollout status deployment/docvault -n docvault --timeout=60s
   ```
3. Old Pod terminated cleanly; replacement Pod `docvault-5f67455bd8-r2vkc` achieved `1/1 Running`.
4. Verified `/health` and `/ready` returned HTTP 200 OK on replacement Pod.
5. Re-authenticated and downloaded `d9_test_persistence.pdf` from the replacement Pod:
   - Retrieved byte digest: `47b21aaed0c5fc1a4e4a4e5f9a8083fdf17247baf780155d08b6163b76a67fc2`.
   - Result: **MATCH (100% Data Integrity Preserved across Pod restart)**.
6. Deleted test document cleanly.

---

## 11. Repeatable Deployment Verification

To guarantee that the Jenkins CD pipeline is deterministic and repeatable, the pipeline was triggered a second time (Build #8) using identical inputs without rebuilding the container image:

### Build #8 Comparison:
- **Target Commit:** `14178f7dc0ff89fe16cd72bdbbe38cb90c838612` (Unchanged)
- **Image Digest:** `sha256:05a3d9053c7250448b760e02f92422bb32c8a6b465c9222b858bfc8eb1ccd687` (Unchanged)
- **Helm Driver:** `configmap`
- **Helm Release History:**
  ```text
  REVISION  UPDATED                   STATUS      CHART           APP VERSION  DESCRIPTION     
  1         Sat Nov 14 15:25:08 2026  superseded  docvault-0.1.0  1.0.0        Install complete
  2         Sat Nov 14 16:33:13 2026  superseded  docvault-0.1.0  1.0.0        Upgrade complete (Build #7)
  3         Sat Nov 14 16:36:34 2026  deployed    docvault-0.1.0  1.0.0        Upgrade complete (Build #8)
  ```
- **Live Pod Health:** Deployment rollout succeeded cleanly with zero downtime. Replicas remained 1/1, `/health` and `/ready` returned HTTP 200 OK, and persistent volume attachments were preserved.

---

## 12. Automated Test Suite Results

All verification tests are codified in `backend/tests/test_d9_deployment_verification.py`. The suite was executed alongside the existing Phase D test suites:

```text
$ .venv/bin/pytest backend/tests/test_d8_3_admission_rbac.py \
                   backend/tests/test_d8_4_delivery_foundation.py \
                   backend/tests/test_d8_5_helm_deployment.py \
                   backend/tests/test_d8_6_registry_database_integration.py \
                   backend/tests/test_d9_deployment_verification.py -v

============================= 97 passed in 25.72s ==============================
```

### Breakdown of Test Coverage:
- `test_d8_3_admission_rbac.py`: 46 passed (admission policy schemas, preflight, positive/negative admission guardrails).
- `test_d8_4_delivery_foundation.py`: 17 passed (Jenkins credentials, K3s TLS auth, namespace isolation, CI check logic).
- `test_d8_5_helm_deployment.py`: 9 passed (Helm chart structure, templates, dry-run admission, zero-Secret chart).
- `test_d8_6_registry_database_integration.py`: 12 passed (Docker Hub image pull, PostgreSQL ClusterIP handshake, Alembic migration job, narrow Rule 7 exception).
- `test_d9_deployment_verification.py`: 13 passed (Jenkins pipeline structure, build execution history, live Helm status, health/ready probes, authentication lifecycle, document integrity, access control, persistence across restart, repeatable deployment).

---

## 13. Operational Distinction & Boundaries

To preserve architectural clarity and audit transparency:

| Category | Components / Operations Included |
|---|---|
| **Automated Jenkins Pipeline Execution** | Stages 1 through 8 executed inside `docvault-jenkins` by job `docvault-delivery-pipeline` (Builds 7 and 8). Queries GitHub APIs, verifies CI checks, extracts image digest, authenticates to K3s, and runs `helm upgrade`. |
| **Manual Administrator Operations** | Out-of-band privileged setup (D8.2 Docker Compose controller setup, D8.3 K3s preflight, D8.6 Docker Hub credentials, PostgreSQL ClusterIP service, initial Alembic migration job, and narrow Rule 7 admission policy update). |
| **Manual Smoke Tests** | Initial curl probes over SSH tunnel verifying Jenkins login HTTP 200 and K3s Node status. |
| **Automated Application Tests** | Automated test suite (`test_d9_deployment_verification.py`) validating live application behavior, authentication cookies, CSRF tokens, upload/download SHA-256 integrity, tenant isolation, and restart survival. |

---

## 14. Unresolved Limitations & Non-Production Invariants

In accordance with project guidelines, this deployment is an academic demonstration and is **not production-ready**:

1. **Single-Node K3s Runtime:** K3s runs as a single-node server with a single control plane and worker process. High availability, multi-zone replication, and etcd clustering are out of scope.
2. **Local-Path Storage Provisioner:** Document persistence utilizes K3s default `local-path` storage on host path `/var/lib/rancher/k3s/storage`. Volume replication across multiple physical nodes is not configured.
3. **Loopback-Bound Jenkins Controller:** The Jenkins controller is bound strictly to `127.0.0.1:8080` with zero public or LAN routing. Automated webhook triggers from GitHub are not possible without an ingress or secure relay; pipeline builds are triggered via API or scheduled polling.
4. **Host Network Flannel Bridge for PostgreSQL:** PostgreSQL runs inside Docker Compose on `docvault_database` and is routed into K3s via an administrator-managed ClusterIP Service + Endpoints pointing to host bridge IP `172.18.0.2`. In production, a cloud-managed database (e.g., AWS RDS / Cloud SQL) or dedicated Kubernetes operator (e.g., CloudNativePG) with mutual TLS would be required.
5. **Academic Vulnerability Invariant:** Passing CI security gates and DAST baseline scans does not imply zero vulnerabilities or absolute security; it demonstrates compliance with the project's defined security baseline and automated admission policies.
