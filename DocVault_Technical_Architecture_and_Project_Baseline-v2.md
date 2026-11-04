# DocVault — Secure Document Management Platform
## Technical Architecture and Project Baseline

**Version:** 2.0  
**Date:** 4 November 2026  
**Project type:** Individual academic DevSecOps project (subject to instructor approval)  
**Source control:** GitHub  
**CI/CD:** Jenkins LTS  
**Deployment:** VirtualBox Ubuntu Server 26.04 LTS  
**Administration:** MobaXterm over SSH  
**Hardware constraint:** Windows 11 host with 16 GB RAM

---

# 1. Executive Summary

DocVault is a secure document management platform designed to demonstrate the integration of application security and DevSecOps practices throughout the software development lifecycle.

The platform will provide authenticated document upload, storage, retrieval, controlled sharing, role-based access control, and security audit logging.

The proposed architecture consists of:

- FastAPI backend.
- Lightweight HTML, CSS, Bootstrap and JavaScript frontend.
- PostgreSQL database.
- Docker and Docker Compose.
- GitHub for source control.
- Jenkins LTS for CI/CD.
- Semgrep CE for SAST.
- Gitleaks for secret detection.
- Grype for vulnerability scanning.
- Syft for SBOM generation.
- Checkov for infrastructure configuration scanning.
- ZAP by Checkmarx for DAST.
- Minikube and Calico for local Kubernetes deployment and network segmentation.
- Helm 4 for application deployment, subject to compatibility verification.

The project will run on an Ubuntu Server virtual machine hosted by VirtualBox on a Windows 11 computer. **MobaXterm will be used as the primary SSH administration client**.

Jenkins will be accessible through an SSH local port-forwarding tunnel rather than being exposed directly to the local network.

Trivy is intentionally excluded from this architecture. Grype, Syft and Checkov will cover the selected vulnerability-scanning, SBOM and configuration-scanning requirements.

> **Approval requirement:** The original course specification describes a team project and identifies GitLab CI as the default CI/CD option, with alternatives subject to approval. The individual-project format and use of GitHub and Jenkins must be approved by the instructor.

# 2. Project Objectives

1. Design and implement a secure document management web application.
2. Enforce authentication, authorization, role separation and controlled document sharing.
3. Record security-relevant application events.
4. Implement a repeatable CI/CD pipeline using GitHub and Jenkins.
5. Integrate source-code, secret, dependency, container-image and infrastructure-configuration security checks.
6. Package the application and database as containers.
7. Deploy the application to local Kubernetes using Helm.
8. Apply Kubernetes workload hardening and network segmentation.
9. Demonstrate controlled vulnerabilities, exploitation in an isolated lab, remediation and retesting.
10. Collect reproducible evidence for the technical report and final demonstration.

# 3. Project Scope

## 3.1 In scope

- User authentication and session management.
- User and administrator roles.
- Document upload, listing, download and deletion.
- Controlled document sharing.
- Server-side ownership and permission checks.
- File validation and upload-size limits.
- Secure document storage outside the public web root.
- Security audit logging.
- Automated application tests.
- Jenkins CI/CD pipeline.
- SAST, secret, vulnerability and configuration scanning.
- Docker image creation and scanning.
- Local Kubernetes deployment through a custom Helm chart.
- Kubernetes NetworkPolicies and workload hardening.
- DAST and authenticated authorization testing.
- Documentation, scan reports and demonstration evidence.

## 3.2 Out of scope for the initial release

- Public cloud deployment or paid cloud services.
- Multi-region or high-availability infrastructure.
- Enterprise identity federation or SSO.
- Service mesh.
- Dedicated secrets-management platform such as Vault.
- ClamAV unless specifically required by the instructor.
- Prometheus, Grafana and Loki during initial implementation.

Optional services may be introduced only after the core platform and security pipeline are working.

# 4. Functional Application Design

## 4.1 Roles

**User**
- Authenticate and manage their session.
- Upload and view their own documents.
- Download or delete documents they own, subject to application policy.
- Share documents with other authorized users where implemented.
- Access documents shared with them.

**Administrator**
- Perform explicitly authorized administrative operations.
- Manage users or account status where included.
- Review security audit events.
- Have administrative actions recorded in audit logs.

## 4.2 Application security requirements

- Enforce authorization on the server for every document operation.
- Never trust document IDs, owner IDs, roles or permissions supplied by the browser.
- Use parameterized database access through the ORM.
- Validate file extension, MIME type, magic bytes and maximum file size.
- Generate random server-side storage filenames.
- Store uploads outside the public web root.
- Implement login throttling.
- Apply CSRF protection when using cookie-based authentication.
- Configure security headers and Content Security Policy.
- Avoid logging passwords, tokens and document contents.
- Pin application dependencies.
- Use a non-superuser PostgreSQL account for normal application access.

## 4.3 Authentication

Use server-side sessions or short-lived tokens stored in appropriately protected `HttpOnly`, `Secure` and `SameSite` cookies.

Do not store authentication tokens in `localStorage`, particularly because the project includes a stored-XSS test scenario.

Use Argon2id for password hashing. Rotate session identifiers after authentication and invalidate sessions on logout.

# 5. Technology Stack

| Layer | Selected technology | Purpose |
|---|---|---|
| Host OS | Windows 11 | Physical host |
| Virtualization | VirtualBox 7.2.10+ | Linux VM |
| VM administration | MobaXterm | SSH terminal and port forwarding |
| Guest OS | Ubuntu Server 26.04 LTS | Project server |
| Source control | GitHub | Repository and version control |
| Backend | Python + FastAPI | REST API |
| Frontend | HTML, CSS, Bootstrap, JavaScript | Web interface |
| Database | PostgreSQL | Application data |
| ORM | SQLAlchemy | Database access |
| Containers | Docker Engine + Compose | Containerization |
| CI/CD | Jenkins LTS | Pipeline orchestration |
| SAST | Semgrep CE | Source-code analysis |
| Secret scanning | Gitleaks | Secret detection |
| Vulnerability scanning | Grype | Dependency and image scanning |
| SBOM | Syft | Software Bill of Materials |
| IaC scanning | Checkov | Dockerfile, Kubernetes and Helm configuration |
| DAST | ZAP by Checkmarx | Dynamic application testing |
| Kubernetes | Minikube | Local cluster |
| CNI | Calico | NetworkPolicy enforcement |
| Deployment | Helm 4 | Kubernetes packaging |
| Registry | Local Docker registry | Store application images |
| Evidence | Jenkins artifacts and Kubernetes logs | Project verification |

All selected tools should be checked for their current release, licensing and installation requirements before use. Do not assume every hosted or commercial feature is free.

Official references:

- GitHub: https://github.com/
- Jenkins: https://www.jenkins.io/
- FastAPI: https://fastapi.tiangolo.com/
- Docker: https://docs.docker.com/
- Semgrep: https://github.com/semgrep/semgrep
- Gitleaks: https://github.com/gitleaks/gitleaks
- Grype: https://github.com/anchore/grype
- Syft: https://github.com/anchore/syft
- Checkov: https://github.com/bridgecrewio/checkov
- ZAP: https://www.zaproxy.org/
- Minikube: https://minikube.sigs.k8s.io/
- Calico: https://docs.tigera.io/calico/latest/
- Helm: https://helm.sh/

# 6. Host and Virtual Machine Architecture

## 6.1 Hardware constraints

- Windows 11 host.
- 16 GB physical RAM.
- VirtualBox running one Ubuntu Server VM.
- Resource-intensive operations executed sequentially.

## 6.2 Initial VM allocation

| Resource | Allocation |
|---|---:|
| RAM | 8 GB |
| vCPU | 4, provided sufficient host logical cores are available |
| Virtual disk | 100 GB dynamically allocated |
| Network | NAT |
| Guest OS | Ubuntu Server 26.04 LTS |
| Administration | MobaXterm over SSH |

These values are starting allocations. Measure resource use and adjust if Windows becomes unstable.

## 6.3 MobaXterm SSH connection

MobaXterm will be the primary administration tool from Windows.

Configure a VirtualBox NAT port-forwarding rule:

| Setting | Value |
|---|---|
| Name | SSH-MobaXterm |
| Protocol | TCP |
| Host IP | `127.0.0.1` |
| Host Port | `2222` |
| Guest IP | Leave blank for dynamically assigned NAT address |
| Guest Port | `22` |

Binding the host IP to `127.0.0.1` prevents the forwarded SSH service from being exposed to the local network.

### MobaXterm configuration

1. Start the Ubuntu VM.
2. Verify that OpenSSH Server is installed and running.
3. Open MobaXterm on Windows.
4. Select **Session → SSH**.
5. Enter `127.0.0.1` as the remote host.
6. Enable **Specify username** and enter the Ubuntu username.
7. Open **Advanced SSH settings**.
8. Set the SSH port to `2222`.
9. Configure a private key if using SSH key authentication.
10. Save the session as `DocVault-Ubuntu-VM`.
11. Connect and verify the terminal session.

Equivalent Windows PowerShell command:

```powershell
ssh -p 2222 your_ubuntu_username@127.0.0.1
```

Replace `your_ubuntu_username` with the actual Linux account name.

### SSH hardening

- Prefer SSH key authentication after verifying key access.
- Protect private keys with a passphrase.
- Disable direct root SSH login.
- Keep Ubuntu and OpenSSH updated.
- Do not expose SSH to the public internet.
- Maintain a recovery path before disabling password authentication.

## 6.4 Jenkins access through MobaXterm

Jenkins should listen only on the Ubuntu VM loopback interface:

```text
127.0.0.1
```

Use MobaXterm's SSH tunneling feature to access it.

| Tunnel setting | Value |
|---|---|
| Forwarding type | Local port forwarding |
| Local port | `8080` |
| Remote server | `127.0.0.1` |
| Remote port | `8080` |
| SSH gateway | `127.0.0.1` |
| SSH port | `2222` |
| SSH username | Ubuntu username |

Keep the SSH tunnel active, then open this URL in the Windows browser:

```text
http://127.0.0.1:8080
```

This forwards the browser connection securely through SSH to Jenkins inside the VM.

Do not create a VirtualBox port-forwarding rule for Jenkins if the SSH tunnel is being used.

If port 8080 is occupied on Windows, use another local port such as 18080 and open:

```text
http://127.0.0.1:18080
```

## 6.5 Application access

Use SSH tunnels or `kubectl port-forward` for local application access where appropriate.

Avoid exposing Jenkins, PostgreSQL, the registry or internal administration services to the LAN or public internet.

# 7. Resource Management

The 16 GB host requires careful resource management.

Indicative estimates, not measured guarantees:

| Component | Approximate RAM |
|---|---:|
| Ubuntu Server and SSH | 0.4–0.6 GB |
| Jenkins controller | 0.9–1.2 GB |
| Jenkins agent JVM | 0.15–0.25 GB |
| Docker daemon and runtime | 0.2–0.3 GB |
| Minikube and cluster services | 1.6–2.2 GB |
| DocVault and PostgreSQL pods | 0.3–0.5 GB |
| Local registry | Less than 0.05 GB |

Run one heavy scanner or build stage at a time.

Defer Prometheus, Grafana and Loki. Initially use structured application logs, Kubernetes logs and archived Jenkins reports.

Capture the following during a full pipeline run:

```bash
free -h
docker stats
kubectl top nodes
kubectl top pods -A
```

Include the actual measurements in the final report.

# 8. GitHub Repository Structure

Proposed repository:

```text
DocVault/
├── app/
│   ├── api/
│   ├── core/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── security/
│   └── main.py
├── frontend/
│   ├── static/
│   └── templates/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── authorization/
├── database/
│   └── migrations/
├── docker/
│   └── Dockerfile
├── helm/
│   ├── docvault/
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   ├── values-dev.yaml
│   │   └── templates/
│   └── postgres/
├── security/
│   ├── semgrep/
│   ├── gitleaks/
│   ├── checkov/
│   ├── grype/
│   └── zap/
├── scripts/
├── docs/
├── reports/
├── .github/
│   └── workflows/
├── .gitignore
├── Jenkinsfile
├── compose.yaml
├── pyproject.toml
└── README.md
```

Jenkins remains the primary CI/CD engine. GitHub Actions may be added for lightweight repository checks, but it is not required for the initial architecture.

Never commit real credentials, `.env` files containing secrets, private keys or unredacted reports.

# 9. Development and Containerization

Use Docker Compose for local application development.

The initial environment should include:

- FastAPI application.
- PostgreSQL.
- Persistent database storage.
- Environment-based application configuration.
- Health checks.
- Database readiness checks.

The application container should:

- Use a minimal maintained base image.
- Run as a non-root user.
- Avoid unnecessary packages.
- Use a read-only root filesystem where practical.
- Drop unnecessary Linux capabilities.
- Disallow privilege escalation.
- Avoid embedding credentials in image layers.
- Use pinned base-image digests where practical.

Docker socket access effectively grants extensive control over the Docker host. Restrict Docker access to the dedicated Jenkins build agent and document the residual risk.

Never mount the Docker socket into scanner containers.

# 10. Jenkins CI/CD Architecture

## 10.1 GitHub integration

GitHub is the canonical source repository.

Recommended practices:

- Protect the main branch.
- Use feature branches.
- Require tests before merging where practical.
- Do not execute untrusted fork pull-request Jenkinsfiles with privileged credentials.
- Use dedicated Jenkins credentials for repository access.
- Record the commit SHA used for each deployment.

## 10.2 Jenkins controller

- Runs pipeline orchestration.
- Uses zero build executors.
- Is not a member of the Docker group.
- Listens only on `127.0.0.1`.
- Is accessed through MobaXterm SSH forwarding.

## 10.3 Jenkins build agent

- Runs as a dedicated Linux user.
- Uses one executor.
- Has the required build and scanner tools.
- Has Docker access only for required image operations.
- Receives credentials only for the stage that needs them.

The agent may run on the same VM for this constrained academic lab, but should remain a separate process and user identity.

This does not provide the same isolation as a separate physical machine. Restrict builds to trusted branches.

## 10.4 GitHub connectivity

A VirtualBox NAT VM generally cannot receive inbound GitHub webhooks directly.

Start with:

- Jenkins SCM polling, or
- Manual pipeline triggers.

If webhooks are introduced later, use a secured relay or deliberately configured reachable endpoint. Do not expose Jenkins casually.

## 10.5 Pipeline stages

1. Checkout from GitHub.
2. Install locked dependencies and run tests.
3. Semgrep SAST.
4. Gitleaks secret scanning.
5. Grype filesystem/dependency scanning.
6. Checkov Dockerfile and Helm/Kubernetes scanning.
7. Build Docker image.
8. Syft SBOM generation.
9. Grype image scanning.
10. Apply security quality gates.
11. Push image to local registry.
12. Deploy using Helm and restricted Kubernetes credentials.
13. Application smoke tests.
14. ZAP DAST and authenticated authorization tests.
15. Archive reports, SBOM, test results and deployment metadata.

Pin scanner versions and verify checksums or signatures where supported. Avoid mutable `latest` tags.

## 10.6 Initial security gate policy

- Unit tests must pass.
- Gitleaks must not detect an unapproved secret.
- Semgrep findings must be reviewed.
- Grype should fail on HIGH or CRITICAL vulnerabilities with available fixes, subject to documented exceptions.
- Checkov findings must be reviewed.
- Exceptions must identify the finding, reason, owner, compensating control and review/expiry date.

Do not silently suppress findings to obtain a green build.

# 11. Security Tool Responsibilities

## 11.1 Semgrep CE

Perform static source-code security analysis.

Use a pinned release and version-controlled ruleset. Add a small number of project-specific rules if feasible.

Do not assume Semgrep CE detects every cross-file authorization flaw. Explicit authorization tests are required.

## 11.2 Gitleaks

Scan the working tree and Git history.

Use only dummy credentials in controlled tests. Demonstrate detection, removal and credential-rotation procedures.

## 11.3 Grype

Use Grype for:

- Application dependency/filesystem vulnerability scanning.
- Container-image vulnerability scanning.
- SBOM-based vulnerability analysis.

Archive JSON reports and human-readable evidence.

Example image archive workflow:

```bash
docker save -o docvault-image.tar docvault:build

grype docker-archive:docvault-image.tar \
  -o json > grype-report.json
```

## 11.4 Syft

Generate a CycloneDX or SPDX SBOM for the built application image.

Example:

```bash
syft docker-archive:docvault-image.tar \
  -o cyclonedx-json=docvault-sbom.json
```

Archive the SBOM with the commit SHA, image digest and Jenkins build number.

An SBOM provides software inventory and traceability. It does not itself prove that an image is secure.

## 11.5 Checkov

Scan:

- Dockerfiles.
- Kubernetes manifests.
- Helm charts and values.
- Other supported infrastructure configuration.

Checkov findings must be reviewed. A clean scan does not replace runtime verification.

## 11.6 ZAP by Checkmarx

Use ZAP for dynamic web application testing.

Prefer the Automation Framework for repeatable authenticated scans.

Configure test accounts and authentication context where appropriate.

ZAP does not reliably discover every IDOR or business-logic flaw automatically. Use explicit multi-user integration tests to prove that one user cannot access another user's documents.

Reset the test database before active scans if scan traffic can modify application data.

# 12. Kubernetes and Helm

## 12.1 Minikube configuration

Use Minikube with the Docker driver.

Initial resource-conscious configuration:

```bash
minikube start \
  --driver=docker \
  --cpus=2 \
  --memory=3072 \
  --disk-size=25g \
  --cni=calico
```

Pin a Kubernetes version supported by the selected Minikube and Calico releases.

Verify compatibility before installation.

## 12.2 Calico enforcement acceptance test

Do not assume NetworkPolicy works merely because Calico pods are running.

The cluster passes only when:

1. An in-cluster test workload can communicate before restrictions are applied.
2. A deny policy demonstrably blocks selected traffic.
3. An allow policy permits only intended traffic.
4. DNS remains functional where required.
5. The test is performed from in-cluster pods, not inferred from host-side `kubectl port-forward`.

If Calico does not work reliably with the selected Minikube configuration, evaluate kind with a supported CNI or another supported Minikube CNI. Record the actual tested environment.

## 12.3 Namespace and network policies

Create the `docvault` namespace as an administrative setup step.

Apply Pod Security Admission `restricted` enforcement where workloads meet the requirements.

Use:

- Default-deny ingress and egress.
- Explicit DNS allowances.
- App-to-PostgreSQL ingress only.
- PostgreSQL egress restrictions.
- Explicitly permitted application ingress.

Test policy behavior from inside the cluster.

## 12.4 Helm chart structure

Maintain a custom chart in GitHub.

The application chart should include:

- Deployment.
- Service.
- ConfigMap.
- References to pre-created Secrets.
- PersistentVolumeClaim where required.
- ServiceAccount.
- NetworkPolicy.
- Pod and container security contexts.
- Resource requests and limits.
- Readiness and liveness probes.
- Helpers and environment-specific values.

Deploy PostgreSQL as a separate release or subchart with an independent lifecycle.

Use `NodePort` or `kubectl port-forward` for the local demonstration.

Do not add an Ingress controller unless there is a demonstrated requirement and the selected controller is actively maintained.

## 12.5 Kubernetes deployment identity

Do not give Jenkins the Minikube administrator kubeconfig.

Create a dedicated ServiceAccount, Role and RoleBinding for Jenkins deployment.

The identity must have only the permissions needed to manage DocVault resources in the `docvault` namespace.

Verify permissions using:

```bash
kubectl auth can-i --list \
  --namespace docvault
```

Avoid `cluster-admin`.

Create the namespace before the Jenkins deployment stage. Do not use `--create-namespace` with a namespace-scoped Jenkins identity.

## 12.6 Example deployment

```bash
helm upgrade --install docvault ./helm/docvault \
  --namespace docvault \
  -f ./helm/docvault/values-dev.yaml
```

Use the exact flags supported by the pinned Helm release.

# 13. Secrets Management

Do not put real secrets in:

- GitHub.
- Helm values files.
- Helm templates with literal credentials.
- Dockerfiles or image layers.
- Jenkinsfiles.
- Scan reports or console output.

Create Kubernetes Secrets out of band using Jenkins credentials or a controlled administrative process.

The Helm chart should reference an existing Secret rather than render secret values into the Helm release.

Important limitations:

- Kubernetes Secret values are base64-encoded, not encrypted merely by being encoded.
- Kubernetes Secrets are not encrypted in etcd by default unless encryption at rest is configured.
- Restrict access through RBAC.
- Inject Jenkins credentials only into stages that require them.
- Use dummy credentials in documentation and examples.

Document residual risks if encryption at rest is not configured.

# 14. Container and Kubernetes Hardening

Apply where compatible with the selected images:

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

Also implement where practical:

- Read-only root filesystem.
- Explicit writable `emptyDir` mounts.
- Dedicated ServiceAccounts.
- `automountServiceAccountToken: false` when API access is unnecessary.
- Digest-pinned images.
- Resource requests and limits.
- Readiness and liveness probes.
- Pod Security Admission restricted enforcement.
- ResourceQuota and LimitRange where useful.
- Separate PostgreSQL application and migration roles.
- Persistent-storage permission testing.

Some database images require specific writable paths or permissions. Test hardening settings rather than applying them blindly.

# 15. Controlled Vulnerability Scenarios

Implement at least four controlled scenarios across at least three categories, subject to the course specification.

| Scenario | Category | Demonstration | Remediation |
|---|---|---|---|
| IDOR in document access | Broken access control | User A attempts to access User B's document by changing an identifier | Server-side ownership/sharing checks and multi-user tests |
| Unsafe file upload | File validation | Upload a prohibited file type or misleading extension | Validate size, extension, MIME and magic bytes; random storage names |
| Stored XSS | Injection | Submit a harmless script payload in a controlled text field | Context-aware output encoding, safe templates and CSP |
| Exposed dummy secret | Secrets management | Place a fake credential in a controlled test fixture or branch | Gitleaks detection, removal and credential rotation |

At least two scenarios should be dynamically confirmed, remediated and retested if required by the course specification.

Use only dummy data, test accounts and the isolated lab.

# 16. Audit Logging and Incident Response

Record security-relevant events:

- Successful and failed authentication.
- Login throttling or account lockout.
- Document upload, download, deletion and sharing.
- Authorization failures.
- Administrative actions.
- Upload validation failures.
- Relevant application errors.

Use structured logs containing timestamps, event types, actor identifiers and relevant object identifiers.

Never log passwords, tokens or document contents.

Demonstrate an incident workflow:

1. Detect the event.
2. Identify the affected user/resource and time window.
3. Contain the test issue.
4. Preserve relevant logs and pipeline evidence.
5. Remediate the cause.
6. Retest and record the outcome.

Audit logs in the same database as application data are not inherently tamper-proof. Document this limitation and restrict modification privileges.

# 17. Testing and Acceptance Criteria

## Application

- Authentication works.
- Users can perform permitted document operations.
- Unauthorized cross-user access is rejected server-side.
- Upload validation rejects prohibited test files.
- Passwords are hashed securely.
- Sessions are invalidated on logout.
- Security events are logged without exposing secrets.

## CI/CD

- Jenkins checks out the correct GitHub commit.
- Automated tests execute and publish results.
- Semgrep and Gitleaks run successfully.
- Grype scans dependencies and the built image.
- Syft generates an SBOM.
- Checkov scans relevant configuration.
- Security gates and exceptions behave as intended.
- Reports are archived with commit and build metadata.

## Kubernetes

- DocVault and PostgreSQL deploy successfully.
- Workloads use hardened security contexts where supported.
- Jenkins deploys with namespace-scoped credentials.
- NetworkPolicies are demonstrably enforced.
- Persistent data behaves correctly after pod restart.
- Application access works through the selected local forwarding method.

## DAST and vulnerability remediation

- ZAP scans the isolated deployment.
- Authenticated testing is configured where appropriate.
- IDOR is verified with explicit multi-user tests.
- Four controlled vulnerability scenarios are documented.
- At least two scenarios are dynamically confirmed, remediated and retested if required.
- Before/after evidence is archived.

## Evidence

- Architecture diagram.
- GitHub repository and commit references.
- Jenkins pipeline reports.
- Unit and integration test results.
- Semgrep, Gitleaks, Grype, Checkov and ZAP reports.
- SBOM artifact.
- Kubernetes deployment and NetworkPolicy test outputs.
- Resource measurements.
- Vulnerability reproduction and remediation evidence.

# 18. Implementation Roadmap

## Phase 0 — Approval and environment

- Obtain instructor approval for individual scope and GitHub/Jenkins choices.
- Install VirtualBox.
- Create Ubuntu Server 26.04 VM.
- Configure NAT SSH forwarding.
- Connect through MobaXterm.
- Update Ubuntu and harden SSH.

## Phase 1 — Core application

- Create GitHub repository.
- Implement FastAPI backend and frontend.
- Implement PostgreSQL models and migrations.
- Implement authentication, roles, document operations, sharing and audit events.
- Add unit and authorization tests.

## Phase 2 — Local containers

- Create Dockerfile and Compose configuration.
- Run the application and PostgreSQL locally.
- Apply non-root container settings.
- Verify persistence and health checks.

## Phase 3 — Jenkins and security tools

- Install Jenkins LTS and the Java version required by the selected Jenkins release.
- Configure controller/agent separation.
- Connect Jenkins to GitHub.
- Add Semgrep, Gitleaks, Grype, Syft, Checkov and test stages.
- Archive reports and implement initial security gates.

## Phase 4 — Kubernetes

- Install Minikube, kubectl, Calico and Helm.
- Verify NetworkPolicy enforcement.
- Create namespace, RBAC and out-of-band Secrets.
- Create and test the custom Helm chart.
- Deploy the application and PostgreSQL with independent lifecycles.

## Phase 5 — DAST and remediation

- Configure ZAP Automation Framework.
- Execute controlled vulnerability scenarios.
- Add multi-user authorization tests.
- Remediate and retest.
- Archive before/after evidence.

## Phase 6 — Final report and demonstration

- Measure resource use.
- Capture pipeline, scanning, deployment and policy evidence.
- Document limitations and residual risks.
- Prepare the final report and demonstration.

# 19. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| 16 GB host memory pressure | 8 GB VM starting allocation, one executor, sequential scans |
| Jenkins agent has Docker privileges | Dedicated agent user, trusted branches and restricted credentials |
| GitHub webhook cannot reach NAT VM | Use SCM polling or manual triggers |
| Scanner supply-chain compromise | Exclude Trivy; pin and verify Grype, Syft and other scanner artifacts |
| Calico not enforcing policies | Mandatory in-cluster enforcement test |
| Secrets leak through Helm | Create Kubernetes Secrets out of band |
| Kubernetes admin credentials leak | Namespace-scoped Jenkins identity |
| Scanner misses business-logic flaws | Explicit authorization tests and manual validation |
| Local registry lacks production protections | Restrict to localhost and document TLS/signing limitations |
| Disk growth | Monitor images, caches, reports and Jenkins workspaces |
| Individual scope rejected | Obtain instructor approval before significant implementation |

# 20. Decisions to Verify Before Implementation

1. Instructor approval for individual project scope.
2. Instructor approval for Jenkins as CI/CD and GitHub as source control.
3. Current Ubuntu Server 26.04 support status for selected VirtualBox, Docker, Jenkins, Minikube, Calico and Helm releases.
4. Compatible Kubernetes and Calico version pair.
5. Current stable versions and artifact verification procedures for Semgrep, Gitleaks, Grype, Syft, Checkov and ZAP.
6. Whether the course requires specific vulnerability categories or evidence formats beyond those listed.
7. Whether a local registry is sufficient for the demonstration.

Do not present an unverified compatibility assumption as a confirmed vendor support statement. Record the exact versions installed and tested.

# 21. Final Architecture Summary

```text
Windows 11 host (16 GB RAM)
└── VirtualBox
    └── Ubuntu Server 26.04 VM
        ├── OpenSSH
        │   └── MobaXterm on Windows
        │       ├── SSH: 127.0.0.1:2222 → VM:22
        │       └── SSH tunnel: localhost:8080 → VM localhost:8080 (Jenkins)
        │
        ├── Docker Engine + Compose
        │   ├── Local registry
        │   └── Jenkins LTS
        │       ├── Controller: 0 executors, localhost-only
        │       └── Dedicated build agent: 1 executor
        │           ├── GitHub checkout
        │           ├── Automated tests
        │           ├── Semgrep
        │           ├── Gitleaks
        │           ├── Grype
        │           ├── Syft
        │           ├── Checkov
        │           └── ZAP
        │
        └── Minikube (Docker driver)
            └── Calico (NetworkPolicy enforcement verified)
                └── docvault namespace
                    ├── DocVault application release (Helm)
                    └── PostgreSQL release (separate lifecycle)

Evidence:
- Jenkins archived reports
- SBOM
- Test results
- Kubernetes logs and policy test results
- Vulnerability before/after evidence
- Resource measurements
```

**Architecture status:** Proposed baseline for implementation. Final software versions, compatibility and security settings must be verified against official documentation at installation time.