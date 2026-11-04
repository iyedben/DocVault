# DocVault v2.1 — Changelog and STRIDE Threat Model

Draft of 4 November 2026. Companion to *Technical Architecture and Project Baseline v2.0*. Status: proposed, pending instructor approval.

## Part A — Changelog v2.0 → v2.1

v2.1 closes the gaps found when v2.0 was compared with the course specification (no threat model, incident-response stages, no explicit blocking demo) and fixes technical inconsistencies (Jenkins placement, local registry reachability, gates that could not block).

### A.1 Added

| ID | Section | Addition |
| --- | --- | --- |
| C-01 | New, `docs/` | Threat model deliverable `docs/threat-model.md` (STRIDE plus OWASP Top 10 mapping). Part B below is the first draft. |
| C-02 | §17 Evidence | Deliverables list now includes the 6–10 page PDF security report, the Compose file, the annotated architecture diagram and the one-page contribution sheet. |
| C-03 | §15 | Prepared demo branch `demo/blocked-secret`: commits a dummy secret, Gitleaks fails the build; then rotate, remove, rerun and pass. Archive both console outputs (redacted). |
| C-04 | §18 | Target dates per phase mapped to the spec milestones (dates to be filled in). |
| C-05 | §6.2 | 2–4 GB swap file in the VM to absorb ZAP + Minikube + Jenkins peaks. |
| C-06 | §13 | Residual risk: Helm stores release state in Secrets, so the Jenkins Role needs Secret access in `docvault` and can read the DB Secret. Documented; Role stays namespace-scoped. |

### A.2 Changed

| ID | Section | Change |
| --- | --- | --- |
| C-07 | §1, §19 | Written rationale for excluding Trivy. Instructor request now also covers the tool substitution (Trivy → Grype, Syft, Checkov). |
| C-08 | §10.2, §21 | Jenkins placement (decision D-1): proposed native install of the controller, matching the loopback-only and no-docker-group rules; agent as a dedicated Linux user connecting over WebSocket to localhost. If a container is chosen, publish as `127.0.0.1:8080:8080` and provide a route to the Minikube API. |
| C-09 | §10.5 step 11, §12 | Registry reachable from the cluster: Minikube registry addon or `--insecure-registry`, with `minikube image load` as fallback. `localhost:5000` on the VM is not reachable from pods. |
| C-10 | §11.2 | Exposed-secret procedure reordered: rotate or replace first, then remove from the working tree and history. |
| C-11 | §16 | Incident workflow rewritten to the spec cycle: detect, contain, eradicate, restore, learn. |
| C-12 | §10.6 | Gates made enforceable: Semgrep fails on ERROR severity; Checkov uses explicit hard-fail check lists (severity metadata may need an API key, verify); Grype `--fail-on high --only-fixed` with an exceptions file. |
| C-13 | §4.3 | `Secure` cookie flag configurable per environment (plain HTTP on localhost for test clients), with a self-signed TLS option for the demo. |
| C-14 | §12.4 | Demo access via NodePort rather than `kubectl port-forward`, so ingress NetworkPolicy is actually exercised. |
| C-15 | §11.6 | ZAP runs in a container without the Docker socket, targeting the NodePort URL on the Minikube IP. |
| C-16 | §4.2 | Bootstrap and JavaScript vendored locally so the CSP needs no CDN allowance. |
| C-17 | §12.4 | PostgreSQL deployed from a custom chart using the official `postgres` image; no Bitnami charts or images. |
| C-18 | §12.1 | Verify that `--disk-size` is honored by the Docker driver; pin the Kubernetes version. |
| C-19 | §20 | New verification item: Checkov Helm scanning with Helm 4, with Helm 3 as fallback. |

### A.3 Open decisions

- **D-1** Jenkins controller native vs container (proposed: native).
- **D-2** Helm 4 vs Helm 3, decided after the Checkov and Minikube compatibility test.
- **D-3** Instructor answers needed: individual scope, GitHub and Jenkins, Trivy substitution, required vulnerability categories and evidence format.

## Part B — STRIDE Threat Model (Draft)

### B.1 Scope and method

STRIDE applied per component and per trust boundary, mapped to OWASP Top 10 (2021 numbering; remap if the course uses a newer edition). Risk is a qualitative H/M rating of likelihood and impact in the lab context. All data, users and secrets are fictional; testing targets only the team's own environment.

### B.2 Assets

| ID | Asset | Why it matters |
| --- | --- | --- |
| A1 | Stored documents | Confidentiality and integrity of user files |
| A2 | Metadata, ownership and sharing permissions | Basis of every authorization decision |
| A3 | Credentials and password hashes | Account takeover |
| A4 | Session identifiers | Impersonation |
| A5 | Audit log | Detection, accountability, incident response |
| A6 | CI/CD credentials (GitHub, Jenkins, registry, Kubernetes) | Pipeline and cluster compromise |
| A7 | Container images, SBOMs, scan reports | Supply-chain integrity and evidence |
| A8 | Kubernetes cluster and Secrets | Runtime isolation and secret confidentiality |

### B.3 Trust boundaries

- **TB1** Browser ↔ DocVault application (NodePort).
- **TB2** Application ↔ PostgreSQL.
- **TB3** Application ↔ document storage (PVC).
- **TB4** GitHub ↔ Jenkins.
- **TB5** Jenkins agent ↔ Docker, registry and Kubernetes API.
- **TB6** Windows host ↔ Ubuntu VM (SSH and tunnel).

### B.4 Threat table

| ID | Component (boundary) | STRIDE | Threat (risk) | Mitigation | OWASP | Validation evidence |
| --- | --- | --- | --- | --- | --- | --- |
| T-01 | Login (TB1) | S | Credential stuffing or brute force (H) | Argon2id, login throttling, generic error messages, failed-login audit events | A07 | Throttle test; `auth.failed` events in log |
| T-02 | Session cookie (TB1) | S, I | Session theft or fixation (H) | HttpOnly and SameSite cookies, ID rotation at login, invalidation at logout, no tokens in localStorage | A07 | Cookie attribute check; logout test |
| T-03 | Document read/download (TB1) | I, E | IDOR: user A reads user B's document by changing the ID (H) **\[V1\]** | Server-side ownership and share check on every operation | A01 | Multi-user tests before and after; denied-access log event |
| T-04 | Document delete/share (TB1) | T, E | User alters, deletes or shares another user's document (H) | Same checks; only owners share or revoke | A01 | Authorization tests |
| T-05 | Admin functions (TB1) | E | Privilege escalation to administrator via forged role or parameter (H) | Role taken from server-side session only; admin routes check role; admin actions audited | A01 | Negative tests as a normal user |
| T-06 | Upload (TB1, TB3) | T, E | Prohibited or misleading file (script renamed `.pdf`) stored or served (H) **\[V2\]** | Extension, MIME and magic-byte validation; size limit; random storage names; outside web root; attachment disposition and nosniff | A04, A05 | Crafted-file upload tests; `upload.rejected` log event |
| T-07 | Upload filename (TB3) | T | Path traversal through filename (M) | Client filename never used for storage; random names; no path joins from input | A01 | Traversal-filename test |
| T-08 | Upload and API (TB1) | D | Oversized or repeated uploads exhaust disk or memory (M) | Max size, per-user quota, resource limits, bounded PVC | A04 | Large-file rejection test; limits in manifests |
| T-09 | Document metadata fields (TB1) | T, E | Stored XSS runs in other users' browsers (H) **\[V3\]** | Context-aware output encoding, autoescaped templates, CSP, HttpOnly cookies | A03 | Harmless payload test before and after; ZAP; CSP header check |
| T-10 | State-changing requests (TB1) | T | CSRF forces actions in a victim's session (M) | CSRF tokens, SameSite cookies | A01 | CSRF negative test |
| T-11 | All user and admin actions | R | An actor denies an action and no trail exists (M) | Structured audit events with actor, time, object, outcome; admin actions logged | A09 | Log review per scenario |
| T-12 | Application logs | I | Passwords, tokens or document contents written to logs (M) | Log field allow-list, redaction, no request-body logging | A09 | Search of captured logs for test secrets |
| T-13 | Audit log store (TB2) | T | Audit rows altered or deleted after a compromise (M) | Restricted DB privileges; also emit to container stdout and archive; limitation documented | A09 | Privilege listing; archived logs |
| T-14 | App ↔ database (TB2) | T, I | SQL injection (H) | ORM parameterization, no string-built SQL, Semgrep rules, non-superuser DB account | A03 | Semgrep results; injection test cases |
| T-15 | Database (TB2) | E | Over-privileged DB role lets a compromised app change schema or read everything (M) | Separate application and migration roles, least privilege | A05 | Grants listing in evidence |
| T-16 | Repository, image, Helm values (TB4) | I | Secret committed or baked into an image or chart (H) **\[V4\]** | Gitleaks on tree and history, Secrets created out of band, rotation-first procedure, `.dockerignore` | A05 | Pipeline fails on dummy secret then passes after fix; image inspection |
| T-17 | Dependencies, base images, scanners | T | Vulnerable or malicious component enters the build (M) | Pinned dependencies and scanner versions, digest pinning, Grype and Syft, checksum verification | A06, A08 | Grype report; SBOM archived with commit and build number |
| T-18 | GitHub → Jenkins (TB4) | T, E | Untrusted branch or PR runs a Jenkinsfile with privileged credentials (H) | Trusted branches only, protected main, credentials scoped per stage | A08 | Pipeline configuration review |
| T-19 | Jenkins controller (TB6) | S, E | Unauthorized access to the Jenkins UI or script console (H) | Loopback bind, SSH tunnel, authentication enabled, zero controller executors | A05, A07 | Port check from LAN shows closed |
| T-20 | Jenkins agent and Docker (TB5) | E | Docker access gives host-level control (H) | Dedicated agent user, trusted branches, no socket in scanner containers; residual risk documented | A05 | Group membership listing |
| T-21 | Application pod | E | Container escape or privilege escalation (H) | Non-root, no privilege escalation, drop ALL capabilities, seccomp RuntimeDefault, read-only root FS, PSA restricted, no service-account token | A05 | `id` inside container; securityContext in manifests; Checkov |
| T-22 | Pod network (TB2) | I, E | A compromised or rogue pod reaches PostgreSQL or other pods (H) | Default-deny ingress and egress; allow only DNS, app → DB and ingress to app | A05 | In-cluster allow and deny tests |
| T-23 | Kubernetes Secrets (TB5) | I | Secret values read through RBAC or etcd; base64 is not encryption (M) | Least-privilege RBAC; absence of encryption at rest documented | A02, A05 | `kubectl auth can-i --list` output |
| T-24 | Jenkins deploy identity (TB5) | E | Stolen kubeconfig grants cluster-admin (H) | Namespace-scoped ServiceAccount and Role; no cluster-admin | A01, A05 | `can-i` outputs |
| T-25 | Local registry (TB5) | T | Image replaced or pushed by an unauthorized party (M) | Localhost-only binding, digest-pinned deployments; lack of TLS and signing documented | A08 | Registry binding check |
| T-26 | SSH to the VM (TB6) | S, E | Brute force or key theft yields VM access (H) | Loopback forward only, key authentication with passphrase, no root login, updates | A07 | `sshd_config` review |
| T-27 | Application and cluster | D | Request flood or resource exhaustion (M) | Login throttling, upload limits, resource requests and limits, probes | A04 | Throttle test; limits in manifests |

### B.5 Mapping to the controlled vulnerability scenarios

| Scenario | Threats | Planned evidence |
| --- | --- | --- |
| V1 IDOR | T-03, T-04 | Scripted multi-user test (ZAP does not reliably find IDOR) |
| V2 Unsafe upload | T-06, T-07 | Crafted-file upload tests and rejection log |
| V3 Stored XSS | T-09 | ZAP or manual harmless payload |
| V4 Dummy secret | T-16 | Gitleaks failure, rotation, passing rerun |

Suggested dynamically confirmed pair for the spec requirement: V1 (multi-user test) and V3 (ZAP or manual), each before and after remediation.

### B.6 Limitations and residual risks

- Audit logs in the application database are not tamper-proof (T-13).
- Kubernetes Secrets are not encrypted at rest by default (T-23).
- The local registry has no TLS or image signing (T-25).
- The Jenkins agent shares the VM with the controller (T-20).
- Repudiation is covered by T-11 only; extend if the report needs more depth.
- Scanners do not find business-logic flaws; explicit authorization tests are required.
