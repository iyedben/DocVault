# DocVault — Phase 0 Environment Audit

**Audit date:** 4 November 2026  
**Workspace:** `/home/docvault/DocVault`  
**Scope:** Read-only inspection of supplied project documents and the command environment available during this audit. No software was installed or upgraded, no system configuration was changed, and no application source was created.

## Executive summary

All three requested project documents are present: the v2.0 Technical Architecture and Project Baseline, the v2.1 Changelog and STRIDE Threat Model, and the original five-page course project specification PDF.

DocVault is proposed as a role-based document management application with a FastAPI/Python backend, simple browser frontend, PostgreSQL, containerization, Jenkins CI/CD, security scanning, and a hardened local Kubernetes deployment. The four controlled scenarios are IDOR, unsafe file upload, stored XSS, and exposure of a dummy secret. The course specification requires at least four vulnerabilities across three categories, at least two dynamically confirmed and fixed, and a pipeline policy that blocks a prepared case.

The Phase 0 shell audit reported Ubuntu 26.04.1 LTS on x86_64 with four CPUs, about 7.3 GiB RAM and 4 GiB swap, and a 97 GB root filesystem with 84 GB available. That inspection ran in a restricted container and is not the standalone VM baseline. Separate VM installation evidence supplied for Phase 1B identifies Oracle VirtualBox and confirms Docker Engine 29.9.3, Compose v5.7.0, Buildx v0.38.1, an active Docker service, and a successful `hello-world` smoke test. See [Phase 1 Docker Installation](PHASE_1_DOCKER_INSTALLATION.md). Other VM resource measurements were not provided.

In the restricted Phase 0 shell, pip, Node.js/npm, Docker/Compose, Kubernetes tools, and Helm were unavailable. Git 2.53.0 and Codex CLI 0.166.0 were detected. The workspace's `.git` path is an empty directory rather than a usable Git repository, and global/system Git configuration files were absent. These are observations from that shell, not proof of the standalone VM state; Docker was subsequently verified on the standalone VM as described in the Phase 1B report.

## Project documents inspected

| Document | Status | Notes |
|---|---|---|
| `DocVault_Technical_Architecture_and_Project_Baseline-v2.md` | Present and read | Main architecture baseline, version 2.0, dated 4 November 2026; proposed and subject to instructor approval. |
| `DocVault v2.1 — Changelog and STRIDE Threat Model.md` | Present and read | Companion draft dated 4 November 2026; proposed and pending instructor approval. |
| `DocVault_Project_Specifications.pdf` | Present and read | Original five-page proposed course specification. Its text was extracted from the PDF's compressed text streams using Python standard-library decoding; no parser was installed. |

### Architecture summary

The proposed application lets authenticated users upload, list, download, delete, and share documents, with server-side ownership and permission checks, user and administrator roles, audit events, and file validation. Documents are stored outside the public web root under generated names. Authentication uses Argon2id and protected cookies/sessions; browser local storage is explicitly excluded for authentication tokens.

The proposed deployment is a Windows 11 host running VirtualBox and an Ubuntu Server 26.04 LTS VM administered from Windows using MobaXterm over SSH. Inside the VM, Docker/Compose runs the application and supporting services. Jenkins orchestrates CI/CD from GitHub; Semgrep, Gitleaks, Grype, Syft, Checkov, and ZAP provide code, secret, dependency/image, SBOM, infrastructure, and dynamic checks. Minikube with Calico provides local Kubernetes deployment and network-policy enforcement; Helm packages the application. Jenkins is intended to be loopback-only and accessed over an SSH tunnel. Pipeline evidence and reports are archived.

The threat-model companion defines assets, six trust boundaries, 27 STRIDE threats mapped to OWASP Top 10 categories, mitigations, and validation evidence. It records residual risks including same-VM Jenkins agent privileges, Kubernetes Secrets not encrypted at rest by default, a local registry without TLS/signing, and audit logs stored with application data.

### Main technology stack in the documents

| Area | Proposed technology |
|---|---|
| Host and virtualization | Windows 11; VirtualBox 7.2.10+ |
| Guest and administration | Ubuntu Server 26.04 LTS; MobaXterm over SSH |
| Source control / CI/CD | GitHub / Jenkins LTS (approval required) |
| Backend / frontend | Python + FastAPI / HTML, CSS, Bootstrap, JavaScript |
| Database / ORM | PostgreSQL / SQLAlchemy |
| Containers | Docker Engine + Docker Compose |
| Security and supply-chain tools | Semgrep CE, Gitleaks, Grype, Syft, Checkov, ZAP by Checkmarx |
| Local orchestration | Minikube, Calico, Helm (v4 proposed, compatibility unresolved) |
| Registry and evidence | Local Docker registry; Jenkins artifacts and Kubernetes logs |

The architecture excludes Trivy and proposes Grype, Syft, and Checkov for the selected scanning, SBOM, and configuration-scanning duties. The course specification names Trivy and says GitLab/GitLab CI is the default; alternatives such as GitHub Actions or Jenkins require instructor approval.

### Implementation phases

The architecture roadmap has these phases:

0. **Approval and environment:** secure instructor approval, prepare the Ubuntu VM, SSH forwarding, and baseline hardening.
1. **Core application:** implement FastAPI/frontend, PostgreSQL models, authentication, roles, document workflows, sharing, audit events, and tests.
2. **Local containers:** add Dockerfile and Compose, non-root runtime, persistence, and health checks.
3. **Jenkins and security tools:** configure controller/agent, GitHub integration, scanner/test stages, artifacts, and gates.
4. **Kubernetes:** install and verify Minikube, kubectl, Calico, and Helm; implement RBAC, secrets, policy, chart, and deployment.
5. **DAST and remediation:** run ZAP and authorization tests, reproduce/remediate scenarios, and archive before/after evidence.
6. **Final report and demonstration:** gather resource and security evidence, document limitations, and prepare the presentation.

The course PDF organizes equivalent work into approval/design plus milestones 2–7 for application, containerization, CI/CD, security checks, Kubernetes, DAST/telemetry, and final evidence/presentation. It does not provide calendar dates.

### Four controlled vulnerability scenarios

| ID | Scenario/category | Planned demonstration and remediation |
|---|---|---|
| V1 | IDOR / broken access control | User A tries to access User B's document by changing an identifier; enforce server-side ownership/sharing checks and prove with multi-user tests. |
| V2 | Unsafe file upload / file validation | Try a prohibited or misleading file; validate size, extension, MIME type, and magic bytes, use random storage names, and record rejection. |
| V3 | Stored XSS / injection | Submit a harmless script payload in controlled metadata; apply context-aware output encoding, safe templates, and CSP. |
| V4 | Exposed dummy secret / secrets management | Add only a fictional credential in a controlled test branch; make Gitleaks block the pipeline, rotate/replace first, clean up, rerun, and retain redacted evidence. |

The spec additionally requires evidence for each finding (location, root cause, impact, reproduction, remediation, regression test), at least two dynamic confirmations followed by fixes and retests, a policy-enforced pipeline failure/recovery, and a fictional attack event visible in telemetry.

### Unresolved technical and approval decisions

- Instructor approval for individual rather than team scope, and approval for GitHub/Jenkins instead of the default GitLab CI; approval for replacing Trivy with the proposed tools.
- Required vulnerability categories, evidence format, and whether the proposed local registry meets course expectations.
- Jenkins controller native installation versus container (v2.1 D-1 proposes native).
- Helm 4 versus Helm 3, to be decided after Checkov and Minikube compatibility checks (v2.1 D-2).
- Current compatibility/support of Ubuntu 26.04 with chosen VirtualBox, Docker, Jenkins, Minikube, Calico, and Helm versions; compatible Kubernetes/Calico versions; scanner release and artifact-verification choices.
- Whether Minikube's `--disk-size` is honored with the selected Docker driver; the exact pinned Kubernetes version.
- How the cluster reaches the image registry (Minikube registry addon, insecure registry, or image-load fallback), and whether Checkov Helm scanning works with Helm 4.
- Whether all v2.1 proposed changes are accepted into the canonical architecture. The companion is a changelog, not a replacement architecture document.

### Contradictions and document gaps

1. **Course team model vs individual project:** the course PDF calls for a team of 3–4 students. The v2.0 architecture proposes an individual project, explicitly subject to instructor approval. This is an approval dependency, not a resolved requirement.
2. **Source control and CI/CD:** the PDF names GitLab/GitLab CI as the default and allows GitHub Actions or Jenkins only if approved. The architecture selects GitHub and Jenkins, pending approval.
3. **Scanner substitution:** the PDF names Trivy for dependency/image scanning. The architecture intentionally excludes it and selects Grype, Syft, and Checkov; v2.1 explicitly adds instructor approval of the substitution.
4. **Incident-response sequence:** v2.0 §16 gives detect, identify, contain, preserve evidence, remediate, retest. The PDF and v2.1 require detect → contain → eradicate → restore → learn. These are different sequences and should be reconciled in the baseline before implementation/reporting.
5. **v2.1 changes are not incorporated in the supplied v2.0 baseline:** v2.1 describes additions/changes (swap, native Jenkins proposal, registry reachability, enforceable gates, NodePort-based DAST/network-policy path, etc.), but the architecture file remains explicitly v2.0 and does not itself contain all those updates. Treat v2.1 as companion proposals, not silently as implemented baseline facts.
6. **Swap requirement vs existing allocation:** v2.1 says add 2–4 GB swap. The observed environment has 4 GB swap, but the v2.0 allocation table does not specify swap. This audit did not change it.
7. **Scope wording:** the v2.0 objective calls for controlled vulnerability remediation and retesting, while some architecture language says “if required by the course specification.” The course PDF makes at least two dynamic confirmations and subsequent fixes mandatory.
8. **Phase dates:** v2.1 says phase target dates are mapped to course milestones “(dates to be filled in)”; no actual dates are provided in either companion document.

## Environment audit

The original Phase 0 commands ran in the available workspace context on 4 November 2026. Values below describe that restricted shell only; they are not measurements of the standalone Ubuntu VM. Separate direct VM evidence for Docker installation is documented in [Phase 1 Docker Installation](PHASE_1_DOCKER_INSTALLATION.md). The architecture's remaining host details are project-provided assumptions unless explicitly recorded in that Phase 1 evidence.

### Operating system, kernel, CPU, memory, and disk

| Check | Observed result |
|---|---|
| Ubuntu | Ubuntu 26.04.1 LTS, codename `resolute` (`/etc/os-release`). Version matches the stated target. |
| Kernel / architecture | Linux `7.0.0-42-generic`, x86_64. |
| CPU | 4 online CPUs (0–3), AMD Ryzen 7 4800H presented to this restricted shell; KVM hypervisor reported. This is not the standalone VM CPU result. |
| RAM | 7.3 GiB total, 1.2 GiB used, 4.5 GiB free, 6.1 GiB available at audit time. This is consistent with an approximately 8 GB VM allocation. |
| Swap | 4.0 GiB swap file `/swap.img`, 0 used. |
| Virtual disk | `/dev/sda` reports 100 GB total; `/dev/sda3` is a 98 GB LVM physical volume. |
| Root filesystem | 97 GB ext4 logical volume mounted at `/`, 8.6 GB used, 84 GB available (10%). `/boot` is 2 GB with 1.7 GB free. |

Disk assessment for the restricted shell: 84 GB was free at the time of that check. Standalone VM free space is not established here. Container images/caches, Jenkins workspaces and artifacts, scanners, and a local Kubernetes cluster can grow substantially. No storage changes were made.

RAM assessment for the restricted shell: it exposed about 7.3 GiB RAM and 4 GiB swap. The standalone VM allocation was not provided with the Phase 1B evidence. The architecture proposes sequential heavy jobs and conservative cluster settings; monitor actual VM memory pressure and avoid concurrent heavy scans.

### User, permissions, and network

- Current account: `docvault`, UID/GID 1000. Reported groups include repeated `nogroup` entries; no `sudo` permission listing was available. `sudo -n -l` was blocked because the execution context sets `no new privileges`; this does not establish whether the actual VM account has administrator access.
- Network interface details: `ip` could not open the netlink socket (`Operation not permitted`). `/proc/net/dev` exposed only loopback in this context, and hostname address lookup was restricted. Treat interface status and IP addresses as **not verified**.
- Connectivity: DNS lookup for `github.com` failed (`Could not resolve host`). This execution environment therefore did not establish GitHub connectivity. The failure may reflect sandbox/network restrictions rather than the VM's persistent network configuration.

### Installed tools and versions

| Tool | Observed result |
|---|---|
| Git | `git version 2.53.0`. |
| Git configuration | No global `~/.gitconfig` or system `/etc/gitconfig` found. `git config --show-origin --list` returned no configured values. Configure identity and any credential method when repository setup is authorized. |
| Git working tree | `git status`/`rev-parse` report “not a git repository.” The visible `.git` is an empty, read-only directory in this context; there is no repository metadata or remote to inspect. |
| Python | Python 3.14.4 (`python3 --version`). |
| pip | Not installed/available for this interpreter (`No module named pip`). |
| Node.js / npm | Not found. |
| Docker / Docker Compose | Not present in the restricted Phase 0 shell. The standalone VM later installed and verified Docker; see [Phase 1 Docker Installation](PHASE_1_DOCKER_INSTALLATION.md). |
| Kubernetes | `kubectl` and `minikube` not found. |
| Helm | Not found. |
| Codex CLI | `codex-cli 0.166.0`. Its version command emitted a warning that it could not create PATH aliases because the filesystem is read-only; version was still reported. |
| Jenkins, Java, scanners | Not separately version-checked as installed tools; none of Jenkins, Semgrep, Gitleaks, Grype, Syft, Checkov, or ZAP appears in the requested tool inventory. Their installation status was not exhaustively verified by searching the entire filesystem. |

### Phase 1 preparation: installed system utilities

The following system utilities were found in `PATH` or the installed package inventory during this check:

| Utility group | Installed utilities |
|---|---|
| Source control / language | Git 2.53.0; Python 3.14.4 (`python3`; pip is unavailable). |
| Network / SSH | `curl`, `wget`, `openssh-client` (`ssh`, `ssh-keygen`), `openssh-server`, `iproute2` (`ip`, `ss`), `net-tools`, `ping`, `dig`, `nslookup`, `ca-certificates`. |
| Data / file handling | `jq`, `tar`, `unzip`, `rsync`, `tree`. |
| Administration / editing | `htop`, `vim`, `nano`, `software-properties-common`. |

Also checked and not found in the restricted Phase 0 shell: `make`, `gcc`, pip for the available Python interpreter, Node.js/npm, Docker/Compose, `kubectl`, Minikube, and Helm. The standalone VM Docker installation is documented separately; the utility list above is not a manifest of the VM. Jenkins, Minikube, Kubernetes, Helm, and security-scanner installation status on the standalone VM has not been verified here.

## Readiness assessment

### Missing prerequisites for the planned implementation

Before the corresponding project phases, the environment will need a working GitHub repository/remote and Git identity; Python packaging tooling and pinned project dependencies; Java/Jenkins; scanner tools; and Kubernetes tools (`kubectl`, Minikube, Calico support, Helm). Docker Engine, Compose, and Buildx are reported installed and verified on the standalone VM in the [Phase 1B Docker Installation report](PHASE_1_DOCKER_INSTALLATION.md). Node.js/npm are not explicitly required by the architecture unless the frontend/tooling choice adds that dependency. Instructor decisions and compatibility checks remain prerequisites before significant implementation.

Phase 1C records a successful isolated Nginx Compose validation, including localhost HTTP and cleanup checks, in the [Phase 1C Compose Validation report](PHASE_1_COMPOSE_VALIDATION.md). This did not test the DocVault application or PostgreSQL.

The original restricted audit context could not verify working network interfaces, DNS, GitHub reachability, sudo privileges, or Docker daemon status. Direct VM evidence now verifies VirtualBox and Docker service/smoke-test status as recorded in the Phase 1B report; other host/network details remain unverified.

### Compatibility and operational concerns

- The original shell audit ran in a container and reported KVM; separate Phase 1B evidence was collected inside the Oracle VirtualBox Ubuntu VM. Do not conflate the two environments.
- Python 3.14.4 is present, while pip is absent. Python dependency compatibility and the supported Python version should be decided and verified before implementation; do not infer library support solely from this audit.
- The restricted shell's root filesystem had 84 GB available; standalone VM root capacity was not supplied with the Docker installation evidence. Verify VM disk headroom before substantial image and cluster use.
- Four vCPUs and approximately 8 GB RAM align with the proposed VM allocation. Resource pressure remains likely during combined CI, scanning, and Kubernetes activity.
- Network failures may prevent GitHub checkout, dependency retrieval, or tool acquisition; this audit could not distinguish sandbox restrictions from guest configuration.
- Git is available but the project directory is not currently a Git checkout and has no observed identity/remote configuration.
- Docker Engine/Compose/Buildx are installed and verified on the standalone VM as recorded in the Phase 1B report. Jenkins, Kubernetes/Calico, Helm, scanners, and their compatibility remain pending or unverified.

### Risks affecting implementation

1. **Approval risk:** individual scope, GitHub/Jenkins, and scanner substitution are pending instructor approval.
2. **Capacity risk:** the restricted shell's root filesystem had 84 GB free; standalone VM capacity was not provided. Images, caches, Jenkins data, and Kubernetes may consume substantial disk space.
3. **Memory risk:** 8 GB guest RAM is constrained for the full proposed stack, particularly concurrent cluster and scanner workloads.
4. **Connectivity risk:** network/DNS tests failed or were restricted in this context, so repository and package access are unconfirmed.
5. **Environment identity risk:** the original Phase 0 shell was a restricted container with an empty mounted `.git` directory. Phase 1B VM evidence separately confirms Oracle VirtualBox, but does not establish that the workspace itself is mounted from that VM.
6. **Compatibility risk:** several selected tool/version pairs are unverified and are called out as decisions in the documents.

## Recommended preparation order

1. Confirm with the instructor the individual project format, GitHub/Jenkins choice, Trivy replacement, and deliverable/evidence expectations.
2. Confirm the VM's user sudo/admin status, SSH/MobaXterm access, network interfaces, DNS, and GitHub connectivity.
3. Verify standalone VM disk headroom and preserve space for images and build artifacts.
4. Keep the planned 8 GB/4 vCPU allocation if the Windows host remains responsive; use sequential resource-intensive tasks.
5. Resolve the document inconsistencies and open compatibility choices: incident-response sequence, Jenkins placement, registry route, Helm version, Kubernetes/Calico pair, and course-required scanner/gate behavior.
6. After approval, prepare version-pinned prerequisites in the architecture's phase order. Application implementation remains subject to the project approval decisions above.

## Recommended next action

Obtain instructor approval for the proposed individual scope and GitHub/Jenkins/Trivy substitutions, then verify remaining VM network, sudo, resource, and compatibility details. Docker installation and its reported verification are recorded in [Phase 1 Docker Installation](PHASE_1_DOCKER_INSTALLATION.md). The earlier Phase 0 host inventory describes the restricted shell, not the standalone VM. No application source or architecture was changed by this documentation update.

## Supplementary Environment Verification

**Verification date:** 4 November 2026  
**Method:** Requested commands were run read-only in the available command environment. Failures caused by sandbox restrictions are reported as inconclusive and are not interpreted as persistent VM configuration.

### Virtualization

- `systemd-detect-virt` reports **`container-other`**. This indicates the current command context is itself containerized; it does not identify the physical or VM hypervisor hosting the container.
- `lscpu` reports four online CPUs, AMD Ryzen 7 4800H presented to the environment, and **KVM** as the hypervisor vendor / full virtualization type. In combination with `systemd-detect-virt`, this is evidence about the nested execution context, not conclusive proof that the user's intended Ubuntu VM runs on KVM rather than VirtualBox.
- Guest Additions check: the `vboxguest` kernel module appears in `lsmod`, but `VBoxControl` was not found and `/opt/VBoxGuestAdditions-*` and `/usr/lib/VBoxGuestAdditions` were absent. This is mixed evidence and does **not** establish a complete or functional VirtualBox Guest Additions installation. It may reflect host/container module visibility.
- **Conclusion:** this audit environment is detected as a container and exposes KVM CPU virtualization metadata. The requested distinction between the intended VirtualBox guest and another underlying hypervisor cannot be resolved from this restricted nested context. Re-run these checks in a direct shell on the Ubuntu VM for a reliable answer.

### Permissions

- `id`: `uid=1000(docvault) gid=1000(docvault)`; supplementary groups shown are repeated `nogroup` entries.
- `sudo -n true` failed with exit status 1. Sudo reported that the **“no new privileges”** flag prevents running as root in this container context. Therefore passwordless sudo is **not available in this command context**; this result does not establish the sudo configuration of the intended VM account.

### Network

- `ip addr` and `ip route` both failed with `Cannot open netlink socket: Operation not permitted` (exit status 1). Interface addresses and routes are **not readable in this context**.
- DNS lookup for `github.com` via `getent ahosts github.com` returned no addresses (exit status 2).
- `curl -I --max-time 8 https://github.com` failed with `curl: (6) Could not resolve host: github.com` (exit status 6). HTTPS connectivity could not be tested because DNS resolution failed first.
- These failures are consistent with the restrictions observed in this container and do not prove that the VM itself lacks DNS or Internet access.

### Storage

- `lsblk`: `/dev/sda` is 100 GB; `/dev/sda2` is 2 GB and mounted at `/boot`; `/dev/sda3` is 98 GB. Snap loop devices were also listed.
- Earlier supplementary `df -h` output showed a 48 GB root logical volume with 37 GB available; a later Phase 0 shell check reported a 97 GB root filesystem with 84 GB available. These are measurements of restricted command contexts, not the standalone VM. `/boot` was reported as 2 GB with 1.7 GB available. Several tmpfs mounts are visible, including bind-mounted workspace metadata directories.
- `findmnt /`: `/` is `/dev/mapper/ubuntu--vg-ubuntu--lv`, ext4, with mount options including **`ro`** (read-only), `nosuid`, and `nodev`. The read-only root mount is an attribute of this current execution environment and may be imposed by its sandbox; it is not evidence that the user's normal VM root filesystem is configured read-only.
- The earlier 100 GB block device versus 48 GB root filesystem discrepancy has not been reproduced by the later check, which reports a 97 GB root filesystem. This check did not modify storage.

### GitHub and repository state

- Git is installed: `git version 2.53.0`.
- `git rev-parse --show-toplevel` and `git remote -v` both failed with “not a git repository” (exit status 128). No GitHub remote or repository is configured in this workspace context.
- No authentication was attempted and no Git configuration was changed.

### Supplementary conclusion

The original Phase 0 probes confirm that command session was constrained inside a container (restricted netlink, `no new privileges`, read-only root mount), while exposing KVM CPU metadata and a `vboxguest` module entry. Those findings describe that shell and are not VM facts. Separate standalone VM evidence for Phase 1B is recorded in [Phase 1 Docker Installation](PHASE_1_DOCKER_INSTALLATION.md). No claim is made here about VM settings not included in that evidence.

## Phase 2A update — standalone VM development environment (4 November 2026)

This section records direct checks on the standalone Ubuntu VM and supersedes earlier Phase 0 shell observations where they described a restricted container. The current host is `docvault-srv`, Ubuntu 26.04.1 LTS on Oracle VirtualBox. It has Python 3.14.4, Git 2.53.0, 83 GB free on a 97 GB root filesystem, 7.3 GiB RAM (6.3 GiB available), and 4 GiB swap. Docker CLI 29.9.3 and Compose v5.7.0 are installed. Docker daemon access could not be verified because the current account lacks Docker socket permission and noninteractive sudo requested authentication.

The Ubuntu preparation utilities (`curl`, `wget`, SSH tools, `ip`, `ss`, `ifconfig`, `ping`, DNS tools, `jq`, archive/file tools, `htop`, editors, `make`, and `gcc`) were checked and found. Node.js/npm, `kubectl`, Minikube, and Helm were absent; they were not required or installed in Phase 2A.

System pip was unavailable. Creating `.venv` initially failed because `python3.14-venv` was missing. That OS package was installed with apt, after which `/home/docvault/DocVault/.venv` was created and used for all Python packages. See [Phase 2A Development Environment](PHASE_2A_DEVELOPMENT_ENVIRONMENT.md) for exact dependency versions, commands, verification, and limitations. No global Python packages were installed.

## Phase 2B update — PostgreSQL deployment (4 November 2026)

The standalone Ubuntu VM subsequently ran PostgreSQL in the `postgres:17-bookworm` container. Manual SSH-terminal checks reported the container `healthy`; `pg_isready -U postgres -d docvault` returned `/var/run/postgresql:5432 - accepting connections`; and both `docvault_app` and `docvault_migrator` authenticated to `docvault`. Role inspection confirmed `postgres` has administrative privileges and the application and migration accounts have no elevated role attributes. All six Boolean attributes in the query output were false for both accounts. The evidence supplied for this update names five of the attributes (`rolsuper`, `rolcreatedb`, `rolcreaterole`, `rolreplication`, `rolbypassrls`); the sixth is not named here because its name was not included in the provided output. See [Phase 2B PostgreSQL Deployment](PHASE_2B_POSTGRESQL_DEPLOYMENT.md) for deployment context and limits of these checks.

This runtime evidence supersedes the earlier statement that PostgreSQL deployment and health verification had not occurred. It does not establish backup/restore readiness or application-to-database connectivity.

## Phase 2B prerequisite check — Docker daemon access (4 November 2026)

Earlier direct checks on `docvault-srv` confirmed `docker.service` was active and running but could not access the Docker daemon through the current account. The later manual SSH-terminal PostgreSQL deployment and validation demonstrate that Docker commands were available in that normal SSH session. The prior permission limitation describes the earlier command context and should not be read as a current inability to deploy. No claim is made here about changes to group membership or socket permissions.
