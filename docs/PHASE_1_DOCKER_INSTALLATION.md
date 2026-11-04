# DocVault — Phase 1B Docker Installation

**Documentation date:** 4 November 2026  
**Additional verification date:** 4 November 2026  
**Installation date:** Not verified in the evidence supplied for this report  
**Scope:** Docker Engine, Docker Compose plugin, and Buildx on the standalone Ubuntu Server VM. This report records the VM results supplied for Phase 1B; it does not treat the restricted Codex shell as the VM.

## Installation overview

Docker Engine and the Docker Compose plugin were installed and verified directly on the standalone Ubuntu Server VM over MobaXterm SSH. The installation method was Docker's official Ubuntu APT repository. Docker Engine was enabled/running at verification time, and a `hello-world` container completed successfully.

The exact installation transcript, repository configuration output, package transaction output, and installation date were not supplied. Therefore, this report records the method and verified results without asserting unprovided command output or timing.

## VM environment and verified versions

| Item | Verified result |
|---|---|
| Environment | Standalone Ubuntu Server VM; Oracle VirtualBox (`oracle`) |
| Ubuntu | 26.04.1 LTS |
| Docker Engine | 29.9.3, build `5457199` |
| Docker Compose | v5.7.0 (`docker compose` plugin) |
| Docker Buildx | v0.38.1, commit `0dbe87f36ed472fe36b6796c3f70b4210a731fc5` |
| Docker service | Active |
| Smoke test | `sudo docker run --rm hello-world` succeeded; output included the expected “Hello from Docker!” message. |

The guest kernel version, CPU/RAM allocation, root filesystem capacity, VM network configuration, Docker package repository suite/configuration, and precise installation date were not included in the supplied VM evidence and are **not verified in this report**.

## Installation method

The reported method used Docker's official APT repository for Ubuntu, following the [official Docker Engine Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/). Docker's repository setup uses its signing key and an APT source configured for the Ubuntu codename and system architecture. The installed package set was:

- `docker-ce`
- `docker-ce-cli`
- `containerd.io`
- `docker-buildx-plugin`
- `docker-compose-plugin`

The standalone legacy `docker-compose` binary installation method was not used. The exact repository setup and package-install commands are not present in the evidence supplied, so this report does not represent them as a captured command transcript.

## Verification commands and results

The following commands were reported as run on the standalone VM:

```bash
docker --version
docker compose version
docker buildx version
sudo systemctl status docker --no-pager
sudo docker run --rm hello-world
```

Recorded results are listed in the version table above. The Docker service was active. The smoke test exited successfully and printed “Hello from Docker!”. Full raw outputs and the service's detailed unit state were not supplied; only the summarized results are recorded.

## Security considerations

- Access to the Docker daemon is highly privileged. A user able to control it can generally obtain host-level privileges.
- Membership in the `docker` group is effectively root-equivalent. The direct VM check found user `docvault` (UID 1000, primary GID 1000) is **not** a member of the `docker` group. The group exists with GID 983. No group membership change was made as part of this documentation update.
- Docker security options reported by the VM were AppArmor using the default profile, Seccomp using the builtin profile, and cgroup namespace enabled.
- On 4 November 2026, `sudo ss -lntp | grep -E '2375|2376' || true` returned no matching listening sockets. This records the result for those ports at the time of the check; it does not establish that every possible remote Docker API exposure has been eliminated.
- Firewall settings were not modified as part of this phase.
- No additional Docker daemon hardening or security setting changes are claimed.
- SSH configuration was not changed as part of the documented scope.

## Additional security verification (4 November 2026)

| Check | VM result |
|---|---|
| User identity | `docvault`, UID 1000, primary GID 1000 |
| Docker group | Exists with GID 983; `docvault` is not a member |
| Docker `SecurityOptions` | AppArmor: default profile; Seccomp: builtin profile; cgroup namespace: enabled |
| TCP listener probe | `sudo ss -lntp | grep -E '2375\|2376' || true` produced no matching listening sockets |

## Limitations and pending decisions

- Installation date and exact command/package transaction transcript remain unverified.
- The recorded VM check found `docvault` is not in the Docker group. If non-sudo Docker access is later desired, any group change requires a conscious decision because membership is root-equivalent.
- VM disk, memory, CPU, kernel, network reachability, firewall rules, and Docker repository configuration were not part of the supplied verification evidence.
- Jenkins, Kubernetes/Minikube, Helm, and security scanner status on the standalone VM is not established by this report. Their installation and architecture choices remain governed by the project baseline and applicable approvals.

This report records Phase 1B Docker installation evidence only. It does not change the approved architecture or assert application implementation work.
