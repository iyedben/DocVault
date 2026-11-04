# DocVault — Phase 2A Development Environment

**Verification date:** 4 November 2026
**Host:** `docvault-srv`, Ubuntu 26.04.1 LTS (Oracle VirtualBox; `systemd-detect-virt` returned `oracle`)
**Project:** `/home/docvault/DocVault`

## Host and repository checks

| Check | Observed result |
|---|---|
| Python | Python 3.14.4 |
| System pip | Not installed for `/usr/bin/python3`; no global Python packages were installed |
| venv | Initially could not bootstrap pip because `python3.14-venv` was missing; installed with `sudo -n apt-get update` and `sudo -n apt-get install -y python3.14-venv` |
| Git | 2.53.0 |
| Disk | 83 GB available on a 97 GB root filesystem |
| Memory | 7.3 GiB total, 6.3 GiB available; 4.0 GiB swap |
| Docker client | Engine CLI 29.9.3; Compose v5.7.0 |
| Docker daemon | Not verified: Docker socket access was denied and `sudo -n docker info` required interactive authentication |
| Git remote | `origin` fetch/push: `https://github.com/iyedben/DocVault.git` |
| Git state at start | Branch `main`, clean, tracking `origin/main` |

The Phase 1 utility inventory was checked directly. Available: `curl`, `wget`, OpenSSH client/server tools, `ip`, `ss`, `ifconfig`, `ping`, `dig`, `nslookup`, `jq`, `tar`, `unzip`, `rsync`, `tree`, `htop`, `vim`, `nano`, `make`, and `gcc`. Not found: Node.js/npm, `kubectl`, Minikube, and Helm. These latter tools are not prerequisites for this Python environment phase. Docker and Compose versions are present; daemon access remains unverified as noted above.

## Virtual environment and packages

Created `/home/docvault/DocVault/.venv` with Python 3.14.4 after installing the missing Ubuntu `python3.14-venv` package. All Python packages were installed inside `.venv`; the externally managed system Python was not modified. Pip in the environment is 26.3.

Runtime exact pins are in `requirements.txt`; development pins are in `requirements-dev.txt`. `requirements-lock.txt` records the complete resolved environment using `pip freeze --all`, including transitive packages and the venv's pip version. Recreate the complete verified environment with:

```bash
cd /home/docvault/DocVault
python3 -m venv .venv  # if missing
. .venv/bin/activate
python -m pip install -r requirements-lock.txt
```

Requested direct dependency versions:

| Group | Package | Version |
|---|---|---:|
| Runtime | FastAPI | 0.162.0 |
| Runtime | Uvicorn | 0.54.0 |
| Runtime | Pydantic | 2.14.2 |
| Runtime | SQLAlchemy | 2.1.8 |
| Runtime | psycopg (binary extra installed) | 3.3.8 |
| Runtime | Alembic | 1.20.1 |
| Runtime | python-dotenv | 1.2.4 |
| Development | pytest | 9.2.0 |
| Development | pytest-cov | 7.1.0 |
| Development | HTTPX | 0.28.1 |
| Development | Ruff | 0.17.3 |
| Development | mypy | 2.4.1 |

## Verification performed

Commands included:

```bash
python3 --version
python3 -m pip --version
python3 -m venv --help
. .venv/bin/activate
python --version
python -m pip --version
python -m pip check
ruff --version
pytest --version
```

With the venv active, imports succeeded for `fastapi`, `uvicorn`, `pydantic`, `sqlalchemy`, `psycopg`, `alembic`, `dotenv`, `pytest`, `pytest_cov`, `httpx`, `ruff`, and `mypy`. Ruff reported 0.17.3; pytest reported 9.2.0; `pip check` reported no broken requirements. No application code or dummy functionality was created, and PostgreSQL, Jenkins, Kubernetes, Minikube, Helm, and security scanners were not installed.

## Limitations

The system interpreter has no standalone pip command module; project package management uses the isolated venv. Docker daemon health could not be checked without an interactive sudo authorization, although Engine and Compose client versions were verified. No project tests were run because this phase only verifies the development environment and there is no application code to test.
