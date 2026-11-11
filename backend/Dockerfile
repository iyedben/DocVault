# Pinned to immutable multi-arch index digest retrieved 2026-11-10 from upstream library/python
FROM python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Remediate fixable zlib vulnerabilities (CVE-2026-76844, CVE-2026-85091) from verified Debian Security snapshot
RUN set -eux; \
    rm -rf /etc/apt/sources.list.d/* /etc/apt/sources.list; \
    echo 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.pgp check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261108T000000Z trixie-security main' > /etc/apt/sources.list.d/snapshot-security.list; \
    apt-get update -o Acquire::Check-Valid-Until=false; \
    apt-get install -y --no-install-recommends --only-upgrade \
        zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1; \
    rm -rf /etc/apt/sources.list.d/* /var/lib/apt/lists/*

COPY requirements-prod-lock.txt /tmp/requirements-prod-lock.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-deps -r /tmp/requirements-prod-lock.txt \
    && rm /tmp/requirements-prod-lock.txt

COPY backend/app ./app
COPY backend/migrations ./backend/migrations
COPY alembic.ini ./alembic.ini
COPY frontend ./frontend

RUN groupadd --system --gid 10001 docvault \
    && useradd --system --uid 10001 --gid docvault --no-create-home docvault \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/docvault/documents

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
