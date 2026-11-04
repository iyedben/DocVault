FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY backend/app ./app
COPY backend/migrations ./backend/migrations
COPY alembic.ini ./alembic.ini

RUN groupadd --system --gid 10001 docvault \
    && useradd --system --uid 10001 --gid docvault --no-create-home docvault

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
