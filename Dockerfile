FROM python:3.12-slim-trixie

# pg_dump for the on-demand /backup endpoint. The client must be at least as new as the
# server (16), so this relies on trixie shipping postgresql-client 17.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client \
 && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first, so this layer is cached until pyproject.toml or uv.lock change.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .

RUN useradd --create-home app && mkdir -p qrcodes && chown -R app /app
USER app

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000

# Apply pending migrations, then start the server.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app:app --host 0.0.0.0 --port 8000"]
