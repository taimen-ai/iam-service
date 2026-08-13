FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.0 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12-slim AS runtime

RUN useradd --create-home --uid 10001 iam
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY alembic.ini ./
COPY migrations ./migrations
COPY src ./src
COPY pyproject.toml README.md ./
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER iam
EXPOSE 8010
CMD ["uvicorn", "iam_service.app:app", "--host", "0.0.0.0", "--port", "8010"]
