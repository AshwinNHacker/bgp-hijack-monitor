FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# Create a non-root user and a writable data directory for the SQLite state file
RUN useradd --create-home --shell /usr/sbin/nologin bgpmon \
    && mkdir -p /app/data \
    && chown -R bgpmon:bgpmon /app

USER bgpmon
VOLUME ["/app/data"]

# config.yaml is expected to be bind-mounted in; state_db_path should point
# under /app/data (see config/config.example.yaml)
ENTRYPOINT ["bgp-hijack-monitor"]
CMD ["monitor", "-c", "/app/config.yaml"]
