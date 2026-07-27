FROM python:3.11-slim

# tzdata lets the TZ env var (set per-service in docker-compose.yml) resolve
# to real offset rules -- without it, glibc silently stays on UTC regardless
# of what TZ is set to.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir .
RUN useradd --create-home --shell /bin/false echidra \
    && mkdir -p /app/logs \
    && chown -R echidra:echidra /app
USER echidra

# docker-compose.yml overrides this per-service (honeypot vs. API); running
# it standalone starts both together via the echidra CLI, same as
# `echidra start` outside a container.
CMD ["python", "-m", "echidra", "start"]
