# Pinned by digest (Dependabot keeps it current); the tag is kept for readability.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# tzdata provides the /usr/share/zoneinfo database that /etc/localtime
# (bind-mounted from the host in docker-compose.yml) resolves against --
# without it, glibc silently stays on UTC regardless of what's mounted.
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
