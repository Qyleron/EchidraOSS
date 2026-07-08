FROM python:3.11-slim

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir .
RUN useradd --create-home --shell /bin/false echidra \
    && mkdir -p /app/logs \
    && chown -R echidra:echidra /app
USER echidra

# docker-compose.yml overrides this per-service (honeypot vs. API); running
# it standalone starts both together via the echidra CLI, same as
# `echidra serve` outside a container.
CMD ["python", "-m", "echidra", "serve"]
