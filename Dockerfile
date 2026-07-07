FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# docker-compose.yml overrides this per-service (honeypot vs. API); running
# it standalone starts both together via the echidra CLI, same as
# `echidra serve` outside a container.
CMD ["python", "-m", "echidra", "serve"]
