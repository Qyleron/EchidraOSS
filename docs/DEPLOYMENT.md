# Deployment

Two supported paths beyond the local dev Quick Start in [README.md](../README.md):
a Docker Compose stack, and systemd units for a bare VM. Both need the same
two secrets first.

## Secrets you need either way

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # ECHIDRA_INGEST_API_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # ECHIDRA_SESSION_SECRET (optional, see below)
```

- `ECHIDRA_INGEST_API_KEY` — required. `POST /classify/session/store` refuses
  every request until this is set.
- `ECHIDRA_SESSION_SECRET` — optional. If unset, the API auto-generates one
  and persists it to `logs/.dashboard_session_secret` on first run, which is
  fine for a single instance. Set it explicitly if you run more than one API
  process (multiple containers/replicas, systemd + a reverse proxy doing
  multiple workers) so they all sign/verify the same session cookies.
- `ECHIDRA_COOKIE_SECURE=true` — set this once the dashboard is served over
  HTTPS (it isn't by default; put a reverse proxy like Caddy or nginx in
  front for TLS termination in production).

## Docker Compose

`docker-compose.yml` also requires `ECHIDRA_DB_PASSWORD` — it sets the
Postgres container's password and is interpolated into both the `honeypot`
and `api` services' `ECHIDRA_DATABASE_URL`, so the three stay in sync.
Compose fails fast with a clear error if you forget to set it, same as
`ECHIDRA_INGEST_API_KEY`. Avoid `@`, `/`, `:`, or `#` in the password —
they're not percent-encoded before being interpolated into the connection
string.

```bash
cp .env.example .env
# edit .env: set ECHIDRA_DB_PASSWORD and ECHIDRA_INGEST_API_KEY (see above)
docker compose up -d --build
docker compose exec api python -m classifier.storage.cli init-db
```

This starts three containers: `db` (Postgres 16), `honeypot` (the four
listeners), and `api` (dashboard + classifier API on port 8000). The
`init-db` step only needs to run once — it's idempotent, so re-running it
against an existing database is safe.

Ports published on the host: `2222` (SSH-style shell), `8080` (HTTP),
`2121` (FTP), `2323` (Telnet), `8000` (dashboard/API). Adjust the `ports:`
mappings in `docker-compose.yml` if any of those collide with something else
already running on the host.

To seed the four demo Intelligence-page issues (useful for a first look at
the dashboard before any real traffic arrives):

```bash
docker compose exec api python -m classifier.storage.cli init-db --seed-demo-issues
```

## systemd (bare VM)

Two separate units — `echidra-honeypot.service` and `echidra-api.service` —
so a crash or restart in one never takes down the other. Both live in
[deploy/systemd/](../deploy/systemd/).

```bash
sudo useradd --system --home /opt/echidra --shell /usr/sbin/nologin echidra
sudo mkdir -p /opt/echidra
sudo cp -r . /opt/echidra   # or git clone directly into /opt/echidra
cd /opt/echidra

python3 -m venv venv
venv/bin/pip install -r requirements.txt

cp .env.example .env
# edit .env: set ECHIDRA_DATABASE_URL and ECHIDRA_INGEST_API_KEY
venv/bin/python -m classifier.storage.cli init-db

sudo chown -R echidra:echidra /opt/echidra
sudo mkdir -p /opt/echidra/logs && sudo chown echidra:echidra /opt/echidra/logs

sudo cp deploy/systemd/echidra-honeypot.service deploy/systemd/echidra-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now echidra-honeypot echidra-api
```

Both unit files run as the unprivileged `echidra` user with
`ProtectSystem=strict` (read-only filesystem outside `logs/`). If you set
any listener port below 1024 (e.g. `ECHIDRA_HTTP_PORT=80`), keep the
`AmbientCapabilities=CAP_NET_BIND_SERVICE` line in
`echidra-honeypot.service` — remove it if you're using the non-privileged
defaults, since it grants a capability the process doesn't otherwise need.

Check status:

```bash
sudo systemctl status echidra-honeypot echidra-api
journalctl -u echidra-honeypot -f
```

## Either way: confirm it's actually working

```bash
cd /opt/echidra   # or wherever you cloned it, with the venv active
python -m echidra status
```

Reports whether each honeypot listener is accepting connections, whether the
API responds to `/health`, whether the database is reachable, and how many
sessions have been classified so far. Run this after any deploy before
declaring it done — a listening honeypot with an unreachable database will
still accept connections and log to JSONL, but the dashboard will be empty.
