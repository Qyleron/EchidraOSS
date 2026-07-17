# Deployment

Three supported paths: the local dev Quick Start, a Docker Compose stack, and
systemd units for a bare VM. Docker Compose and systemd both require
`ECHIDRA_INGEST_API_KEY`. `ECHIDRA_SESSION_SECRET` is required for Compose;
for a bare-metal systemd run it's optional only if you're running a single
API process — set it explicitly if you run more than one, so they all
sign/verify the same dashboard session cookies (see below).

## Local machine

Covered in full in the [README Quick Start](../README.md#quick-start)
(`echidra init` / `echidra serve` / `echidra status`) and in
[TESTING_GUIDE.md](TESTING_GUIDE.md#manual-testing-guide) if you'd rather run
each service in its own terminal. No systemd units, containers, or a
dedicated `echidra` user — just a clone, a virtualenv, and `.env`. This is
the right choice for trying Echidra out or actively developing on it; move to
Docker Compose or systemd once you want it running unattended.

## Secrets you need either way

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # ECHIDRA_INGEST_API_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # ECHIDRA_SESSION_SECRET (optional, see below)
```

- `ECHIDRA_INGEST_API_KEY` — required. `POST /classify/session/store` refuses
  every request until this is set.
- `ECHIDRA_SESSION_SECRET` — optional only for a single-instance bare-metal
  (systemd) deployment. If unset there, the API auto-generates one and
  persists it to `logs/.dashboard_session_secret` on first run. Set it
  explicitly if you run more than one API process (systemd + a reverse proxy
  doing multiple workers) so they all sign/verify the same session cookies.
  Compose always requires it explicitly — see below.
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

Unlike a bare-metal run, Compose also requires `ECHIDRA_SESSION_SECRET`
explicitly rather than falling back to the auto-generated/persisted default
described above — the `api` container's writable layer doesn't survive
`docker compose down`/recreation, so an auto-generated secret would silently
rotate and invalidate every dashboard session.

```bash
cp .env.example .env
# edit .env: set ECHIDRA_DB_PASSWORD, ECHIDRA_INGEST_API_KEY, and
# ECHIDRA_SESSION_SECRET (see above)
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
[deploy/systemd/](../deploy/systemd/) — `echidra-honeypot.service` for the
listeners and `echidra-api.service` for the dashboard and classifier API.

Both unit files run as the unprivileged `echidra` user with
`ProtectSystem=strict` (read-only filesystem outside `logs/`). The
`AmbientCapabilities=CAP_NET_BIND_SERVICE` line in
`echidra-honeypot.service` is commented out by default, since it grants a
capability the process doesn't otherwise need. Uncomment it only if you set
any listener port below 1024 (e.g. `ECHIDRA_HTTP_PORT=80`).

Both unit files assume the layout below (`WorkingDirectory=/opt/echidra`,
`EnvironmentFile=/opt/echidra/.env`, `ExecStart=/opt/echidra/venv/bin/...`) —
edit the paths in `deploy/systemd/*.service` first if you install somewhere
else:

```bash
sudo useradd --system --home /opt/echidra --shell /usr/sbin/nologin echidra
sudo git clone <this-repo-url> /opt/echidra
cd /opt/echidra
sudo python3 -m venv venv
sudo ./venv/bin/pip install -e .
sudo cp .env.example .env
sudo $EDITOR .env   # set ECHIDRA_DATABASE_URL, ECHIDRA_INGEST_API_KEY, ECHIDRA_SESSION_SECRET
sudo mkdir -p logs
sudo chown -R echidra:echidra /opt/echidra

sudo cp deploy/systemd/echidra-honeypot.service deploy/systemd/echidra-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now echidra-honeypot
sudo systemctl enable echidra-api

# echidra-api requires a Postgres instance reachable at ECHIDRA_DATABASE_URL
# before it starts cleanly -- init it first, the same way Compose's init-db
# step works, then start the service.
sudo -u echidra venv/bin/python -m classifier.storage.cli init-db
sudo systemctl start echidra-api
```

Check status:

```bash
sudo systemctl status echidra-honeypot echidra-api
journalctl -u echidra-honeypot -f
```

## Any of these: confirm it's actually working

```bash
cd /opt/echidra   # or wherever you cloned it, with the venv active
python -m echidra status
```

Reports whether each honeypot listener is accepting connections, whether the
API responds to `/health`, whether the database is reachable, and how many
sessions have been classified so far. Run this after any deploy before
declaring it done — a listening honeypot with an unreachable database will
still accept connections and log to JSONL, but the dashboard will be empty.
