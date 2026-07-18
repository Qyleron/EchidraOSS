# Deployment

Three supported paths:

- **Local machine** — run directly from your terminal during development
  or evaluation. Suitable for trying Echidra out; not for unattended use.
- **systemd (bare VM)** — the same direct Python install as local machine,
  but managed as OS services that start on boot and restart on crash.
  The right choice for a dedicated server without Docker.
- **Docker Compose** — the entire stack (honeypot, API, Postgres) in
  containers. The right choice if Docker is available and you want
  a self-contained deployment without managing Python or Postgres directly.

Docker Compose and systemd both require `ECHIDRA_INGEST_API_KEY`.
`ECHIDRA_SESSION_SECRET` is required for Compose; for a bare-metal systemd
run it's optional only if you're running a single API process — set it
explicitly if you run more than one, so they all sign/verify the same
dashboard session cookies (see below).

## Local machine

Covered in full in the [README Quick Start](../README.md#quick-start)
(`echidra init` / `echidra serve` / `echidra status`) and in
[TESTING_GUIDE.md](TESTING_GUIDE.md#manual-testing-guide) if you'd rather run
each service in its own terminal. No systemd units, containers, or a
dedicated `echidra` user — just a clone, a virtualenv, and `.env`.

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
docker compose up -d --build db
docker compose run --rm --build api python -m classifier.storage.cli init-db
docker compose up -d --build honeypot api
```

`db` (Postgres 16) starts first, and `honeypot`/`api` already wait on its
healthcheck via `depends_on` -- but that only guarantees Postgres itself is
up, not that the schema exists yet, so `init-db` runs against it before
`honeypot`/`api` start (`docker compose run` spins up a one-off container
using `api`'s image/config, without needing `api` itself running yet, the
same way `docker compose exec api ...` needs a running container to attach
to; `--build` on that line ensures the image actually exists to run on a
clean checkout, rather than relying on Compose's implicit auto-build).
The `--rm` migration container is temporary and removed once `init-db`
finishes -- three long-running containers remain afterward: `db`,
`honeypot` (the four listeners), and `api` (dashboard + classifier API on
port 8000). The `init-db` step only needs to run once — it's idempotent,
so re-running it against an existing database is safe.

Ports published on the host: `2222` (SSH-style shell), `8080` (HTTP),
`2121` (FTP), `2323` (Telnet). Adjust the `ports:` mappings in
`docker-compose.yml` if any of those collide with something else already
running on the host. `8000` (dashboard/API) is bound to `127.0.0.1` only —
see below.

To seed the four demo Intelligence-page issues (useful for a first look at
the dashboard before any real traffic arrives):

```bash
docker compose exec api python -m classifier.storage.cli init-db --seed-demo-issues
```

**Accessing the dashboard remotely**

Port 8000 is bound to `127.0.0.1` only — it is not publicly accessible
by default, unlike the four decoy ports above, which are meant for the
same internet-facing exposure attackers reach. To reach the dashboard
from your local machine, open an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 user@your.server.ip
```

Then open http://localhost:8000 in your browser. The tunnel forwards
your local port 8000 to the server's port 8000 over the encrypted SSH
connection.

If you need persistent remote access, put nginx or Caddy in front of
port 8000 with TLS and restrict access by IP or client certificate.

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
sudoedit /opt/echidra/.env   # set ECHIDRA_DATABASE_URL, ECHIDRA_INGEST_API_KEY, ECHIDRA_SESSION_SECRET
sudo mkdir -p logs data      # data/ persists the SSH host key -- see echidra-honeypot.service's ReadWritePaths
sudo chown -R echidra:echidra /opt/echidra
sudo chmod 600 /opt/echidra/.env
sudo chmod 700 /opt/echidra/logs /opt/echidra/data

sudo cp deploy/systemd/echidra-honeypot.service deploy/systemd/echidra-api.service /etc/systemd/system/
sudo systemctl daemon-reload

# Initialize the database against ECHIDRA_DATABASE_URL before starting
# either service, the same way Compose's init-db step works, so neither
# echidra-api's first requests nor the honeypot's background classification
# worker hit missing tables.
sudo -u echidra venv/bin/python -m classifier.storage.cli init-db

sudo systemctl enable --now echidra-honeypot echidra-api
```

Check status:

```bash
sudo systemctl status echidra-honeypot echidra-api
sudo journalctl -u echidra-honeypot -f
```

**Firewall port 8000 on bare-metal deployments**

Unlike Compose (which binds 8000 to loopback in `docker-compose.yml`), a
systemd deployment has no such binding built in — `echidra-api.service`
listens on `0.0.0.0:8000` by default, same as the four honeypot ports.
After starting the services, restrict dashboard access to localhost only
at the firewall:

```bash
# ufw
sudo ufw deny 8000
sudo ufw allow 2222
sudo ufw allow 8080
sudo ufw allow 2121
sudo ufw allow 2323
```

Access the dashboard remotely via SSH tunnel as described above.

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
