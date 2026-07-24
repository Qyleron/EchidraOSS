# Echidra — Multi-Protocol Honeypot

![image](assets/Qyleron_Banner.png)

Echidra is a deceptive honeypot that simulates attacker-facing systems, captures
attacker behavior across four protocols, classifies it, and surfaces the
result in a web dashboard — without ever executing real commands or exposing
real data.

---

## What Is Echidra?

Echidra pretends to be a Linux server. Attackers connect over SSH-style TCP,
HTTP, FTP, or Telnet and see a believable, persona-driven system: real-looking
banners, users, files, running processes, and (for the shell) an interactive
fake command set — `ls`, `cat`, `whoami`, `ps`, `netstat`, and more. Nothing
they type touches the real host or filesystem.

Every completed session is logged, classified (actor type, risk, MITRE ATT&CK
technique, intent), geolocated, and stored in PostgreSQL for review in the
dashboard.

---

## Features

**Honeypot listeners**
- SSH-style interactive fake shell (TCP, asyncio) — persona-backed banners,
  users, fake filesystem, decoy files, and process list
- HTTP — fake Apache/nginx/WordPress/phpMyAdmin pages, captures paths, headers,
  and POST bodies (credential-harvesting probes)
- FTP — vsFTPd-style banner, captures `USER`/`PASS` attempts
- Telnet — Mirai-style login prompt, captures credential attempts
- Each listener can be enabled/disabled globally by setting its port env var

**Classification**
- Deterministic, editable YAML rules (`classifier/rules/default_rules.yaml`)
  turn session features into an actor label (e.g. `automated_scanner`,
  `brute_force_bot`, `skilled_human_operator`), confidence, risk score/level,
  behavior stage, intent, and MITRE ATT&CK tags
- Timing-based signals (inter-command intervals, commands/minute) distinguish
  scripted bots from slower, interactive human operators
- A knowledge-base lookup (`classifier/rules/issue_playbook.yaml`) turns each
  `(actor, technique)` pair into a recommended fix shown on the Intelligence
  page — unmapped pairs still surface with a generic fix, so new behavior is
  never silently dropped
- Offline IP → country resolution (`geoip2fast`) for the map view

**Storage & API**
- PostgreSQL schema for sessions, session events, classifier runs/signals,
  manual labels, issues, persona configs, and alert config/events
- Sessions are always written to `logs/sessions.jsonl` regardless of
  database configuration — PostgreSQL enables the dashboard, live alerts,
  and fast cross-session queries
- FastAPI backend serves the classifier endpoints and the dashboard itself

**Dashboard** (`/dashboard`, behind signup/login)
- **Sessions** — captured session list and detail view
- **Analytics** — aggregate charts across all captured traffic
- **Intelligence** — recurring-issue rollup with recommended fixes, MITRE tags,
  and open/closed status
- **Personas** — per-persona identity, fake users, decoy files, alert routing,
  and per-persona analytics
- **Alerts** — global SMTP config, send-test-email, and alert event history

---

## Prerequisites (local machine)

You need Python 3.11+ and, for the dashboard/API/alerts, a local PostgreSQL
server. The honeypot itself runs and logs to `logs/sessions.jsonl` without a
database — Postgres only unlocks the dashboard, live classification storage,
and alerts. Skip straight to [Quick Start](#quick-start) if you already have
Postgres running and a database created.

Both platforms below create a dedicated `echidra` Postgres role, scoped to
just owning its own `echidra` database — not a superuser, since the
application only ever needs to create/alter its own tables, never
cluster-wide admin rights.

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt install -y postgresql
sudo -u postgres createuser echidra
sudo -u postgres psql -c "ALTER ROLE echidra WITH PASSWORD 'echidra';"
sudo -u postgres createdb -O echidra echidra
```

**macOS (Homebrew):**
```bash
brew install postgresql@16 && brew services start postgresql@16
createuser echidra
psql postgres -c "ALTER ROLE echidra WITH PASSWORD 'echidra';"
createdb -O echidra echidra
```

(Any password works — `echidra` above is just a placeholder; set your own and
use it in `.env` next. An explicit password, rather than relying on
peer/trust auth, avoids connection failures that vary by how your local
`pg_hba.conf` is configured.)

**Set up `.env`:**
```bash
cp .env.example .env
```
Open `.env` and check only the *uncommented* `ECHIDRA_DATABASE_URL` line if
`.env.example` also left a commented-out example above it — `dotenv` ignores
commented lines, so a stray uncommented placeholder is easy to miss and
silently wrong. With the role/database above, it should read:
```
ECHIDRA_DATABASE_URL=postgresql://echidra:echidra@localhost:5432/echidra
```
(matching `.env.example`'s own commented default exactly, if you used the same
password). Everything else in `.env.example` has a working default — leave it
as-is for a first run.

---

## Quick Start

A handful of commands, no need to know the underlying modules:

```bash
pip install -e .   # installs Echidra + puts the `echidra` command on your PATH
echidra help         # lists every subcommand (init/serve/stop/classify/status) with its own --help
echidra init        # creates .env, generates ECHIDRA_INGEST_API_KEY, initializes the schema (if ECHIDRA_DATABASE_URL is set)
echidra serve        # runs the honeypot listeners and the API/dashboard together until Ctrl+C
echidra status       # in a second shell: confirms listeners/API/database are actually up and reports session counts
echidra stop         # in a second shell: stops a `serve`
```

Then open **http://localhost:8000** in your browser — it takes you straight
to the dashboard (sign up on first visit).

**Only the first signup succeeds.** Echidra is single-operator by default —
once one dashboard account exists, signup closes (403 for anyone else) so an
internet-reachable instance doesn't stay open to public registration. Use
Login for that account from then on; see `ECHIDRA_ALLOW_SIGNUPS` in
`.env.example` if you deliberately want more than one dashboard user.

No PostgreSQL yet? `echidra init` skips the database step and tells you so;
the honeypot still runs and logs to `logs/sessions.jsonl`, you just won't get
the dashboard/API or live alerting until `ECHIDRA_DATABASE_URL` is set in
`.env` and you re-run `echidra init`.

### Resetting your local database

To wipe all captured data and rebuild the schema fresh from
[`classifier/storage/schema.sql`](classifier/storage/schema.sql) (useful after
pulling schema changes, or if your local data just needs a clean slate):
```bash
dropdb echidra
createdb echidra
echidra init   # re-creates every table
```
Add `--seed-demo-issues` only if you're manually testing the Intelligence
page and want its 4 synthetic issues to check against (see
[docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md)) — skip it for normal use, or
those fabricated issues will sit in your dashboard next to real captured
data with nothing distinguishing them as fake.
`echidra init`'s schema step (and every statement in `schema.sql`) is
idempotent, so you can also re-run just `echidra init` at any time against an
existing, populated database to pick up new columns/tables without losing
data — only `dropdb`/`createdb` above actually discards anything.

**JSONL-only mode (no Postgres)?** Classify captured sessions on demand:

    echidra classify logs/sessions.jsonl

This prints classifier output — actor label, risk, MITRE tags, evidence —
for every session in the file. Add `--output reports/out.jsonl` to write
results to a file instead of stdout. Note this only classifies and prints —
it does not write to PostgreSQL, so sessions captured before you set up a
database won't retroactively appear in the dashboard once you add one.

Want to run each service manually (its own terminal, `--reload` for API
development, only one listener at a time)? See the prereqs block at the top
of [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md#manual-testing-guide).

### Deployment options

Three supported paths — pick the one that matches where this is running:

| Path | Best for | How |
|---|---|---|
| **Local machine** | Trying it out, day-to-day development | The Quick Start above (`echidra` CLI), or run each service in its own terminal per [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md#manual-testing-guide) |
| **Docker Compose** | A self-contained stack (honeypot + API + Postgres) on any machine with Docker | [docs/DEPLOYMENT.md#docker-compose](docs/DEPLOYMENT.md#docker-compose) |
| **systemd (bare VM)** | A long-running deployment on a VM you administer directly, without Docker | [docs/DEPLOYMENT.md#systemd-bare-vm](docs/DEPLOYMENT.md#systemd-bare-vm) |

All three read the same `.env` file and produce the same `logs/sessions.jsonl` —
switching between them later doesn't require re-architecting anything.

Default listeners:

| Protocol | Port | Env override |
|---|---|---|
| SSH-style shell | 2222 | `ECHIDRA_PORT` |
| HTTP | 8080 | `ECHIDRA_HTTP_PORT` |
| FTP | 2121 | `ECHIDRA_FTP_PORT` |
| Telnet | 2323 | `ECHIDRA_TELNET_PORT` |

Set any protocol port to `0` to disable that listener. Pick a persona with
`ECHIDRA_PERSONA=ubuntu_web_server` set before `echidra serve` (or
`python -m honeypot.main`).

Signup is only open until the first dashboard account exists — after that it
returns 403 unless you set `ECHIDRA_ALLOW_SIGNUPS=true`, so a self-hosted
instance doesn't stay open to public registration forever. `POST
/classify/session/store` (the only write-and-alert-capable classifier
endpoint) similarly refuses all requests until you set
`ECHIDRA_INGEST_API_KEY` and send it back as the `X-Api-Key` header —
`echidra init` generates this for you; see `.env.example` if you're setting
it up manually. See [CONTEXT.md](CONTEXT.md) for current build status and
architecture notes, [docs/CONCEPTS.md](docs/CONCEPTS.md) for the core domain
model (persona, session, classification, issues, alerts), and
[docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) for per-service and per-page
manual test commands.

**Troubleshooting**
- `echidra: command not found` — your PATH doesn't include the environment
  `pip install -e .` installed into. Activate that virtualenv first, or run
  the CLI as `python -m echidra` instead.
- `echidra status` shows a listener/API as unreachable — check the other
  shell running `echidra serve` for a traceback; a common cause is a port in
  the table above already being in use, often a previous `echidra serve`
  that's still running (e.g. its terminal was closed instead of Ctrl+C'd).
  Run `echidra stop` to stop it. Otherwise, use `ss -tulnp | grep <port>` to
  identify the PID and terminate it only if it is the stale Echidra process.
  If it's a `docker compose` stack rather than a stale process, see the
  "run only one deployment path at a time" note in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
- Working in a remote VS Code session (Remote-SSH, WSL, Codespaces, a dev
  container)? This workspace turns off `remote.autoForwardPorts` (see
  `.vscode/settings.json`), so port 8000 won't auto-forward to your local
  machine. Forward it yourself: `Ctrl+Shift+P` → "Forward a Port" → `8000`,
  then open the forwarded URL VS Code gives you in the Ports panel.

---

## One persona at a time

Echidra runs **one active persona** at a time — set it with
`ECHIDRA_PERSONA=ubuntu_web_server` before `echidra serve`. The five
presets visible in the dashboard are configuration choices, not five
simultaneous honeypots.

To capture different attack profiles in parallel, run Echidra on
multiple servers, each with a different persona, all pointing at the
same `ECHIDRA_DATABASE_URL`. The dashboard aggregates sessions from
all of them, tagged by `persona_id`, so you can compare attack
patterns across personas in the Analytics and Intelligence pages.

---

## Safety Model

Echidra never runs attacker input on the host. Shell commands, HTTP requests,
FTP/Telnet credentials are parsed and answered with fake, persona-scoped data
only — files, directory listings, and process lists are reconstructed from an
in-memory persona, never the real filesystem. Echidra recommends safeguarding
actions (rate-limiting, alerting, credential rotation) but never itself blocks
IPs, changes firewalls, or touches production systems.

---

## Tech Stack

| Component | Stack |
|---|---|
| Honeypot runtime | Python 3.11, `asyncio` |
| Classifier API | FastAPI |
| Rule engine | YAML |
| Schemas | Pydantic |
| Storage | PostgreSQL (optional — JSONL always written) |
| Geolocation | `geoip2fast` (offline) |
| Dashboard | HTML, CSS, JavaScript |

---

## Folder Structure

```text
echidra_oss/
├── honeypot/
│   ├── main.py                  # starts all four listeners
│   ├── network/
│   │   ├── ssh_server.py        # real SSH listener (asyncssh)
│   │   ├── ssh_keys.py          # persistent SSH host key
│   │   ├── protocol_server.py   # generic listener used by http/ftp/telnet
│   │   ├── http_handler.py
│   │   ├── ftp_handler.py
│   │   ├── telnet_handler.py
│   │   └── config.py
│   ├── logging/session_logger.py
│   └── core/
│       ├── persona.py
│       ├── session.py
│       └── engine.py            # fake shell command dispatcher
├── classifier/
│   ├── api/app.py               # FastAPI app: classifier + dashboard routes
│   ├── schemas/session.py
│   ├── features/session.py
│   ├── rules/                   # default_rules.yaml, issue_playbook.yaml
│   ├── scoring/session.py
│   └── storage/                 # repository, schema.sql, geolocation.py
├── dashboard/public/             # sessions/analytics/intelligence/personas/alerts.html
├── echidra/cli.py                # `echidra` console script: init/serve/stop/classify/status
├── deploy/systemd/               # echidra-honeypot.service, echidra-api.service
├── tests/
├── docs/
├── assets/
├── docker-compose.yml
├── README.md
├── SECURITY.md
└── LICENSE.md
```

---

## Get in Touch

Follow [@qyleron](https://x.com/qyleron) on X (formerly Twitter).

If you have a specific question, [contact](https://qyleron.com) us.

---

## License

This project is licensed under the AGPLv3 License. See [LICENSE.md](./LICENSE.md) for details.
