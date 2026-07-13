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
- Every listener can be enabled/disabled and given its own port per persona

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
- FastAPI backend serves the classifier endpoints and the dashboard itself

**Dashboard** (`/dashboard`, behind signup/login)
- **Sessions** — captured session list and detail view
- **Analytics** — aggregate charts across all captured traffic
- **Intelligence** — recurring-issue rollup with recommended fixes, MITRE tags,
  and open/closed status
- **Personas** — per-persona identity, services/ports, fake users, decoy
  files, alert routing, interaction depth, and per-persona analytics
- **Alerts** — global SMTP config, send-test-email, and alert event history

---

## Quick Start

Four commands, no need to know the underlying modules:

```bash
pip install -e .   # installs Echidra + puts the `echidra` command on your PATH
echidra init        # creates .env, generates ECHIDRA_INGEST_API_KEY, initializes the schema (if ECHIDRA_DATABASE_URL is set)
echidra serve        # runs the honeypot listeners and the API/dashboard together until Ctrl+C
echidra status       # in a second shell: confirms listeners/API/database are actually up and reports session counts
```

Then open **http://localhost:8000** in your browser — it takes you straight
to the dashboard (sign up on first visit).

No PostgreSQL yet? `echidra init` skips the database step and tells you so;
the honeypot still runs and logs to `logs/sessions.jsonl`, you just won't get
the dashboard/API or live alerting until `ECHIDRA_DATABASE_URL` is set in
`.env` and you re-run `echidra init`.

Want to run each service manually (its own terminal, `--reload` for API
development, only one listener at a time)? See the prereqs block at the top
of [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md#manual-testing-guide). For a
Docker Compose stack or a systemd deployment on a VM, see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

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
architecture notes, and [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) for
per-service and per-page manual test commands.

**Troubleshooting**
- `echidra: command not found` — your PATH doesn't include the environment
  `pip install -e .` installed into. Activate that virtualenv first, or run
  the CLI as `python -m echidra` instead.
- `echidra status` shows a listener/API as unreachable — check the other
  shell running `echidra serve` for a traceback; a common cause is a port in
  the table above already being in use.

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
| Storage | PostgreSQL |
| Geolocation | `geoip2fast` (offline) |
| Dashboard | HTML, CSS, JavaScript |

---

## Folder Structure

```text
echidra_oss/
├── honeypot/
│   ├── main.py                  # starts all four listeners
│   ├── network/
│   │   ├── server.py            # SSH-style shell listener
│   │   ├── protocol_server.py   # generic listener used by http/ftp/telnet
│   │   ├── connection.py
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
├── tests/
├── docs/
├── assets/
├── README.md
└── LICENSE.md
```

---

## License

This project is licensed under the AGPLv3 License. See [LICENSE.md](./LICENSE.md) for details.
