# Echidra — Multi-Protocol Honeypot & Attacker Behavior Classifier

![image](assets/Qyleron_Banner_README.png)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

Echidra is an open-source deceptive honeypot and threat-intelligence platform
that simulates attacker-facing SSH, HTTP, FTP, and Telnet services, captures
real attacker behavior, classifies it against MITRE ATT&CK techniques, and
surfaces the result in a web dashboard — without ever executing real commands
or exposing real data.

**[Docs & full setup guide](https://qyleron.com/setup-and-onboarding/) · [Dashboard guide](https://qyleron.com/console-guide/)**

---

## What Is Echidra?

Echidra pretends to be a Linux server. Attackers connect over SSH-style TCP,
HTTP, FTP, or Telnet and see a believable, persona-driven system: real-looking
banners, users, files, running processes, and (for the shell) an interactive
fake command set. Nothing they type touches the real host or filesystem.

Every completed session is logged, classified (actor type, risk, MITRE ATT&CK
technique, intent), geolocated, and stored in PostgreSQL — or `logs/sessions.jsonl`
if PostgreSQL isn't configured — for review in the dashboard.

## Features

- **Honeypot listeners** — SSH-style fake shell, HTTP (fake Apache/nginx/WordPress/phpMyAdmin), FTP, and Telnet, each independently enabled/disabled by port
- **Classification** — deterministic YAML rules turn session features into an actor label, risk score, behavior stage, intent, and MITRE ATT&CK tags, plus a knowledge-base of recommended fixes
- **Storage & API** — PostgreSQL schema for sessions/events/classifier runs, always mirrored to `logs/sessions.jsonl`; FastAPI backend serves the classifier endpoints and dashboard
- **Dashboard** — Intelligence (recurring issues + fixes), Sessions, Analytics, Personas, and Alerts (email/Slack)

See the [Dashboard guide](https://qyleron.com/console-guide/) for a full field-by-field reference.

## Quick Start

```bash
pip install -e .    # installs Echidra + puts the `echidra` command on your PATH
echidra init         # creates .env, generates ECHIDRA_INGEST_API_KEY, initializes the schema
echidra start        # runs the honeypot listeners and the API/dashboard together until Ctrl+C
```

Open **http://localhost:8000** — it takes you straight to the dashboard (sign
up on first visit; only the first signup succeeds by default).

No PostgreSQL yet? `echidra init` skips the database step and tells you so —
the honeypot still runs and logs to `logs/sessions.jsonl` without it.

For PostgreSQL setup, `.env` configuration, Docker Compose / systemd
deployment, and troubleshooting, see the full
**[Setup Guide](https://qyleron.com/setup-and-onboarding/)**.

## Safety Model

Echidra never runs attacker input on the host. Shell commands, HTTP requests,
and FTP/Telnet credentials are parsed and answered with fake, persona-scoped
data only, reconstructed from an in-memory persona, never the real
filesystem. Echidra never itself blocks IPs, changes firewalls, or touches
production systems.

## Tech Stack

Python 3.11 (`asyncio`) · FastAPI · YAML rule engine · Pydantic · PostgreSQL
(optional) · `geoip2fast` · HTML/CSS/JS dashboard

## Get in Touch

Follow [@qyleron](https://x.com/qyleron) on X, or
[contact us](https://qyleron.com/contact) with questions.

## License

Licensed under AGPLv3. See [LICENSE.md](./LICENSE.md) for details.
