# Echidra — Deception Platform & Attacker Behavior Classifier

![Echidra open-source deception platform and attacker behavior classifier banner.](assets/qyleron-cyber-deception-banner.png)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

Echidra is an open-source deception platform and threat-intelligence engine,
built around multi-protocol honeypot listeners, that simulates attacker-facing
SSH, HTTP, FTP, and Telnet services, captures real attacker behavior,
classifies it against MITRE ATT&CK techniques, and surfaces the result in a
web dashboard — without ever executing real commands or exposing real data.

**[Docs & full setup guide](https://qyleron.com/setup-and-onboarding/) · [Console guide](https://qyleron.com/console-guide/)**

<br />

![Echidra Intelligence dashboard aggregating recurring attacker sessions by actor profile and MITRE ATT&CK technique.](assets/echidra-oss-issue-intelligence-dashboard.gif)

---

## Why Echidra

Nobody legitimate touches a decoy, so an Echidra alert is worth reading.
Instead of raw logs, you get **findings**: attacker sessions grouped by
behavior, mapped to MITRE ATT&CK, each with a recommended fix. Every
classification traces back to a YAML rule you can read and change. It's one
install, light enough for a small VPS, and it exports attacker IPs straight
into your firewall.

| | Echidra | T-Pot | Cowrie | Thinkst Canary |
|---|---|---|---|---|
| What you get | Findings with ATT&CK techniques and fixes | Kibana dashboards and attack map over many honeypots | Very realistic SSH/Telnet session logs | Polished alerting on many decoy services |
| Protocols | SSH, HTTP, FTP, Telnet | 20+ honeypots | SSH, Telnet | Many services |
| Footprint | ~50 MB RAM at idle for decoys + dashboard, PostgreSQL separate ([measured](#benchmarks)) | Elastic stack, several GB of RAM | Light | Hardware, VM or cloud decoys with a hosted console |
| Detection logic | Readable YAML rules | Per-honeypot tools | Log output for your own tooling | Closed |
| Price | Free, open source (AGPL) | Free, open source | Free, open source | Commercial |

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
- **Blocklist export** — `echidra blocklist` or Analytics → Export Blocklist lists attacker IPs for your firewall, fail2ban, or Cloudflare

See the [Console guide](https://qyleron.com/console-guide/) for a full field-by-field reference.

## Quick Start

### Method A: Native (Recommended for trying it out)

```bash
pip install -e .    # installs Echidra + puts the `echidra` command on your PATH
echidra init         # creates .env, generates ECHIDRA_INGEST_API_KEY, initializes the schema
echidra start        # runs the honeypot listeners and the API/dashboard together until Ctrl+C
```

### Method B: Docker Compose

Set `ECHIDRA_DB_PASSWORD`, `ECHIDRA_INGEST_API_KEY`, and `ECHIDRA_SESSION_SECRET` in a `.env` file (see [docker-compose.yml](docker-compose.yml) for the full list of environment variables), then:

```bash
docker compose up -d
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
production systems; `echidra blocklist` only exports a list for you to apply.

## Benchmarks

Reproduce the load test used in the demo video and blog post yourself.

Terminal 1, watch CPU and RSS on the honeypot and classifier processes. If
Echidra was started with `echidra start`, this reads its PIDs automatically
from `logs/echidra.pid`:

```bash
./benchmarks/monitor.sh
```

Running under systemd, Docker, or anything else that doesn't write that
pidfile? Pass the PIDs directly instead:

```bash
./benchmarks/monitor.sh <honeypot_pid>,<classifier_pid>
```

Terminal 2, run the flood:

```bash
pip install aiohttp
python3 benchmarks/flood_test.py
```

Reference result from our own run, on an idle instance with no internet
exposure, using the default 100 req/s for 10 seconds:

| | Honeypot RSS | Total RSS (honeypot + API) |
|---|---|---|
| Before the flood | 24 MB | 50 MB |
| After the flood | 133 MB | 156 MB |

RSS steps up once on first traffic, then stays flat: two further floods added
about 60 KB each. No restarts.

CPU is bursty, not flat. Each request becomes a full session that is
classified and stored, so the honeypot's CPU spiked to a peak of about 135%
(more than one core) for roughly a second, then rose and fell repeatedly for
about 79 seconds while it worked through the backlog, and returned to idle
(0 to 1%). That was on a VirtualBox VM; on a single-vCPU host the peak is
capped at 100% and the backlog takes longer to clear. Actual numbers depend on
your hardware; this reproduces the methodology, not a guaranteed result.

Running under Docker Compose instead? Use `docker stats` to watch the same
two containers' CPU/memory while `flood_test.py` runs.

Full writeup: [Defending Against Automated Botnet Floods Without Degrading
Container CPU Footprints](https://qyleron.com/blog/defending-botnet-floods-container-cpu/)

## Tech Stack

Python 3.11 (`asyncio`) · FastAPI · YAML rule engine · Pydantic · PostgreSQL
(optional) · `geoip2fast` · HTML/CSS/JS dashboard

## Get in Touch

Found a bug or have a feature request? See [ISSUES.md](ISSUES.md) for how to
report it. Otherwise, follow [@qyleron](https://x.com/qyleron) on X, or
[contact us](https://qyleron.com/contact) with questions.

## License

Licensed under AGPLv3. See [LICENSE.md](./LICENSE.md) for details.
