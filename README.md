# Echidra - Multi-Protocol Honeypot

![image](assets/Qyleron_Banner.png)

Echidra is a deceptive honeypot project built to simulate attacker-facing systems, capture behavior, and support explainable threat analysis.

The current version is a Python-based proof of concept: a fake Linux terminal over TCP with personas, fake files, fake command responses, per-session state, and tests. The next major milestone is a Behavioral Classifier that labels attacker sessions using timing, command behavior, protocol activity, and rule-based evidence.

---

## What Is Echidra?

Echidra pretends to be a Linux server.

When someone connects, they see a believable shell prompt. They can type commands like `whoami`, `pwd`, `ls`, `cat`, `ps`, or `netstat`, but Echidra never executes real system commands and never exposes real files.

Instead, Echidra returns controlled fake responses from an in-memory persona and records what the visitor does during the session.

Think of it as a controlled fake terminal for safely observing attacker behavior.

---

## Current Status

Echidra currently includes:

- Async TCP honeypot server using Python `asyncio`
- Per-client connection handling
- Persona-based fake Linux identities
- Fake banners, hostnames, users, files, processes, and ports
- Fake shell command handling
- Per-session command history and state
- Path normalization for Linux-like file access
- Timeout, disconnect, and graceful shutdown behavior
- Unit, integration, stability, and basic concurrency tests

Next major upgrade:

- Persistent structured logging of attacker sessions
- Behavioral Classifier for bot-versus-human and intent analysis

---

## Architecture

![image](https://github.com/user-attachments/assets/b57a0de5-6696-435b-845f-87c1f82f0bfc)

Current honeypot flow:

```text
attacker
  -> TCP server
  -> ConnectionHandler
  -> Persona
  -> SessionState
  -> InteractionEngine
  -> fake Linux response
```

Planned intelligence flow:

```text
raw honeypot events
  -> canonical session schema
  -> feature extraction
  -> YAML rule evaluation
  -> actor vote aggregation
  -> behavior stage and intent mapping
  -> MITRE mapping
  -> risk scoring
  -> evidence generation
  -> API response and database storage
```

---

## Core Features

### Implemented

- Fake Linux shell over TCP
- Multiple personas such as generic Linux and Ubuntu-style hosts
- Fake filesystem backed by controlled in-memory data
- Safe command simulation without executing real shell commands
- Session-specific state for each connected visitor
- Basic support for concurrent clients
- Test coverage for core behavior and TCP interaction

### Planned

- Persistent structured logs
- SSH, Telnet, FTP, and HTTP honeypot services
- FastAPI Behavioral Classifier service
- PostgreSQL storage for sessions, classifier runs, and manual labels
- Dashboard and reporting views
- Local alerts through SMTP or webhooks
- Docker/systemd deployment support

---

## Behavioral Classifier Plan

The Echidra Behavioral Classifier will be an explainable, rule-driven intelligence layer for classifying attacker sessions.

The first version will focus on bot-versus-human classification using:

- Inter-keystroke timing
- Authentication behavior
- Command patterns
- Protocol activity
- File and network events
- Risk indicators

Runtime modes:

| Mode | Purpose | Trigger |
|---|---|---|
| Real-time classifier | Immediate alerts and adaptive deception decisions | Every 30 seconds during active sessions |
| Post-session classifier | Full intelligence, evidence, reporting, and dataset labeling | After session close |

Planned actor labels:

- `automated_scanner`
- `brute_force_bot`
- `commodity_bot`
- `script_kiddie`
- `skilled_human_operator`

Classifier output will include:

- Session ID and protocol
- Actor type and confidence
- Behavior stage and intent
- Risk score and risk level
- MITRE tags
- Plain-English evidence
- Recommended action
- Feature summary
- Matched rules

---

## Tech Stack

| Component | Stack |
|---|---|
| Honeypot runtime | Python 3.11, `asyncio` |
| Fake shell engine | Python |
| Classifier API | FastAPI, planned |
| Rule engine | YAML rules, planned |
| Schemas | Pydantic, planned |
| Storage | PostgreSQL + JSONB, planned |
| Dashboard | HTML, CSS, JavaScript, D3.js, planned |
| Deployment | Docker Compose or systemd, planned |

---

## Folder Structure

Current/planned structure:

```text
echidra_oss/
├── honeypot/
│   ├── main.py
│   ├── network/
│   │   ├── server.py
│   │   ├── connection.py
│   │   └── config.py
│   └── core/
│       ├── persona.py
│       ├── session.py
│       └── engine.py
├── classifier/              # planned
│   ├── schemas/
│   ├── features/
│   ├── rules/
│   ├── scoring/
│   └── api/
├── tests/
├── assets/
├── README.md
└── LICENSE.md
```

---

## Quick Start

Run the honeypot:

```bash
python -m honeypot.main
```

Connect locally:

```bash
nc 127.0.0.1 2222
```

Use a specific persona:

```bash
ECHIDRA_PERSONA=ubuntu_web_server python -m honeypot.main
```

The default listener is:

```text
host: 0.0.0.0
port: 2222
```

---

## Safety Model

Echidra does not run attacker commands on the host machine.

Commands are parsed and answered by the interaction engine. Files are fake entries from the selected persona. Directory listings are reconstructed from fake paths. This keeps the honeypot controlled while still making the attacker interaction feel realistic.

---

## Roadmap

1. Add persistent structured session logging.
2. Define the canonical session schema.
3. Build feature extraction for timing, authentication, commands, protocols, files, and network events.
4. Implement editable YAML classification rules.
5. Add risk scoring, evidence generation, and MITRE mapping.
6. Expose real-time and post-session classification through FastAPI.
7. Store classifier runs and manual labels in PostgreSQL.
8. Collect and label real sessions for evaluation.
9. Build dashboard/reporting views.

---

## License

This project is licensed under the AGPLv3 License. See [LICENSE.md](./LICENSE.md) for details.
