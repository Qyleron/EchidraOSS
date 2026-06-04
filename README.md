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
- Append-only JSONL logging for completed attacker sessions
- Serialized single-line writes for session log records
- Path normalization for Linux-like file access
- Editable YAML classification rules with deterministic matching
- Post-session classifier pipeline from session record to summary
- Raw session dict and JSONL classification helpers for ingestion
- Batch JSONL classification helpers for existing session logs
- CLI command for batch JSONL session classification
- FastAPI post-session classifier endpoint
- Risk scoring, evidence aggregation, and MITRE tag mapping for matched rules
- Behavior stage and intent mapping for classifier summaries
- Evidence-backed Safeguard Advisor recommendations for external security tools
- Timeout, disconnect, and graceful shutdown behavior
- Unit, integration, stability, and basic concurrency tests

Next major upgrade:

- Store classifier runs and manual labels in PostgreSQL

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
  -> advisory safeguard recommendations
  -> post-session classification summary
  -> API response
  -> database storage
```

---

## Core Features

### Implemented

- Fake Linux shell over TCP
- Multiple personas such as generic Linux and Ubuntu-style hosts
- Fake filesystem backed by controlled in-memory data
- Safe command simulation without executing real shell commands
- Session-specific state for each connected visitor
- Structured session logs with IDs, timing, end reasons, and command history
- YAML rule loading and matching over extracted session features
- Post-session classification pipeline using the default YAML ruleset
- Decoded session-record and JSONL-line helpers for future API/log ingestion
- Batch JSONL log classification helpers for offline analysis
- CLI support for printing classifier summaries from JSONL logs
- FastAPI endpoint for post-session classification
- Aggregated classifier summaries with risk levels, evidence, MITRE tags,
  behavior stages, intents, feature summaries, and Safeguard Advisor
  recommendations
- Basic support for concurrent clients
- Test coverage for core behavior and TCP interaction

### Planned

- SSH, Telnet, FTP, and HTTP honeypot services
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

- Classifier and rules version
- Session ID and protocol
- Actor type and confidence
- Actor vote tally
- Behavior stage and intent
- Risk score and risk level
- MITRE tags
- Plain-English evidence
- Persona context and surfaced decoy files
- Recommended action
- Feature summary
- Matched rules

### Safeguard Advisor Boundary

Echidra will recommend preventive and safeguarding actions with supporting
evidence. It will not directly block IP addresses, modify firewalls, disable
accounts, or change production systems.

External tools such as firewalls, WAFs, SIEM/SOAR platforms, IAM systems, and
ticketing tools remain responsible for executing approved actions.

---

## Structured Session Logs

Echidra appends one JSON object per completed connection to:

```text
logs/sessions.jsonl
```

Set `ECHIDRA_SESSION_LOG` to use a different path. JSON Lines keeps each
session independently readable and makes the file easy to stream into the
planned classifier or an external ingestion tool.

Each record includes:

- `schema_version`, `session_id`, and `protocol`
- `peer_ip`, `peer_port`, and `persona_id`
- `started_at`, `ended_at`, and `duration_seconds`
- `end_reason`: `logout`, `timeout`, `disconnect`, `shutdown`, or `error`
- `command_count` and timestamped `commands`
- `decoy_files_surfaced`: unique fake files exposed through successful reads or listings

Before persistence, each completed record is validated against the canonical
Pydantic contract in `classifier/schemas/session.py`. The v1 contract rejects
unknown fields, invalid lifecycle reasons, mismatched command counts, and
timestamps that fall outside the session window. Surfaced decoys must be
unique safe absolute paths.

---

## Session Features

The deterministic extractor in `classifier/features/session.py` converts each
validated TCP shell session into measurements for later rules and scoring:

- Session duration, command count, and commands per minute
- Inter-command intervals and their average
- Unique and repeated command counts
- Discovery command count
- File-read and sensitive-path-read counts
- Surfaced decoy paths and their count for persona-aware reporting
- Exit-command presence and normalized command names

Rule evaluation and scoring assign initial actor labels, risk levels, evidence,
MITRE tags, actor vote tallies, behavior stage, intent, version metadata, and
persona context from these features. The scoring summary includes a compact
feature summary for API and storage consumers. It also emits advisory,
evidence-backed Safeguard Advisor recommendations for external tools such as
SIEM/SOAR platforms, firewalls, WAFs, IAM systems, and ticketing systems.
The `classifier.pipeline.classify_session` helper runs the full post-session
path from a validated session record through feature extraction, rule
evaluation, and scoring. `classify_session_record` and `classify_session_jsonl`
validate raw ingestion input before running that same path. Batch helpers can
classify many JSONL lines or a whole session log file. The same batch path is
available from the command line:

```bash
python -m classifier.cli classify-jsonl logs/sessions.jsonl
```

Write summaries to a file:

```bash
python -m classifier.cli classify-jsonl logs/sessions.jsonl --output reports/classifier-runs.jsonl
```

If a historical log contains malformed JSONL, the CLI reports the bad line
number and exits without a traceback.

The post-session API exposes the same classifier contract over HTTP:

```bash
uvicorn classifier.api:app --reload
```

```text
POST /classify/session
```

The request body is the canonical completed session record, and the response is
the classifier summary used by CLI and storage consumers.

See [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md) for the current build plan,
status, next steps, and simplest end-to-end flow.

---

## Tech Stack

| Component | Stack |
|---|---|
| Honeypot runtime | Python 3.11, `asyncio` |
| Fake shell engine | Python |
| Classifier API | FastAPI |
| Rule engine | YAML rules |
| Schemas | Pydantic |
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
│   ├── logging/
│   │   └── session_logger.py
│   └── core/
│       ├── persona.py
│       ├── session.py
│       └── engine.py
├── classifier/              # planned
│   ├── schemas/
│   │   └── session.py
│   ├── features/
│   │   └── session.py
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

1. Add persistent structured session logging. **Implemented**
2. Define the canonical session schema. **Implemented**
3. Build feature extraction for timing, authentication, commands, protocols, files, and network events. **TCP shell foundation implemented**
4. Implement editable YAML classification rules. **Implemented**
5. Add risk scoring, evidence generation, and MITRE mapping. **Implemented**
6. Add Safeguard Advisor recommendations for external security tools.
7. Expose real-time and post-session classification through FastAPI. **Post-session API implemented**
8. Store classifier runs and manual labels in PostgreSQL.
9. Collect and label real sessions for evaluation.
10. Build dashboard/reporting views.

---

## License

This project is licensed under the AGPLv3 License. See [LICENSE.md](./LICENSE.md) for details.
