# Core Concepts

This document explains Echidra's core domain model — what the pieces mean and
how they fit together. For "how do I run this" see the
[README](../README.md); for "how do I manually test page X" see
[TESTING_GUIDE.md](TESTING_GUIDE.md).

---

## Persona

A persona is the fake machine identity an attacker sees: hostname, OS/SSH
banners, uname string, login user + home directory, fake filesystem, visible
`running_processes`/ports, SUID binaries, decoy credentials, and
`http_server_type` (which fake web server the HTTP listener presents —
`"none"` makes it reject all requests).

Five presets are hardcoded `Persona` dataclasses. At runtime,
`get_active_persona()` reads `ECHIDRA_PERSONA` (default `generic_linux`),
first tries to build a `Persona` from a dashboard-saved `persona_configs`
row, and falls back to the hardcoded preset if no matching DB row exists (or
no database is configured).

The dashboard's `PersonaConfigInput` is a narrower, analyst-editable subset
of a persona — banners, hostname, users, processes, `http_server_type`,
decoy files, plus alert settings (see [Alerts](#alerts) below). Real login
identity, SUID binaries, and credentials stay fixed at the DB persona's
defaults, since the config schema doesn't capture them yet.

- `honeypot/core/persona.py` — `Persona`, `PRESET_PERSONAS`, `get_persona()`
- `honeypot/network/config.py` — `get_active_persona()`,
  `_load_persona_from_db()`, `_persona_from_config_record()`
- `classifier/storage/models.py` — `PersonaConfigInput`

Echidra runs **one active persona at a time** per running instance — see
"One persona at a time" in the [README](../README.md) for how to capture
multiple persona profiles in parallel.

---

## Session

A `SessionState` is one connected client's live interaction: peer address,
persona used, start/end time and reason, command log, current working
directory, and which decoy files were surfaced to it.

On completion, `to_record()` produces a dict validated into a
`SessionRecord` — schema version, protocol (`tcp_shell`/`http`/`ftp`/
`telnet`), peer ip/port, persona id, timing, end reason, commands, and
decoy files surfaced — with validators that catch inconsistent ordering,
mismatched durations, and duplicate decoy paths.

`SessionLogger.log()` appends the record as a line to `logs/sessions.jsonl`
(mode `0600`, since it may contain captured credentials). This file is
always written regardless of database configuration. `finalize_and_schedule()`
then schedules auto-classification, which is what writes the session into
PostgreSQL — a session captured before a database was configured will not
retroactively appear in the dashboard once one is added.

- `honeypot/core/session.py` — `SessionState.to_record()`
- `classifier/schemas/session.py` — `SessionRecord`, `CommandEvent`
- `honeypot/logging/session_logger.py` — `SessionLogger.log()`,
  `finalize_and_schedule()`

---

## Classification

Classification turns a raw session into an actor label, risk score/level,
behavior stage, intent, and MITRE ATT&CK tags — deterministically, not via a
model call.

1. `classifier/features/session.py` turns a `SessionRecord` into numeric/
   boolean `SessionFeatures` — commands per minute, discovery-command count,
   sensitive-file reads, decoy exposure, exit-command presence, a
   human-timing score.
2. `classifier/rules/default_rules.yaml` declares conditions over those
   features; each rule is tagged with an actor label, risk score, MITRE
   tags, and evidence text. Matching rules produce `RuleMatch`es.
3. `classifier/scoring/session.py`'s `summarize_rule_evaluation()` combines
   matches into a `ClassificationSummary` — combined risk score/level,
   actor label (by vote), behavior stage, intent, and recommended
   deception/alert actions.

Rules are plain YAML, so new actor patterns can be added without touching
scoring logic.

- `classifier/features/session.py`
- `classifier/rules/default_rules.yaml`, `classifier/rules/engine.py` —
  `load_rules()`, `evaluate_rules()`
- `classifier/scoring/session.py` — `summarize_rule_evaluation()`

---

## Issue rollup

The Intelligence page doesn't show individual sessions — it shows recurring
*issues*, one per `(actor_label, MITRE technique)` pair, each with a
recommended fix.

`classifier/rules/issue_playbook.yaml` maps an `(actor, technique)` pair to
a title, recommended fix, and impact (falling back to a generic entry if the
pair isn't catalogued). `sync_issues_from_classifier_runs()` aggregates
stored classifier runs by that pair, looks up the playbook entry, and
upserts an `IssueRecord` with a deterministic id — so re-running sync
refreshes counts without resetting an analyst's open/closed status. A
second pass independently detects brute-force behavior from raw connection
frequency by peer IP and consolidates into the same issue id.

- `classifier/rules/issue_playbook.yaml`
- `classifier/storage/issue_sync.py` — `sync_issues_from_classifier_runs()`

---

## Alerts

Alerts have two layers: a **global** SMTP config, and **per-persona**
routing on top of it.

Global SMTP config (host, port, credentials, from-email, TLS) is set once
via the Alerts page (`PUT /alerts/config`). Per-persona settings on
`PersonaConfigInput` — `alert_routing_level` (`none`/`email`/`slack`/`both`)
and `alert_min_risk_level` — gate whether and when *that persona's*
classifications trigger an alert at all; they're edited on the Personas
page, inside a given persona's modal, not on the Alerts page.

At classification time, the alert trigger point skips sending if routing is
`none`, computes the effective risk threshold from the persona's
`alert_min_risk_level` (falling back to the global default), and — if the
session's risk meets that threshold — dispatches by email (needs
`contact_email` plus the global SMTP host) and/or Slack (needs
`slack_webhook`), recording the result as an alert event.

- `classifier/storage/models.py` — `PersonaConfigInput.alert_routing_level`,
  `alert_min_risk_level`
- `classifier/alerts.py` — alert dispatch (SMTP/Slack)
- `classifier/api/app.py` — alert config and test-send endpoints
