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
no database is configured). The persona is loaded once before the decoys
start and refreshed in the background, so a dashboard edit applies within a
short while; if the database can't be reached, the decoys keep the persona
they already have.

The dashboard's `PersonaConfigInput` is a narrower, analyst-editable subset
of a persona — banners, hostname, users, processes, `http_server_type`,
decoy files, plus alert settings (see [Alerts](#alerts) below). A saved
persona with a preset's id keeps that preset's files, login identity, SUID
binaries and credentials, with its decoy files added on top (a decoy file
with the same path replaces the preset's). Any other saved persona starts
from a few lived-in files (`.bashrc`, `.profile`, `/etc/hostname`,
`/etc/hosts`, an `/etc/passwd` listing its users) plus its decoy files.

- `honeypot/core/persona.py` — `Persona`, `PRESET_PERSONAS`, `get_persona()`
- `honeypot/network/config.py` — `get_active_persona()`,
  `_load_persona_from_db()`, `_persona_from_config_record()`
- `classifier/storage/models.py` — `PersonaConfigInput`

Each running instance serves one active persona. To run several personas in
parallel, start one instance per persona (each with its own
`ECHIDRA_PERSONA` and ports) against the same database; the dashboard shows
them all together.

---

## Session

A `SessionState` is one connected client's live interaction: peer address,
persona used, start/end time and reason, command log, current working
directory, and which decoy files were surfaced to it.

On completion, `to_record()` produces a dict validated into a
`SessionRecord` — schema version, protocol (`tcp_shell`/`http`/`ftp`/
`telnet`), peer ip/port, persona id, timing, end reason, commands, and
decoy files surfaced, plus for SSH the client's version line and how far
the connection got (`client_version`, `end_stage`, `end_error`) — with validators that catch inconsistent ordering,
mismatched durations, and duplicate decoy paths.

`SessionLogger.log()` appends the record as a line to `logs/sessions.jsonl`
(mode `0600`, since it may contain captured credentials). This file is
always written regardless of database configuration. `finalize_and_schedule()`
then schedules auto-classification, which is what writes the session into
PostgreSQL. If the database can't be reached at that moment, the session is
also kept in `logs/pending-sessions.jsonl`, and `classifier/catch_up.py`
stores it once the database is back. Sessions still waiting to be stored
when the honeypot stops are kept there too, and stored within a minute of
the next start. A session captured before a database
was configured is stored with `echidra import logs/sessions.jsonl`.

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

Each issue's title, recommended fix and impact come from two playbooks:
`classifier/rules/mitre_playbook.yaml`, with one entry per ATT&CK
technique, and `classifier/rules/issue_playbook.yaml`, with entries for
specific `(actor, technique)` pairs (falling back to a generic entry if
neither covers the pair). `sync_issues_from_classifier_runs()` groups
classifier runs by that pair, looks up the playbook entry, and writes an
`IssueRecord` with a deterministic id, so syncing again refreshes counts
without resetting an analyst's open/closed status. A closed issue that
picks up new sessions reopens. A second check detects brute-force
behavior from raw connection frequency by peer IP and writes to the same
issue id.

The sync is incremental. Storing a classifier run also adds it to
`issue_sync_queue`, in the same transaction. Each sync pass reads only the
queued runs and merges them into each issue's stored totals:
- **Bridge tables:** `issue_sessions`, `issue_personas` and
  `issue_source_ips` hold each issue's distinct sessions, personas and
  source IPs. A count grows only by rows that weren't there yet, so
  merging the same run twice changes nothing.
- **Running values:** first and last seen, the highest risk, and the first
  five evidence samples are kept on the issue and combined with each new
  batch.

A pass costs the same however many runs are stored. Passes run in the
background, at most every 30 seconds. A Postgres advisory lock keeps the
honeypot and API processes from syncing at the same time.

The first sync on a new database, or after upgrading from a version
without the queue, rebuilds every issue from all stored runs.
`sync-issues --full` does the same rebuild on demand.

- `classifier/rules/mitre_playbook.yaml`, `classifier/rules/issue_playbook.yaml`
- `classifier/storage/issue_sync.py` — `sync_issues_from_classifier_runs()`
- `classifier/storage/repository.py` — `IssueSyncStore` and the "Issue
  sync" SQL

---

## Alerts

Alerts are set up in one place, the Alerts page (`PUT /alerts/config`):
the on/off switch, **Send alerts to** (`default_contact_email`, and
optionally `default_slack_webhook`), the mail server (host, port,
credentials, from-email, TLS), the global minimum risk level, and
`excluded_ips`: source addresses that never trigger an alert, eg. your own
scanners or monitoring (one per line).

Every decoy sends its alerts to Send alerts to, unless its persona sets its
own email or Slack webhook on the Personas page ("Alerts for this decoy").
The page stores which of the two is filled in as `alert_routing_level`
(`email`/`slack`/`both`, or `none` for no override). A persona's `alert_min_risk_level`, when
set, replaces the global minimum for that decoy. `_alert_route()` in
`classifier/alerts.py` makes this choice for live, follow-up and catch-up
alerts alike, and the Alerts page's status line shows its result.

When a session's risk meets the threshold, the alert is sent by email
(needs the mail server) and/or Slack, and recorded as an alert event. With
both, each channel is sent and recorded on its own. Send Test Email saves
the form, then sends to Send alerts to (or the From address if it's empty).

Alerts lead with the recommended fix. Repeat alerts for the same source
address and technique within `ECHIDRA_ALERT_REPEAT_MINUTES` (default 60)
are held and sent as one follow-up with the count; a higher risk level, or
a critical session, always alerts at once. Sessions stored late (after a
database outage or a stop) get one summary alert per decoy instead of one
alert each.

- `classifier/storage/models.py` — `AlertConfigInput.default_contact_email`,
  `default_slack_webhook`, `excluded_ips`; `PersonaConfigInput.alert_routing_level`,
  `alert_min_risk_level`
- `classifier/alerts.py` — `_alert_route()`, alert dispatch (SMTP/Slack),
  `_is_excluded_ip()`
- `classifier/api/app.py` — alert config and test-send endpoints
