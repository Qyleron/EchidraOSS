# Manual Testing Guide

Hands-on commands and expected output for every honeypot listener, the
classifier/storage layer, and every dashboard page. Run these yourself —
nothing here is automated for you.

Prereqs for most sections:

```bash
cp .env.example .env                       # set ECHIDRA_DATABASE_URL inside
python -m classifier.storage.cli init-db   # creates tables
python -m honeypot.main                    # terminal 1 — the 4 protocol listeners
uvicorn classifier.api.app:create_app --factory --reload        # terminal 2 — API + dashboard, port 8000
```

---

## 1. The four honeypot services

### SSH-style fake shell (port 2222)

```bash
nc 127.0.0.1 2222
```

Type these one at a time:

| Command | Expected output |
|---|---|
| (connect) | `Linux fake-host 5.15.0-91-generic x86_64` banner, then `Last login: ...`, then a `root@fake-host:~#`-style prompt |
| `whoami` | `root` |
| `pwd` | `/home/admin` |
| `id` | `uid=0(root) gid=0(root) groups=0(root)` |
| `uname -a` | `Linux fake-host 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux` |
| `ls` | `bin  boot  dev  etc  home  tmp  var` |
| `ls /home/admin` | `notes.txt  readme.txt` |
| `cat /home/admin/readme.txt` | `Welcome to the system.` |
| `cat /etc/passwd` | `root:x:0:0:root:/root:/bin/bash` / `admin:x:1000:1000:admin:/home/admin:/bin/bash` |
| `cat /nope` | `cat: /nope: No such file or directory` |
| `ps` | header row + `sshd`, `cron`, `rsyslogd` as fake PIDs |
| `whatever123` | `bash: whatever123: command not found` |
| `exit` | connection closes |

After `exit` (or Ctrl-C), confirm the session was logged:

```bash
tail -1 logs/sessions.jsonl | python3 -m json.tool
```

Expect a JSON object with `"protocol": "tcp_shell"`, your typed commands under
`"commands"`, and `"decoy_files_surfaced": ["/home/admin/readme.txt", "/etc/passwd"]`
(every file you `cat`, or that appeared in an `ls` listing, gets tracked here).

### HTTP (port 8080)

```bash
curl -si http://127.0.0.1:8080/
```
Expect `HTTP/1.1 200 OK`, `Server: Apache/2.4.54 (Debian)` (generic_linux
persona), body = "Apache2 Ubuntu Default Page".

```bash
curl -si http://127.0.0.1:8080/wp-login.php
```
Expect `200 OK` and a WordPress login form (`<form ... action="/wp-login.php">`).

```bash
curl -si http://127.0.0.1:8080/.env
```
Expect `403 Forbidden`.

```bash
curl -si http://127.0.0.1:8080/nonexistent-path
```
Expect `404 Not Found`.

```bash
curl -si -X POST http://127.0.0.1:8080/wp-login.php \
  -d "log=admin&pwd=letmein123"
```
Expect `200 OK` (same WP login page echoed back). Then check it was captured:

```bash
tail -1 logs/sessions.jsonl | python3 -m json.tool
```
Expect a command entry like `"POST /wp-login.php: log=admin&pwd=letmein123"`.

### FTP (port 2121)

```bash
printf 'USER admin\r\nPASS admin123\r\n' | nc 127.0.0.1 2121
```
Expect, in order:
```
220 (vsFTPd 3.0.3)
331 Please specify the password.
530 Login incorrect.
421 Timeout.
```
Then `tail -1 logs/sessions.jsonl` should show `"USER admin"` and
`"PASS admin123"` in `commands`.

### Telnet (port 2323)

Use a real telnet client, not `nc` — the handler spends its first ~2 seconds
draining Telnet IAC negotiation bytes, and a real client sends those
automatically before you type anything. Piping input through `nc` immediately
gets eaten by that drain window instead of reaching the login prompt.

```bash
telnet 127.0.0.1 2323
```
Expect the persona's OS banner, then `fake-host login: `. Type `root`, Enter,
then `Password:`, type `toor`, Enter. Expect a ~1s pause, then
`Login incorrect`, then the login prompt again.

If you want a scripted version, delay the input past the 2-second drain
window:

```bash
{ sleep 2.5; printf 'root\r\n'; sleep 0.5; printf 'toor\r\n'; sleep 0.5; } | nc 127.0.0.1 2323
```

Then confirm capture: `tail -1 logs/sessions.jsonl` should show
`"login: root"` and `"password: toor"`.

---

## 2. Fake files, decoys, and persona identity

These are config, not a live protocol — verify them through the Personas
dashboard page (section 7) or by reading `honeypot/core/persona.py` presets
directly. To confirm a *specific* decoy actually surfaces during a session,
`cat` its exact path over the SSH-shell listener (section 1) and check
`decoy_files_surfaced` in the resulting log line, as shown above.

Note: each preset persona also declares `suid_binaries` (e.g.
`/usr/bin/sudo`, `/bin/su`) — this is returned by `GET /personas` but the
interactive shell (`honeypot/core/engine.py`) has no `find`/`sudo` command
that surfaces it yet, so there's nothing to test interactively here today.

**A saved persona config now reaches the live honeypot.** This endpoint
requires a logged-in dashboard session — run section 7's signup call first
to create `cookies.txt` (on a fresh database, that signup must be the first
one you run, since it's first-account-only). Then create the persona config:
```bash
curl -s -b cookies.txt -X POST "http://127.0.0.1:8000/persona-configs/custom_demo" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom demo",
    "hostname": "custom-demo-01",
    "os_banner": "Linux custom-demo-01 6.1.0-custom x86_64",
    "ssh_enabled": true,
    "ssh_port": 2222,
    "running_processes": ["nginx", "redis-server"],
    "fake_users": ["deploy"],
    "decoy_files": []
  }'
ECHIDRA_PERSONA=custom_demo python -m honeypot.main
```
Then connect over the SSH-shell listener (section 1) — the login banner
should show `custom-demo-01`, not a preset hostname. Editing the config
afterward won't take effect on its own — the process caches the persona
until `clear_active_persona_cache()` runs or the process restarts; that's
expected, not a bug.

---

## 3. Event classification / MITRE mapping (post-session classifier)

No live listener needed — this is the stateless classification endpoint.

```bash
curl -s -X POST http://127.0.0.1:8000/classify/session \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": 1,
    "session_id": "8f28043f-6860-4857-8e3f-11a7cb16e6fd",
    "protocol": "tcp_shell",
    "peer_ip": "203.0.113.45",
    "peer_port": 49215,
    "persona_id": "generic_linux",
    "started_at": 100.0,
    "ended_at": 105.0,
    "duration_seconds": 5.0,
    "end_reason": "disconnect",
    "command_count": 4,
    "commands": [
      {"cmd": "whoami", "timestamp": 101.0},
      {"cmd": "hostname", "timestamp": 102.0},
      {"cmd": "pwd", "timestamp": 103.0},
      {"cmd": "ls", "timestamp": 104.0}
    ],
    "decoy_files_surfaced": []
  }' | python3 -m json.tool
```

Expected (verified against the current rule set):
```json
{
  "actor_label": "automated_scanner",
  "confidence": 0.72,
  "risk_score": 35,
  "risk_level": "low",
  "behavior_stage": "discovery",
  "intent": "reconnaissance",
  "mitre_tags": ["T1087", "T1082"],
  "matched_rule_ids": ["automated_discovery_burst"]
}
```
(full response also includes `feature_summary`, `evidence`,
`deception_action`, `alert_action`, `analyst_recommendation`, and
`persona_context`).

To persist it (requires `ECHIDRA_DATABASE_URL`), swap the path to
`/classify/session/store` — response adds a `run_id`, and the row lands in
`classifier_runs`/`classifier_signals` (see section 6). This endpoint also
requires `ECHIDRA_INGEST_API_KEY` to be set and sent back as the `X-Api-Key`
header (`-H "X-Api-Key: $ECHIDRA_INGEST_API_KEY"`) — it writes to the database
and can trigger alert emails, so it 503s if the key isn't configured and 401s
if the header is missing or wrong.

---

## 4. Behavioral classification (bot vs. human, timing-based)

The classifier has no raw per-keystroke telemetry — timing is measured
between completed commands (`average_inter_command_interval_seconds`), since
the shell reads whole lines, not individual keys. Two contrasting payloads
against the same `/classify/session` endpoint as above:

**Fast, bursty → bot.** Use the exact payload from section 3
(4 discovery commands in 5 seconds, no exit) → `automated_scanner`, as shown.

**Slow, interactive → human.** Same shape, spaced out:
```bash
curl -s -X POST http://127.0.0.1:8000/classify/session \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": 1,
    "session_id": "8f28043f-6860-4857-8e3f-11a7cb16e6fd",
    "protocol": "tcp_shell",
    "peer_ip": "203.0.113.45",
    "peer_port": 49215,
    "persona_id": "generic_linux",
    "started_at": 99.0,
    "ended_at": 113.0,
    "duration_seconds": 14.0,
    "end_reason": "logout",
    "command_count": 4,
    "commands": [
      {"cmd": "whoami", "timestamp": 100.0},
      {"cmd": "pwd", "timestamp": 104.0},
      {"cmd": "ls", "timestamp": 108.0},
      {"cmd": "hostname", "timestamp": 112.0}
    ],
    "decoy_files_surfaced": []
  }' | python3 -m json.tool
```
Expected:
```json
{
  "actor_label": "skilled_human_operator",
  "confidence": 0.64,
  "risk_score": 45,
  "risk_level": "medium",
  "behavior_stage": "execution",
  "intent": "interactive_operation",
  "mitre_tags": ["T1059"],
  "matched_rule_ids": ["interactive_low_and_slow"]
}
```

`brute_force_bot`/T1110 can't be produced by a single `/classify/session`
call — it depends on `connection_count_from_same_ip`, which is only computed
against stored sessions (5+ connections from the same `peer_ip` within 24h).
Test it via `sync-issues` instead (section 6).

---

## 5. Country lookup (geolocation)

Pure function, no network needed:

```bash
python3 -c "
from classifier.storage.geolocation import resolve_country
print(resolve_country('8.8.8.8'))   # expect: United States
print(resolve_country('1.1.1.1'))   # expect: Australia
"
```

`resolve_country()` now returns `NULL` for private/reserved/unresolved lookups, so use public IPs for positive geolocation checks.

To see it end-to-end through storage, POST to `/classify/session/store`
(with the `X-Api-Key` header from section 3) with `"peer_ip": "8.8.8.8"` and
then check the `country` column (section 6).

---

## 6. Permanent storage (PostgreSQL)

```bash
psql "$ECHIDRA_DATABASE_URL" -c "\dt"
```
Expect: `dashboard_users`, `sessions`, `session_events`, `classifier_runs`,
`classifier_signals`, `manual_labels`, `issues`, `issue_mitre_techniques`,
`persona_configs`, `alert_config`, `alert_events`.

After a `/classify/session/store` call (section 3/5):
```bash
psql "$ECHIDRA_DATABASE_URL" -c "SELECT id, protocol, peer_ip, country, persona_id FROM sessions ORDER BY started_at DESC LIMIT 1;"
psql "$ECHIDRA_DATABASE_URL" -c "SELECT actor_label, risk_score, risk_level FROM classifier_runs ORDER BY id DESC LIMIT 1;"
```
Expect one matching row in each, `country` = `United States` if you used
`8.8.8.8`.

Seeded demo data (present immediately after `init-db`, before anything else runs):
```bash
psql "$ECHIDRA_DATABASE_URL" -c "SELECT title, severity, status FROM issues;"
```
Expect 4 rows (3 `open`, 1 `closed`) — this is what the Intelligence page
should show on a completely fresh install.

Roll up real captured sessions into issues:
```bash
python -m classifier.storage.cli sync-issues
```
Expect stdout confirming how many issues were created/updated; rerunning is
idempotent (counts refresh, but analyst open/closed status is preserved).

---

## 7. Dashboard pages

All dashboard routes require a logged-in session cookie. Sign up once, save
the cookie, and reuse it:

```bash
curl -s -c cookies.txt -X POST http://127.0.0.1:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "correct horse battery staple"}'
```
Expect `{"authenticated": true, "email": "test@example.com"}`. A second signup
with the same email should 409 (`"email already registered"`). Signup is also
now first-account-only: once any dashboard user exists, a signup attempt with
a *different* email 403s (`"signup is disabled ..."`) unless
`ECHIDRA_ALLOW_SIGNUPS=true` is set. On a fresh database, run this section's
signup before any other, since it's the one that gets to succeed.

Then in a browser: visit `http://localhost:8000/auth`, log in with the same
credentials, and walk each page:

| Page | URL | What to check |
|---|---|---|
| Sessions | `/dashboard/sessions` | Table lists captured sessions; clicking one opens a session detail view with its command history |
| Analytics | `/dashboard/analytics` | Aggregate charts render (not blank) once at least one session/classifier run exists |
| Intelligence | `/dashboard/intelligence` | 4 seeded issues appear with title, severity, recommended fix, impact, MITRE tags; toggling status calls `PATCH /issues/{id}/status` |
| Personas | `/dashboard/personas` | Table of preset + custom personas; "Customize"/"Edit Config" opens the modal — check all three dropdowns (Alert Routing, Min Risk Level, Interaction Depth) show rounded corners, grey hover, and a pointer cursor, not the browser's native blue highlight; save and confirm the row updates; switch to the Analytics tab and confirm the "N/A" placeholder shows until you pick a persona |
| Alerts | `/dashboard/alerts` | SMTP config form saves via `PUT /alerts/config`; "Send test alert" only succeeds once `enabled`, `smtp_host`, and `smtp_from_email` are set — otherwise expect `400 alerts not enabled` or `400 smtp_host and smtp_from_email are required` |

---

## 8. Automated test suite

```bash
pytest
```
Expect all tests to pass. To scope to what's new/relevant here:
```bash
pytest tests/test_dashboard_ui.py -v      # static HTML/branding checks per page
pytest tests/test_rules_engine.py tests/test_scoring_session.py -v   # classifier rule + scoring logic
pytest tests/test_session_features.py -v # timing/feature extraction
pytest tests/test_issue_sync.py -v        # issue rollup + brute-force-by-IP logic
```
Note: `FtpHandler`, `HttpHandler`, and `TelnetHandler` already have dedicated
automated coverage in [tests/test_ftp_handler.py](tests/test_ftp_handler.py),
[tests/test_http_handler.py](tests/test_http_handler.py), and
[tests/test_telnet_handler.py](tests/test_telnet_handler.py). Those tests are
the right place to confirm listener behavior alongside the broader suite.

---

## 9. persona.txt spec vs. what's built

The current persona spec and implementation use two distinct fields in the
Personas modal: **Alert Routing** (`none/email/slack/both`) and **Min Risk
Level** (`critical/high/medium/low`). These values are stored in
`persona_configs.alert_routing_level` and `persona_configs.alert_min_risk_level`.
Use this section to verify that the modal, saved persona configuration, and the
spec text all reflect those two fields consistently.
