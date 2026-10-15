# Changelog

All notable changes to Echidra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `echidra blocklist`: export attacker IPs seen in a time window, as plain
  text or CSV, filtered by minimum risk and session count, for use in a
  firewall, fail2ban, or Cloudflare. Private addresses and `--exclude`
  ranges are left out.
- `echidra reset-password <email>`: set a new dashboard password from the
  server, logging out existing sessions and clearing any login lockout.
- "Export Blocklist (TXT)" on the Analytics page, and
  `GET /analytics/blocklist`: the same list for the applied date range.
- Classifier rules for what an SSH session does after logging in:
  downloading and running a program (intent "Payload Delivery") and adding
  a login key to `authorized_keys` (intent "Persistence"). Both are rated
  high and come with a recommended fix. Two more cover reading a system
  program to learn the CPU type and confirming a guessed password with a
  test command (T1110.001, Password Guessing), both rated medium.
- HTTP rules that name the attack, each with a recommended fix: commands
  injected into a web request to download and run a program (router,
  camera and GeoServer exploits), path traversal, open-proxy tests, checks
  for Hikvision cameras, GeoServer and AI tool or model servers (MCP,
  OpenAI-style APIs), and WinRM and Windows sign-in probes. More secret
  and configuration files count as sensitive (`.aws/credentials`,
  `config.json`, `terraform.tfstate` and others).
- SSH session records include the client's version line and how far the
  connection got (`end_stage`: before the version line, not SSH, key
  exchange failed, before login, login without a password, after the
  password, or shell), with the reason in `end_error` when one was given,
  including the host key types a client asked for when none matched.
- The SSH decoy has an RSA, an ECDSA and an Ed25519 host key, like a
  default OpenSSH server, each generated on first start. For OpenSSH
  personas, the key exchange, cipher, MAC, compression and host key lists
  follow the defaults of the OpenSSH version the persona announces. An
  existing Ed25519 key is kept.
- The FTP decoy recognises other protocols sent to its port. TLS and
  remote-desktop openings are logged as readable markers, and a classifier
  rule labels web, SSH, TLS and remote-desktop openings as a scan for
  services on unexpected ports (T1046, Network Service Discovery), with a
  recommended fix.
- The fake shell answers `echo`, including `-n`, `-e` and its escapes;
  runs several commands on one line (`;`, `&&`, `||`) and pipelines, with
  `grep`, `head`, `tail`, `wc`, `base64` and `sh -c`; accepts programs by
  full path (`/bin/echo`); and prints a program file header that matches
  the persona's CPU. The router persona answers with BusyBox applets and
  BusyBox's own messages. Non-interactive `ssh host cmd` output no longer
  ends with a prompt. Output can be sent to files with `>`, `>>` and `2>`;
  `touch`, `mkdir`, `cp`, `rm` and `chmod` work, with GNU or BusyBox
  messages; and a file made runnable can be run as `./file`. What a
  session writes is kept in that session only, never on the host.
- GitHub Actions: tests on Python 3.11–3.13, CodeQL, and OpenSSF Scorecard; Dependabot for pip,
  Docker, and Actions.

### Changed
- Intelligence issues update incrementally. Each sync merges only the
  classifier runs stored since the previous sync, so its cost stays the
  same however much data is stored. Counts stay exact, and the honeypot
  and API processes never sync at the same time. The first sync after
  upgrading rebuilds every issue once, and `sync-issues --full` rebuilds
  them on demand.
- Alerts are grouped: a session alerts once for each risk level it reaches,
  and repeat alerts for the same source address and technique within an
  hour are held, then sent as one follow-up with the count. A higher risk
  level, or a critical session, always alerts at once. Set
  `ECHIDRA_ALERT_REPEAT_MINUTES` to change the window (`0` sends every
  alert).
- A session's ATT&CK techniques are listed most serious first, so alerts
  lead with the fix for the most serious thing the session did. When a
  high-rated rule matches, it also sets the session's intent, and
  commodity bots that log in over SSH get their own finding.
- An HTTP `Authorization` header counts as a credential submission only
  when it is Basic and carries a username and password. A GET request
  whose query string carries a username and a password counts too, and
  the Realtek router login field `psd` is read as a password.
- The Telnet Mirai rule matches only device-specific factory passwords and
  is tagged T1078.001 (Default Accounts), with its own recommended fix.
  Generic pairs such as `admin:admin` are labelled as brute-force.
- `echidra start` and `deploy/systemd/echidra-api.service` now bind the
  dashboard to `127.0.0.1` by default, matching Docker Compose. Use
  `--api-host` to override.
- Alert emails and Slack messages lead with the recommended fix (the same
  one the Intelligence page shows), put the actor, source IP, decoy and
  ATT&CK techniques in the subject, use readable values, and link straight
  to the session in the dashboard (set `ECHIDRA_DASHBOARD_URL` if you don't
  open it at `http://127.0.0.1:8000`).
- Dashboard: tables, the Overview map and event list, and Analytics show a
  loading spinner until their data arrives; brighter form labels, hints and
  placeholders; larger notices; save and test results on the Alerts page
  appear as notices, with a lasting "App password saved" indicator under
  the password field; smoother scrolling in the persona editor; creating
  and editing a persona use the same form style, with required fields
  marked; more space between form fields; hovered table rows stand apart
  from the header row; better default fonts on Linux.
- Logging in now returns you to the dashboard page you were sent to the
  login page from (eg. an alert's session link) instead of the Overview.
- Clearer sign-in, sign-up, alert test, error and notice messages that say
  what happened and what to do next.
- Python 3.12 and 3.13 support (`PyYAML` 6.0.2).
- Smaller Docker build context: local data and development files are
  excluded.
- `SECURITY.md` rewritten to describe Echidra's security model.
- `echidra start` prints a short summary: decoy ports, dashboard URL, an
  SSH-tunnel hint, and how to stop.
- Dashboard: messages appear as in-page notices instead of browser popups;
  the sign-in and persona forms show their own validation messages; dark
  scrollbars and autofill styling; empty pages explain what happens next.

### Fixed
- SSH host key files are created owner-readable only from the start.
- An SSH client that closes the connection before logging in is recorded
  as a disconnect, not an error; a login timeout is recorded as a timeout.
- Alerts sent while an SSH session is still open are recorded in the alert
  history, and with "both" routing each channel is sent and recorded on its
  own.
- Docker Compose passes `ECHIDRA_DASHBOARD_URL` to the honeypot and
  dashboard, so alert links use it.
- The `ECHIDRA_COOKIE_SECURE` startup notice is logged once instead of
  twice, and says when it applies.
- Spacing between the sign-in page's message box and the form below it.
- Server validation messages no longer show a raw "Value error," prefix on
  the sign-in page.
- Fields in two-column forms (eg. Persona ID and Display Name) line up.
- The `test` extra includes `httpx`, and the project URLs point at the
  right repository.
- `echidra start` reports busy ports up front, and `echidra start`/`stop`
  point to `systemctl` when Echidra is running as a systemd service.

## [0.2.0] - 2026-10-06

### Added
- Classification coverage on the Analytics page and in
  `GET /analytics/summary` (`classified_sessions`, `unclassified_sessions`):
  how many sessions in the selected range got an actor label, shown as a
  note under the intent tiles and included in the CSV/XLSX export.
- `healthcheck` on the `api` service in `docker-compose.yml`, polling
  `/health`, so `docker compose ps` reports when the dashboard is actually
  ready.
- Real-socket tests for the global connection limit in `ProtocolServer`.

### Fixed
- Slack webhook URLs are validated by exact hostname when a persona is
  saved, the same check used when an alert is sent. URLs with credentials
  or a non-default port are rejected.
- The Analytics date range now survives a page reload. The applied range is
  kept in the URL (`?from=&from_hour=&to=&to_hour=`), so it can also be
  bookmarked or shared.
- Shell emulation fidelity improvements.
- CLI and dashboard polish.

### Changed
- Replaced the last Pydantic v1 method calls (`.copy()` in
  `classifier/pipeline.py`, plus `parse_obj`/`dict`/`json`/`construct`
  across the test suite) with their v2 equivalents, ahead of their removal
  in Pydantic v3.
- A closed finding reopens when new sessions are linked to it.

### Docs
- `docs/DEPLOYMENT.md` explains the brief startup window after
  `docker compose up -d` and how to check readiness.

## [0.1.0]

First public release: SSH, HTTP, FTP and Telnet deception listeners,
persona-driven fake systems, rule-based classification mapped to MITRE
ATT&CK, PostgreSQL storage, the web console (Overview, Intelligence,
Sessions, Analytics, Personas, Alerts), email and Slack alerting, the
`echidra` CLI, Docker Compose and systemd deployment, and reproducible
load-test benchmarks.
