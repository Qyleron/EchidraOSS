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
- GitHub Actions: tests on Python 3.11–3.13, CodeQL, and OpenSSF Scorecard; Dependabot for pip,
  Docker, and Actions.

### Changed
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
  the password field; smoother scrolling in the persona editor.
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
