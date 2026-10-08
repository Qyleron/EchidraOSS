# Changelog

All notable changes to Echidra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- `echidra start` and `deploy/systemd/echidra-api.service` now bind the
  dashboard to `127.0.0.1` by default, matching Docker Compose. Use
  `--api-host` to override.

### Fixed
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
- Slack webhook URLs are now validated by exact hostname when a persona is
  saved, matching the check at send time. Previously a prefix match let
  URLs like `https://hooks.slack.com.evil.example/` save successfully; they
  were only rejected when an alert was sent. URLs with credentials or a
  non-default port are also rejected.
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
