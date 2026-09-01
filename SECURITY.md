# Security Policy

## Reporting a vulnerability

If you find a security issue in Echidra itself, please email
security@qyleron.com rather than opening a public GitHub issue.
We will respond within 72 hours.

## Known dependency vulnerabilities

Found via `pip-audit -r requirements.txt`, cross-checked with `safety check
-r requirements.txt`, run in an isolated environment (never installed
alongside the app's own dependencies — see the remediation plan below for
why that distinction matters).

`python-dotenv` (1 arbitrary-file-overwrite-via-symlink CVE, PYSEC-2026-2270)
is remediated in this release — bumped to `python-dotenv==1.2.2`, verified
against the full test suite before release.

The `pydantic` `EmailStr` ReDoS advisory (CVE-2024-3772 / PVE-2023-61416,
https://github.com/pydantic/pydantic/pull/7360) no longer applies: the
project has migrated off Pydantic v1 entirely (see below), and Pydantic v2's
`EmailStr` uses the `email-validator` package rather than the vulnerable
regex.

### Starlette CVEs (fixed)

The five CVEs previously tracked against `starlette==0.50.0` are fixed as of
this release. The project migrated every Pydantic v1-style validator
(`@validator`, `@root_validator`, `class Config`) across
`classifier/schemas/`, `classifier/storage/models.py`, and
`classifier/api/app.py` to Pydantic v2 syntax, which unblocked upgrading to
`fastapi==0.141.1` and `starlette==1.6.0`, `pydantic==2.13.5`. All five are
covered by the pinned versions:

| CVE | Advisory | Issue | Fixed in | Status |
|---|---|---|---|---|
| CVE-2026-48818 | PYSEC-2026-2281 | SSRF via UNC path handling in `StaticFiles.lookup_path()` (Windows) | 1.1.0 | Fixed (1.6.0) |
| CVE-2026-48817 | PYSEC-2026-2280 | Arbitrary method execution via unrestricted `getattr` dispatch in `HTTPEndpoint` | 1.1.0 | Fixed (1.6.0) |
| CVE-2026-54282 | PYSEC-2026-248 | Host/URL confusion via unvalidated path concatenation in `request.url` | 1.3.0 | Fixed (1.6.0) |
| CVE-2026-54283 | PYSEC-2026-249 | Denial of service via unbounded `request.form()` field count/size | 1.3.1 | Fixed (1.6.0) |
| CVE-2026-48710 | PYSEC-2026-161 | HTTP request smuggling via unvalidated `Host` header reconstruction | 1.0.1 | Fixed (1.6.0) |

We still recommend firewalling port 8000 from external access as
defense-in-depth — see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the
recommended configuration. Under Docker Compose it's bound to `127.0.0.1`
only (`docker-compose.yml`'s `127.0.0.1:8000:8000`); under systemd,
`echidra-api.service` binds `0.0.0.0:8000` like the four honeypot listener
ports (2222 SSH-style, 8080 HTTP, 2121 FTP, 2323 Telnet — none of which use
FastAPI/Starlette), so access control there depends on the `ufw deny 8000`
rule from [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) actually being applied
and verified active (`sudo ufw status verbose`).

### CodeQL findings (fixed)

A CodeQL scan flagged three issues, all fixed:

- **SSRF in the Slack alert webhook** (`classifier/alerts.py`): the
  `slack_webhook` scheme/host check used `str.startswith()`, which a
  crafted URL (e.g. `https://hooks.slack.com.evil.example/`) could pass
  while still routing the outbound request to an attacker-controlled host.
  Fixed by parsing the URL and checking `parsed.hostname` exactly, then
  rebuilding the outbound request URL from a hardcoded
  `https://hooks.slack.com` scheme/host rather than reusing the
  user-supplied string, so the value reaching `Request()` is provably not
  attacker-controlled.
- **HTML attribute injection** in `dashboard/public/{index,analytics,
  personas,sessions}.html`.
- **Missing script integrity** (no Subresource Integrity hash) on an
  externally-loaded script in the dashboard.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |
