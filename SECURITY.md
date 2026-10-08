# Security Policy

## Reporting a vulnerability

If you find a security issue in Echidra, please email
security@qyleron.com rather than opening a public GitHub issue.
We respond within 72 hours.

Please include the affected version or commit, steps to reproduce, and the
impact you observed. We'll keep you updated while we work on a fix and
credit you in the release notes unless you'd rather stay anonymous.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |

## How Echidra is built to be safe

**Attacker input is never executed.** Shell commands, HTTP requests, and
FTP/Telnet logins are parsed and answered from an in-memory fake persona.
Nothing an attacker sends runs on the host or reads the real filesystem.

**The dashboard isn't exposed to the internet.** `echidra start`, Docker
Compose, and the systemd unit all bind the dashboard/API to `127.0.0.1` by
default; reach it remotely over an SSH tunnel. Only the decoy ports face
the internet. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

**Dashboard access**
- Passwords stored as salted PBKDF2-SHA256 hashes.
- Signed, `HttpOnly`, `SameSite=Lax` session cookies; sessions can be
  revoked server-side.
- Login rate limiting; only the first account can sign up unless
  `ECHIDRA_ALLOW_SIGNUPS` is set.
- Dashboard API responses are sent with `Cache-Control: no-store`.

**Data at rest**
- Alert SMTP passwords are encrypted in the database.
- Session logs, which can contain captured credentials, are written with
  owner-only (`0600`) permissions.

**Least privilege**
- Docker containers run as a non-root user with all capabilities dropped
  and `no-new-privileges`.
- systemd units run as a dedicated `echidra` user with `NoNewPrivileges`
  and `ProtectSystem=strict`.

**Safe exports and alerts**
- CSV/XLSX exports neutralize spreadsheet formula injection from
  attacker-typed input.
- Slack webhooks are restricted to `hooks.slack.com` by exact hostname.

## Dependencies and code scanning

Dependencies are pinned. Every change runs the test suite and CodeQL code
scanning, Dependabot tracks dependency and base-image updates, and the
project is checked by the OpenSSF Scorecard. Security fixes are listed in
the [CHANGELOG](CHANGELOG.md).
