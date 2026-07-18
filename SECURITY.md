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

`pydantic` (1 ReDoS advisory in its `EmailStr` regex, tracked under two
identifiers for the same fix: CVE-2024-3772 and PVE-2023-61416 —
https://github.com/pydantic/pydantic/pull/7360) and `python-dotenv` (1
arbitrary-file-overwrite-via-symlink CVE, PYSEC-2026-2270) were also
found during this audit and are already remediated in this release —
bumped to `pydantic==1.10.13` and `python-dotenv==1.2.2` respectively, both
verified against the full test suite before release.

### Starlette CVEs (accepted, tracked)

Five CVEs in the currently pinned `starlette==0.50.0` are unpatched in this
release:

| CVE | Advisory | Issue | Fixed in |
|---|---|---|---|
| CVE-2026-48818 | PYSEC-2026-2281 | SSRF via UNC path handling in `StaticFiles.lookup_path()` (Windows) | 1.1.0 |
| CVE-2026-48817 | PYSEC-2026-2280 | Arbitrary method execution via unrestricted `getattr` dispatch in `HTTPEndpoint` | 1.1.0 |
| CVE-2026-54282 | PYSEC-2026-248 | Host/URL confusion via unvalidated path concatenation in `request.url` | 1.3.0 |
| CVE-2026-54283 | PYSEC-2026-249 | Denial of service via unbounded `request.form()` field count/size | 1.3.1 |
| CVE-2026-48710 | PYSEC-2026-161 | HTTP request smuggling via unvalidated `Host` header reconstruction | 1.0.1 |

Fixing them requires upgrading to `starlette>=1.3.1`, which requires
`fastapi>=0.133.0` (every fastapi release that supports starlette 1.x
requires `pydantic>=2.7.0` — there is no combination that keeps starlette
patched and pydantic on v1), which in turn requires migrating every
Pydantic v1-style validator (`@validator`, `@root_validator`, `class
Config`) across `classifier/schemas/`, `classifier/storage/models.py`, and
`classifier/api/app.py` to Pydantic v2 syntax, plus re-verifying validation
behavior didn't change anywhere it's relied on. That migration is tracked
and will ship in a future release rather than being folded into a routine
dependency bump.

**Reduced exposure:** `starlette` only runs as part of the dashboard/API
(port 8000) — the four honeypot listener ports (2222 SSH-style, 8080 HTTP,
2121 FTP, 2323 Telnet) are plain asyncio/asyncssh protocol handlers and
don't use FastAPI/Starlette at all, so none of these five CVEs are
reachable through them. How port 8000 itself is protected differs by
deployment path: under Docker Compose it's bound to `127.0.0.1` only
(`docker-compose.yml`'s `127.0.0.1:8000:8000`), so it's unreachable
externally regardless of firewall state. Under systemd, `echidra-api.service`
binds `0.0.0.0:8000` like the four honeypot ports — access control there is
the `ufw` rule from [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (`ufw deny
8000`), not a loopback bind, so it is only protected if that firewall rule
has actually been applied and verified active (`sudo ufw status verbose`).
A systemd deployment that skips the firewall step exposes port 8000, and
these CVEs, to the public internet.

We recommend all deployers firewall port 8000 from external access. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the recommended configuration.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |
