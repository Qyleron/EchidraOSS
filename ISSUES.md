# Reporting Issues

## Security vulnerabilities

Don't open a public issue for these — see [SECURITY.md](SECURITY.md) and
email security@qyleron.com instead.

## Bugs and feature requests

Everything else (bugs, crashes, incorrect classification behavior, dashboard
UI problems, docs gaps, feature requests) goes to
[GitHub Issues](https://github.com/Qyleron/EchidraOSS/issues).

Before opening one, search existing issues for a duplicate first.

### For a bug report, include

- What you expected to happen vs. what actually happened
- Steps to reproduce (the exact commands you ran, or the dashboard page/
  action, if it's a UI issue)
- Echidra version/commit, OS, Python version, and deployment method (local
  `pip install -e .`, Docker Compose, or systemd)
- Relevant log output or a stack trace, if there is one — redact anything
  sensitive (IPs, hostnames, credentials) first
- Whether it reproduces on a fresh `init-db` or only with existing data

### For a feature request

Describe the problem you're trying to solve, not just the feature you have
in mind — the same underlying need sometimes has a simpler fix than what's
being asked for.

## Questions and general discussion

If it's not a bug or a concrete feature request — general "how do I..."
questions, deployment help, etc. — use
[GitHub Discussions](https://github.com/Qyleron/EchidraOSS/discussions) on
the same repo rather than an issue, so it stays searchable separately from
tracked work.
