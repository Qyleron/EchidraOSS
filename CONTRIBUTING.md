# Contributing to Echidra

Echidra is a security tool, so all code is written and reviewed by the
maintainers. **We don't accept pull requests from outside contributors**;
pull requests that add or change code will be closed without merging.

You can still help a lot, and contributions through issues are credited in
the release notes.

## How to contribute

- **Report bugs:** open a
  [GitHub issue](https://github.com/Qyleron/EchidraOSS/issues). See
  [ISSUES.md](ISSUES.md) for what to include.
- **Suggest features or improvements:** open an issue describing the
  problem you want solved, not only the solution you have in mind.
- **Suggest detection rules:** open an issue with the attacker behavior,
  the MITRE ATT&CK technique it maps to, and an example session (redact
  anything sensitive). Maintainers write and test the rule.
- **Improve the docs:** open an issue pointing to what's wrong, missing or
  unclear.
- **Ask questions:** use
  [GitHub Discussions](https://github.com/Qyleron/EchidraOSS/discussions).
- **Security issues:** don't open a public issue. Follow
  [SECURITY.md](SECURITY.md).

## What makes a good issue

- One problem or idea per issue.
- For bugs: Echidra version or commit, how you deployed it, exact steps to
  reproduce, and what you expected versus what happened.
- For suggestions: who it helps and why, with an example if you can.
- No secrets, real credentials or unredacted IPs/hostnames of your own
  systems.

## What happens next

Maintainers triage new issues, label them, and reply. Accepted changes are
implemented by the maintainers, tested in CI on Python 3.11 to 3.13, and
listed in the [CHANGELOG](CHANGELOG.md).

## License

Echidra is licensed under the [AGPL-3.0](LICENSE.md). You're free to fork
and modify it under that license.
