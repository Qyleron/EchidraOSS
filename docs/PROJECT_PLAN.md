# Echidra Project Plan

This document is the simple working map for where Echidra is, what is already
done, and what should come next.

## Simplest Flow

```text
attacker connects
  -> fake TCP shell answers safely
  -> session commands are recorded
  -> completed session is written as JSONL
  -> session record is validated
  -> features are extracted
  -> YAML rules are evaluated
  -> classifier summary is produced
  -> existing JSONL logs can be batch-classified
  -> CLI can emit classifier summaries to stdout or a JSONL report file
  -> future API, database, alerts, and dashboard consume the summary
```

## Done

- Fake Linux TCP shell with safe command simulation
- Persona-based fake users, hostnames, files, processes, and ports
- Per-session command history and lifecycle state
- Append-only JSONL logging for completed sessions, with each record written as
  one serialized line
- Canonical Pydantic session schema
- Session feature extraction for timing, command rate, discovery, file reads,
  sensitive file reads, decoys, exits, and command names
- Editable YAML rule loading and deterministic rule evaluation
- Actor labels, actor vote tally, confidence, risk score, and risk level
- Evidence aggregation, MITRE tags, persona context, and matched rule IDs
- Behavior stage and intent mapping
- Safeguard Advisor recommendations for external tools
- Compact feature summary inside classifier output
- Post-session classifier pipeline from `SessionRecord` to summary
- Raw dict and JSONL classification helpers for log/API ingestion
- Batch JSONL classification helpers for existing session logs
- CLI command for batch classification of session logs to stdout or a file
- CLI errors identify malformed JSONL input by line number

## Where We Are

Echidra now has the core post-session classifier path in place. A completed
session can be validated, converted into features, matched against the default
YAML rules, and summarized into an explainable classifier result.

Existing JSONL session logs can also be classified in batches through code or
the CLI. The project is ready for the API/storage layer because classifier
output is now structured enough for external consumers.

## Next Work

1. Add a FastAPI classifier endpoint for post-session classification.
2. Store classifier runs and manual labels in PostgreSQL.
3. Add more feature extraction as new protocols arrive.
4. Expand YAML rules for SSH, Telnet, FTP, and HTTP collectors.
5. Add local alert delivery through SMTP or webhooks.
6. Build dashboard/reporting views.
7. Collect labeled sessions for evaluation and tuning.

## Current Classifier Output

The classifier summary includes:

- Classifier and rules version
- Actor label, actor votes, and confidence
- Risk score and risk level
- Behavior stage and intent
- Persona context and compact feature summary
- MITRE tags
- Evidence
- Matched rule IDs
- Safeguard Advisor recommendations

## Current Classification Entry Points

- `classify_session` accepts a validated `SessionRecord`.
- `classify_session_record` accepts a decoded session dictionary.
- `classify_session_jsonl` accepts one JSONL log line.
- `classify_session_jsonl_lines` accepts many JSONL lines.
- `classify_session_jsonl_file` accepts a JSONL log path.
- `python -m classifier.cli classify-jsonl <path>` prints JSONL summaries.
- `python -m classifier.cli classify-jsonl <path> --output <path>` writes them.

## Comment And Docstring Rule

Use docstrings for public modules, models, and functions that form the project
contract. Use inline comments only when they explain non-obvious logic. Avoid
comments that repeat what the code already says.
