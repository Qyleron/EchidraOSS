"""Post-session classification entry points for validated and raw logs."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from classifier.features.session import extract_session_features
from classifier.rules.engine import (
    ClassificationRule,
    RuleSet,
    evaluate_rules,
    load_rules,
)
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import (
    ClassificationSummary,
    summarize_rule_evaluation,
)


DEFAULT_RULES_PATH = Path(__file__).parent / "rules" / "default_rules.yaml"


def classify_session(
    session: SessionRecord,
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Classify one validated post-session record into an analyst summary.

    Raises ValueError when a rule references an unknown feature field or uses an
    operator against an incompatible feature value.
    """
    active_rules = rules if rules is not None else load_rules(DEFAULT_RULES_PATH)
    features = extract_session_features(session)
    evaluation = evaluate_rules(features, active_rules)
    return summarize_rule_evaluation(evaluation, features)


def classify_session_record(
    record: dict[str, Any],
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Validate and classify one decoded session log record.

    Raises pydantic.ValidationError when the record does not match the canonical
    session schema.
    """
    session = SessionRecord.parse_obj(record)
    return classify_session(session, rules)


def classify_session_jsonl(
    line: str,
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Classify one JSON Lines record emitted by SessionLogger.

    Raises json.JSONDecodeError for malformed JSON and pydantic.ValidationError
    for decoded records that fail schema validation.
    """
    return classify_session_record(json.loads(line), rules)


def classify_session_jsonl_lines(
    lines: Iterable[str],
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> list[ClassificationSummary]:
    """Classify non-empty JSONL session records from an iterable of lines.

    Raises the same exceptions as classify_session_jsonl for the first invalid
    line encountered.
    """
    return [
        classify_session_jsonl(line, rules)
        for line in lines
        if line.strip()
    ]


def classify_session_jsonl_file(
    path: str | Path,
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> list[ClassificationSummary]:
    """Classify all non-empty session records in a JSONL log file.

    Raises OSError when the file cannot be read, plus the parsing and validation
    exceptions documented by classify_session_jsonl.
    """
    with Path(path).open("r", encoding="utf-8") as log_file:
        return classify_session_jsonl_lines(log_file, rules)
