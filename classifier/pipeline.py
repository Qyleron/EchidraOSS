"""Post-session classification entry points for validated and raw logs."""

from __future__ import annotations

import json
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
    """Classify one validated post-session record into an analyst summary."""
    active_rules = rules if rules is not None else load_rules(DEFAULT_RULES_PATH)
    features = extract_session_features(session)
    evaluation = evaluate_rules(features, active_rules)
    return summarize_rule_evaluation(evaluation, features)


def classify_session_record(
    record: dict[str, Any],
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Validate and classify one decoded session log record."""
    session = SessionRecord.parse_obj(record)
    return classify_session(session, rules)


def classify_session_jsonl(
    line: str,
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Classify one JSON Lines record emitted by SessionLogger."""
    return classify_session_record(json.loads(line), rules)
