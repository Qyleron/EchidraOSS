import uuid

import pytest
from pydantic import ValidationError

from classifier.features.session import SessionFeatures
from classifier.rules.engine import (
    ClassificationRule,
    RuleCondition,
    RuleSet,
    evaluate_rules,
    load_rules,
)


def make_features(**overrides):
    data = {
        "session_id": uuid.uuid4(),
        "protocol": "tcp_shell",
        "persona_id": "generic_linux",
        "end_reason": "logout",
        "duration_seconds": 10.0,
        "command_count": 4,
        "commands_per_minute": 24.0,
        "unique_command_count": 3,
        "repeated_command_count": 1,
        "discovery_command_count": 3,
        "file_read_count": 1,
        "sensitive_file_read_count": 1,
        "decoy_files_surfaced": ["/etc/passwd"],
        "decoy_files_surfaced_count": 1,
        "exit_command_present": False,
        "inter_command_intervals_seconds": [1.0, 2.0, 3.0],
        "average_inter_command_interval_seconds": 2.0,
        "command_names": ["whoami", "ls", "cat", "ls"],
    }
    data.update(overrides)
    return SessionFeatures.parse_obj(data)


def make_rule(**overrides):
    data = {
        "id": "sensitive_file_probe",
        "name": "Sensitive file probe",
        "actor_label": "commodity_bot",
        "confidence": 0.78,
        "risk_score": 55,
        "evidence": ["Sensitive fake file was read."],
        "conditions": [
            {
                "field": "sensitive_file_read_count",
                "operator": "gte",
                "value": 1,
            },
        ],
    }
    data.update(overrides)
    return ClassificationRule.parse_obj(data)


def test_rule_evaluation_returns_matching_rules():
    rules = RuleSet(rules=[make_rule()])
    features = make_features()

    result = evaluate_rules(features, rules)

    assert len(result.matched_rules) == 1
    assert result.best_match.rule_id == "sensitive_file_probe"
    assert result.best_match.actor_label == "commodity_bot"


def test_rule_evaluation_skips_non_matching_rules():
    rules = RuleSet(rules=[make_rule()])
    features = make_features(sensitive_file_read_count=0)

    result = evaluate_rules(features, rules)

    assert result.matched_rules == []
    assert result.best_match is None


def test_rule_conditions_support_list_membership_checks():
    rule = make_rule(
        conditions=[
            RuleCondition(
                field="decoy_files_surfaced",
                operator="contains",
                value="/etc/passwd",
            ),
            RuleCondition(
                field="command_names",
                operator="contains",
                value="cat",
            ),
        ],
    )

    result = evaluate_rules(make_features(), [rule])

    assert result.best_match.rule_id == "sensitive_file_probe"


def test_rule_evaluation_rejects_unknown_feature_fields():
    rule = make_rule(
        conditions=[
            {
                "field": "missing_feature",
                "operator": "equals",
                "value": True,
            },
        ],
    )

    with pytest.raises(ValueError, match="Unknown feature field"):
        evaluate_rules(make_features(), [rule])


def test_ruleset_rejects_duplicate_rule_ids():
    with pytest.raises(ValidationError, match="rule ids must be unique"):
        RuleSet(rules=[make_rule(), make_rule()])


def test_default_yaml_rules_load_and_match_expected_features():
    rules = load_rules("classifier/rules/default_rules.yaml")

    result = evaluate_rules(make_features(), rules)

    assert {match.rule_id for match in result.matched_rules} == {
        "automated_discovery_burst",
        "sensitive_file_probe",
        "interactive_low_and_slow",
    }
