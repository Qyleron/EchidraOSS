import pytest
from pydantic import ValidationError

from tests.conftest import make_features
from classifier.rules.engine import (
    ClassificationRule,
    RuleCondition,
    RuleSet,
    evaluate_rules,
    load_rules,
)


def make_rule(**overrides):
    data = {
        "id": "sensitive_file_probe",
        "name": "Sensitive file probe",
        "actor_label": "commodity_bot",
        "confidence": 0.78,
        "risk_score": 55,
        "mitre_tags": ["T1005"],
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
    assert result.best_match.mitre_tags == ["T1005"]


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


def test_rule_rejects_unknown_actor_labels():
    with pytest.raises(ValidationError, match="unexpected value"):
        make_rule(actor_label="commodity_bto")


def test_in_operator_requires_iterable_expected_value():
    with pytest.raises(ValidationError, match="non-string iterable"):
        make_rule(
            conditions=[
                {
                    "field": "actor_label",
                    "operator": "in",
                    "value": "commodity_bot",
                },
            ],
        )


def test_contains_operator_rejects_non_iterable_feature_values():
    rule = make_rule(
        conditions=[
            {
                "field": "command_count",
                "operator": "contains",
                "value": 55,
            },
        ],
    )

    with pytest.raises(ValueError, match="Feature field is not iterable"):
        evaluate_rules(make_features(), [rule])


def test_contains_any_operator_matches_when_any_value_present():
    rule = make_rule(
        conditions=[
            RuleCondition(
                field="command_names",
                operator="contains_any",
                value=["sqlmap", "nikto", "hydra"],
            ),
        ],
    )

    matching = make_features(command_names=["whoami", "sqlmap", "exit"])
    non_matching = make_features(command_names=["whoami", "ls", "exit"])

    assert evaluate_rules(matching, [rule]).matched_rules != []
    assert evaluate_rules(non_matching, [rule]).matched_rules == []


def test_contains_any_operator_requires_iterable_expected_value():
    with pytest.raises(ValidationError, match="non-string iterable"):
        make_rule(
            conditions=[
                {
                    "field": "command_names",
                    "operator": "contains_any",
                    "value": "sqlmap",
                },
            ],
        )


def test_contains_any_operator_rejects_non_iterable_feature_values():
    rule = make_rule(
        conditions=[
            {
                "field": "command_count",
                "operator": "contains_any",
                "value": ["sqlmap"],
            },
        ],
    )

    with pytest.raises(ValueError, match="Feature field is not iterable"):
        evaluate_rules(make_features(), [rule])


def test_default_rules_match_script_kiddie_tool_names_on_tcp_shell():
    rules = load_rules("classifier/rules/default_rules.yaml")
    features = make_features(
        protocol="tcp_shell",
        command_names=["whoami", "sqlmap", "exit"],
        exit_command_present=True,
    )

    result = evaluate_rules(features, rules)

    matched_ids = {match.rule_id for match in result.matched_rules}
    assert "script_kiddie_tool_names" in matched_ids
    tool_match = next(m for m in result.matched_rules if m.rule_id == "script_kiddie_tool_names")
    assert tool_match.actor_label == "script_kiddie"


def test_default_rules_script_kiddie_tool_names_ignores_other_protocols():
    rules = load_rules("classifier/rules/default_rules.yaml")
    features = make_features(
        protocol="http",
        command_names=["sqlmap"],
    )

    result = evaluate_rules(features, rules)

    assert "script_kiddie_tool_names" not in {m.rule_id for m in result.matched_rules}


def test_default_yaml_rules_load_and_match_expected_features():
    rules = load_rules("classifier/rules/default_rules.yaml")

    result = evaluate_rules(make_features(), rules)

    assert rules.rules_version == "1.0.0"
    assert result.rules_version == "1.0.0"
    assert {match.rule_id for match in result.matched_rules} == {
        "automated_discovery_burst",
        "sensitive_file_probe",
        "interactive_low_and_slow",
    }
