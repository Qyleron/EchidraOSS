from __future__ import annotations

from pathlib import Path
from collections.abc import Iterable
from typing import Any, Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from classifier.features.session import SessionFeatures


ActorLabel = Literal[
    "automated_scanner",
    "brute_force_bot",
    "commodity_bot",
    "script_kiddie",
    "skilled_human_operator",
]
ACTOR_LABELS: tuple[str, ...] = tuple(get_args(ActorLabel))

RuleOperator = Literal[
    "contains",
    "contains_any",
    "equals",
    "gt",
    "gte",
    "in",
    "lt",
    "lte",
    "not_equals",
]


class RuleCondition(BaseModel):
    """One boolean check against extracted session features."""

    field: str = Field(min_length=1)
    operator: RuleOperator
    value: Any

    @model_validator(mode="after")
    def validate_operator_value_shape(self) -> "RuleCondition":
        operator = self.operator
        value = self.value

        if operator == "in" and not _is_non_string_iterable(value):
            raise ValueError("in operator value must be a non-string iterable")

        if operator == "contains_any" and not _is_non_string_iterable(value):
            raise ValueError("contains_any operator value must be a non-string iterable")

        return self

    model_config = ConfigDict(extra="forbid")


class ClassificationRule(BaseModel):
    """Editable YAML rule that can match one extracted session."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    actor_label: ActorLabel
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    mitre_tags: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    conditions: list[RuleCondition] = Field(min_length=1)

    @field_validator("mitre_tags")
    @classmethod
    def mitre_tags_must_not_be_empty(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.strip():
                raise ValueError("mitre_tags items cannot be empty")
        return value

    @field_validator("evidence")
    @classmethod
    def evidence_items_must_not_be_empty(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.strip():
                raise ValueError("evidence items cannot be empty")
        return value

    model_config = ConfigDict(extra="forbid")


class RuleSet(BaseModel):
    """Top-level YAML document containing all editable rules."""

    rules_version: str = "unversioned"
    rules: list[ClassificationRule] = Field(min_length=1)

    @model_validator(mode="after")
    def rule_ids_must_be_unique(self) -> "RuleSet":
        rules = self.rules or []
        rule_ids = [rule.id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("rule ids must be unique")
        return self

    model_config = ConfigDict(extra="forbid")


class RuleMatch(BaseModel):
    """One rule that matched a feature vector."""

    rule_id: str
    name: str
    actor_label: ActorLabel
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    mitre_tags: list[str]
    evidence: list[str]

    model_config = ConfigDict(extra="forbid")


class RuleEvaluation(BaseModel):
    """Deterministic result of applying a ruleset to session features."""

    rules_version: str = "unversioned"
    matched_rules: list[RuleMatch]

    @property
    def best_match(self) -> RuleMatch | None:
        if not self.matched_rules:
            return None

        return max(
            self.matched_rules,
            key=lambda match: (match.confidence, match.risk_score),
        )

    model_config = ConfigDict(extra="forbid")


def load_rules(path: str | Path) -> RuleSet:
    """Load and validate an editable YAML ruleset."""
    with Path(path).open("r", encoding="utf-8") as rule_file:
        raw_rules = yaml.safe_load(rule_file)

    if raw_rules is None:
        raise ValueError("rules file cannot be empty")

    return RuleSet.model_validate(raw_rules)


def evaluate_rules(
    features: SessionFeatures,
    rules: RuleSet | list[ClassificationRule],
) -> RuleEvaluation:
    """Return all rules whose conditions match the supplied features."""
    rule_list = rules.rules if isinstance(rules, RuleSet) else rules
    rules_version = rules.rules_version if isinstance(rules, RuleSet) else "unversioned"
    matches = []

    for rule in rule_list:
        if all(_condition_matches(features, condition) for condition in rule.conditions):
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    name=rule.name,
                    actor_label=rule.actor_label,
                    confidence=rule.confidence,
                    risk_score=rule.risk_score,
                    mitre_tags=list(rule.mitre_tags),
                    evidence=list(rule.evidence),
                )
            )

    return RuleEvaluation(rules_version=rules_version, matched_rules=matches)


def _condition_matches(
    features: SessionFeatures,
    condition: RuleCondition,
) -> bool:
    if not hasattr(features, condition.field):
        raise ValueError(f"Unknown feature field: {condition.field}")

    actual = getattr(features, condition.field)
    expected = condition.value

    if condition.operator == "contains":
        if not _is_non_string_iterable(actual):
            raise ValueError(f"Feature field is not iterable: {condition.field}")
        return expected in actual
    if condition.operator == "contains_any":
        if not _is_non_string_iterable(actual):
            raise ValueError(f"Feature field is not iterable: {condition.field}")
        return any(candidate in actual for candidate in expected)
    if condition.operator == "equals":
        return actual == expected
    if condition.operator == "gt":
        return actual is not None and actual > expected
    if condition.operator == "gte":
        return actual is not None and actual >= expected
    if condition.operator == "in":
        return actual in expected
    if condition.operator == "lt":
        return actual is not None and actual < expected
    if condition.operator == "lte":
        return actual is not None and actual <= expected
    if condition.operator == "not_equals":
        return actual != expected

    raise ValueError(f"Unsupported operator: {condition.operator}")


def _is_non_string_iterable(value: Any) -> bool:
    return isinstance(value, Iterable) and not isinstance(value, (str, bytes))
