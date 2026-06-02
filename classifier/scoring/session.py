from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from classifier.features.session import SessionFeatures
from classifier.rules.engine import ACTOR_LABELS, ActorLabel, RuleEvaluation, RuleMatch


RiskLevel = Literal["none", "low", "medium", "high", "critical"]
CLASSIFIER_VERSION = "1.0.0"
class EvidenceItem(BaseModel):
    """One normalized evidence sentence with its source rule."""

    rule_id: str
    text: str

    class Config:
        extra = "forbid"


class PersonaContext(BaseModel):
    """Persona and decoy exposure context used by analysts and dashboards."""

    persona_id: str | None
    decoy_files_surfaced: list[str]

    class Config:
        extra = "forbid"


class ClassificationSummary(BaseModel):
    """Aggregated classifier output derived from matched YAML rules."""

    classifier_version: str
    rules_version: str
    actor_label: ActorLabel | None
    actor_votes: dict[str, int]
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    persona_context: PersonaContext
    mitre_tags: list[str]
    evidence: list[EvidenceItem]
    matched_rule_ids: list[str]

    class Config:
        extra = "forbid"


def summarize_rule_evaluation(
    evaluation: RuleEvaluation,
    features: SessionFeatures | None = None,
) -> ClassificationSummary:
    """Aggregate rule matches into one risk and evidence summary."""
    if not evaluation.matched_rules:
        return ClassificationSummary(
            classifier_version=CLASSIFIER_VERSION,
            rules_version=evaluation.rules_version,
            actor_label=None,
            actor_votes=_actor_vote_tally([]),
            confidence=0.0,
            risk_score=0,
            risk_level="none",
            persona_context=_persona_context(features),
            mitre_tags=[],
            evidence=[],
            matched_rule_ids=[],
        )

    matched_rules = evaluation.matched_rules
    risk_score = _combined_risk_score(matched_rules)
    actor_label, confidence = _actor_vote(matched_rules)

    return ClassificationSummary(
        classifier_version=CLASSIFIER_VERSION,
        rules_version=evaluation.rules_version,
        actor_label=actor_label,
        actor_votes=_actor_vote_tally(matched_rules),
        confidence=confidence,
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        persona_context=_persona_context(features),
        mitre_tags=_unique_ordered(
            tag for match in matched_rules for tag in match.mitre_tags
        ),
        evidence=[
            EvidenceItem(rule_id=match.rule_id, text=text)
            for match in matched_rules
            for text in match.evidence
        ],
        matched_rule_ids=[match.rule_id for match in matched_rules],
    )


def _combined_risk_score(matches: list[RuleMatch]) -> int:
    weighted_scores = [
        match.risk_score * match.confidence
        for match in matches
    ]
    total_confidence = sum(match.confidence for match in matches)
    if total_confidence == 0:
        return max(match.risk_score for match in matches)

    return round(sum(weighted_scores) / total_confidence)


def _actor_vote(matches: list[RuleMatch]) -> tuple[ActorLabel, float]:
    votes = {actor_label: 0.0 for actor_label in ACTOR_LABELS}
    for match in matches:
        votes[match.actor_label] += match.confidence

    actor_label, vote_confidence = max(
        votes.items(),
        key=lambda item: (item[1], item[0]),
    )
    normalized_confidence = vote_confidence / len(matches)
    return actor_label, round(min(normalized_confidence, 1.0), 2)


def _actor_vote_tally(matches: list[RuleMatch]) -> dict[str, int]:
    votes = {actor_label: 0 for actor_label in ACTOR_LABELS}
    for match in matches:
        votes[match.actor_label] = votes.get(match.actor_label, 0) + 1
    return votes


def _persona_context(features: SessionFeatures | None) -> PersonaContext:
    if features is None:
        return PersonaContext(persona_id=None, decoy_files_surfaced=[])

    return PersonaContext(
        persona_id=features.persona_id,
        decoy_files_surfaced=list(features.decoy_files_surfaced),
    )


def _risk_level(risk_score: int) -> RiskLevel:
    if risk_score >= 85:
        return "critical"
    if risk_score >= 65:
        return "high"
    if risk_score >= 40:
        return "medium"
    if risk_score >= 1:
        return "low"
    return "none"


def _unique_ordered(values) -> list[str]:
    seen = set()
    unique_values = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique_values.append(value)
    return unique_values
