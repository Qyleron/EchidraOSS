from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from classifier.features.session import SessionFeatures
from classifier.rules.engine import ACTOR_LABELS, ActorLabel, RuleEvaluation, RuleMatch


RiskLevel = Literal["none", "low", "medium", "high", "critical"]
BehaviorStage = Literal[
    "none",
    "discovery",
    "credential_access",
    "collection",
    "execution",
]
Intent = Literal[
    "unknown",
    "reconnaissance",
    "credential_theft",
    "data_access",
    "interactive_operation",
]
SafeguardPriority = Literal["low", "medium", "high", "critical"]
SafeguardAction = Literal[
    "increase_source_monitoring",
    "preserve_session_transcript",
    "review_decoy_exposure",
    "rotate_exposed_credentials",
    "escalate_incident_review",
]
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


class SafeguardRecommendation(BaseModel):
    """Advisory control recommendation for external security tools."""

    action: SafeguardAction
    priority: SafeguardPriority
    tool_category: str
    rationale: str
    supporting_evidence: list[str]

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
    behavior_stage: BehaviorStage
    intent: Intent
    persona_context: PersonaContext
    safeguard_recommendations: list[SafeguardRecommendation]
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
            behavior_stage="none",
            intent="unknown",
            persona_context=_persona_context(features),
            safeguard_recommendations=[],
            mitre_tags=[],
            evidence=[],
            matched_rule_ids=[],
        )

    matched_rules = evaluation.matched_rules
    risk_score = _combined_risk_score(matched_rules)
    actor_label, confidence = _actor_vote(matched_rules)
    risk_level = _risk_level(risk_score)
    mitre_tags = _unique_ordered(
        tag for match in matched_rules for tag in match.mitre_tags
    )
    behavior_stage, intent = _behavior_stage_and_intent(
        matched_rules,
        mitre_tags,
        features,
    )
    evidence = [
        EvidenceItem(rule_id=match.rule_id, text=text)
        for match in matched_rules
        for text in match.evidence
    ]
    persona_context = _persona_context(features)

    return ClassificationSummary(
        classifier_version=CLASSIFIER_VERSION,
        rules_version=evaluation.rules_version,
        actor_label=actor_label,
        actor_votes=_actor_vote_tally(matched_rules),
        confidence=confidence,
        risk_score=risk_score,
        risk_level=risk_level,
        behavior_stage=behavior_stage,
        intent=intent,
        persona_context=persona_context,
        safeguard_recommendations=_safeguard_recommendations(
            risk_level=risk_level,
            behavior_stage=behavior_stage,
            intent=intent,
            persona_context=persona_context,
            evidence=evidence,
        ),
        mitre_tags=mitre_tags,
        evidence=evidence,
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
        votes[match.actor_label] += 1
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


def _behavior_stage_and_intent(
    matches: list[RuleMatch],
    mitre_tags: list[str],
    features: SessionFeatures | None,
) -> tuple[BehaviorStage, Intent]:
    tag_set = set(mitre_tags)
    rule_ids = {match.rule_id for match in matches}

    if "T1552.001" in tag_set:
        return "credential_access", "credential_theft"
    if "T1005" in tag_set:
        return "collection", "data_access"
    if "T1087" in tag_set or "T1082" in tag_set:
        return "discovery", "reconnaissance"
    if "T1059" in tag_set:
        return "execution", "interactive_operation"

    if features is not None:
        if features.sensitive_file_read_count > 0:
            return "collection", "data_access"
        if features.discovery_command_count > 0:
            return "discovery", "reconnaissance"

    if "interactive_low_and_slow" in rule_ids:
        return "execution", "interactive_operation"

    return "none", "unknown"


def _safeguard_recommendations(
    risk_level: RiskLevel,
    behavior_stage: BehaviorStage,
    intent: Intent,
    persona_context: PersonaContext,
    evidence: list[EvidenceItem],
) -> list[SafeguardRecommendation]:
    supporting_evidence = [item.text for item in evidence]
    recommendations = []

    if risk_level in {"high", "critical"}:
        recommendations.append(
            SafeguardRecommendation(
                action="escalate_incident_review",
                priority="critical" if risk_level == "critical" else "high",
                tool_category="SIEM/SOAR",
                rationale=(
                    "High-risk classifier output should be reviewed before "
                    "any external enforcement action."
                ),
                supporting_evidence=supporting_evidence,
            )
        )

    if intent == "credential_theft":
        recommendations.append(
            SafeguardRecommendation(
                action="rotate_exposed_credentials",
                priority="high",
                tool_category="IAM or secrets manager",
                rationale=(
                    "Credential-access behavior indicates possible interest "
                    "in reusable secrets."
                ),
                supporting_evidence=supporting_evidence,
            )
        )

    if (
        behavior_stage == "collection"
        and persona_context.decoy_files_surfaced
    ):
        recommendations.append(
            SafeguardRecommendation(
                action="review_decoy_exposure",
                priority="medium",
                tool_category="SIEM or ticketing system",
                rationale=(
                    "Surfaced decoy files provide analyst context for "
                    "follow-up investigation."
                ),
                supporting_evidence=persona_context.decoy_files_surfaced,
            )
        )

    if behavior_stage == "discovery":
        recommendations.append(
            SafeguardRecommendation(
                action="increase_source_monitoring",
                priority=(
                    "medium"
                    if risk_level in {"medium", "high", "critical"}
                    else "low"
                ),
                tool_category="Firewall, WAF, or SIEM",
                rationale=(
                    "Discovery activity may precede credential access, "
                    "collection, or exploitation attempts."
                ),
                supporting_evidence=supporting_evidence,
            )
        )

    if behavior_stage == "execution":
        recommendations.append(
            SafeguardRecommendation(
                action="preserve_session_transcript",
                priority="medium",
                tool_category="SIEM or case management",
                rationale=(
                    "Interactive execution behavior is useful for analyst "
                    "review and replay."
                ),
                supporting_evidence=supporting_evidence,
            )
        )

    return recommendations


def _unique_ordered(values) -> list[str]:
    seen = set()
    unique_values = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique_values.append(value)
    return unique_values
