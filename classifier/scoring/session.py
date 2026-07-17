from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from classifier.features.session import SessionFeatures
from classifier.rules.engine import ACTOR_LABELS, ActorLabel, RuleEvaluation, RuleMatch


ClassificationStatus = Literal["complete", "partial", "insufficient_data"]
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
    "vulnerability_exploitation",
]
SafeguardPriority = Literal["low", "medium", "high", "critical"]
DeceptionActionName = Literal["adaptive_response_delay"]
AlertActionName = Literal["notify_analyst"]
AnalystRecommendationName = Literal[
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


class FeatureSummary(BaseModel):
    """Compact feature snapshot included in classifier outputs."""

    session_id: str
    protocol: str
    duration_seconds: float = Field(ge=0)
    command_count: int = Field(ge=0)
    commands_per_minute: float = Field(ge=0)
    discovery_command_count: int = Field(ge=0)
    file_read_count: int = Field(ge=0)
    sensitive_file_read_count: int = Field(ge=0)
    decoy_files_surfaced_count: int = Field(ge=0)
    exit_command_present: bool
    # 0.0 (clearly bot-speed) to 1.0 (clearly human-paced); None when the
    # session has fewer than two commands and so has no cadence to score.
    human_timing_score: float | None = Field(default=None, ge=0, le=1)

    class Config:
        extra = "forbid"


class DeceptionAction(BaseModel):
    """A safe action the honeypot can apply without an external service."""

    action: DeceptionActionName
    delay_seconds: float = Field(ge=0, le=10)
    rationale: str

    class Config:
        extra = "forbid"


class AlertAction(BaseModel):
    """A typed instruction consumed by alert delivery."""

    action: AlertActionName
    priority: SafeguardPriority
    minimum_risk_level: RiskLevel
    rationale: str
    supporting_evidence: list[str]

    class Config:
        extra = "forbid"


class AnalystRecommendation(BaseModel):
    """The next investigation step shown to an analyst."""

    action: AnalystRecommendationName
    priority: SafeguardPriority
    rationale: str
    supporting_evidence: list[str]

    class Config:
        extra = "forbid"


class ClassificationSummary(BaseModel):
    """Aggregated classifier output derived from matched YAML rules."""

    classifier_version: str
    rules_version: str
    classification_status: ClassificationStatus
    insufficient_data_reason: str | None
    actor_label: ActorLabel | None
    actor_votes: dict[str, int]
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    behavior_stage: BehaviorStage
    intent: Intent
    persona_context: PersonaContext
    feature_summary: FeatureSummary | None
    deception_action: DeceptionAction | None
    alert_action: AlertAction | None
    analyst_recommendation: AnalystRecommendation | None
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
        status, reason = _classification_status(features, [])
        return ClassificationSummary(
            classifier_version=CLASSIFIER_VERSION,
            rules_version=evaluation.rules_version,
            classification_status=status,
            insufficient_data_reason=reason,
            actor_label=None,
            actor_votes=_actor_vote_tally([]),
            confidence=0.0,
            risk_score=0,
            risk_level="none",
            behavior_stage="none",
            intent="unknown",
            persona_context=_persona_context(features),
            feature_summary=_feature_summary(features),
            deception_action=None,
            alert_action=None,
            analyst_recommendation=None,
            mitre_tags=[],
            evidence=[],
            matched_rule_ids=[],
        )

    matched_rules = evaluation.matched_rules
    status, reason = _classification_status(features, matched_rules)
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
        classification_status=status,
        insufficient_data_reason=reason,
        actor_label=actor_label,
        actor_votes=_actor_vote_tally(matched_rules),
        confidence=confidence,
        risk_score=risk_score,
        risk_level=risk_level,
        behavior_stage=behavior_stage,
        intent=intent,
        persona_context=persona_context,
        feature_summary=_feature_summary(features),
        deception_action=_deception_action(risk_level),
        alert_action=_alert_action(risk_level, evidence),
        analyst_recommendation=_analyst_recommendation(
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


def _classification_status(
    features: SessionFeatures | None,
    matched_rules: list[RuleMatch],
) -> tuple[ClassificationStatus, str | None]:
    """Decide whether a session had enough signal to classify safely.

    A session with fewer than two observed commands carries no meaningful
    command pattern and no inter-command timing signal at all (there's no
    auth step to fall back on), so it can never support a confident actor
    label regardless of connection duration -- not even when the lone
    command happens to match a rule (eg. a single "sqlmap ..." line matching
    script_kiddie_tool_names). One coincidental match on one command
    overstates confidence; that case is "partial", not "complete", and a
    session with one command that matches nothing at all has no evidence
    whatsoever, so that's "insufficient_data" rather than a low-confidence
    guess.
    """
    if features is None:
        if matched_rules:
            return "complete", None
        return "insufficient_data", "session features were not supplied"

    command_count = features.command_count

    if command_count == 0:
        if matched_rules:
            return "partial", (
                "no commands were observed; matching evidence alone isn't "
                "enough signal to classify with full confidence"
            )
        return "insufficient_data", (
            "no commands were observed during the session, so no reliable "
            "command or timing evidence is available"
        )

    if command_count == 1:
        if matched_rules:
            return "partial", (
                "only one command was observed; a single matching rule isn't "
                "enough signal to classify with full confidence"
            )
        return "insufficient_data", (
            "fewer than two commands were observed during the session, so no "
            "reliable command or timing evidence is available"
        )

    if matched_rules:
        return "complete", None
    return "partial", (
        "commands were observed but none matched a classification rule "
        "confidently enough to assign an actor label"
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


def _feature_summary(features: SessionFeatures | None) -> FeatureSummary | None:
    if features is None:
        return None

    return FeatureSummary(
        session_id=str(features.session_id),
        protocol=features.protocol,
        duration_seconds=features.duration_seconds,
        command_count=features.command_count,
        commands_per_minute=features.commands_per_minute,
        discovery_command_count=features.discovery_command_count,
        file_read_count=features.file_read_count,
        sensitive_file_read_count=features.sensitive_file_read_count,
        decoy_files_surfaced_count=features.decoy_files_surfaced_count,
        exit_command_present=features.exit_command_present,
        human_timing_score=features.human_timing_score,
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

    # T1110 (Brute Force) is every brute_force_bot rule's only tag (repeat
    # connections, raw auth attempts, FTP/Telnet/HTTP credential bursts) --
    # without this branch, all of those matched, "complete" classifications
    # fell through to behavior_stage="none"/intent="unknown" despite being
    # unambiguously credential-access activity.
    if "T1552.001" in tag_set or "T1110" in tag_set:
        return "credential_access", "credential_theft"
    if "T1005" in tag_set:
        return "collection", "data_access"
    # T1190 (Exploit Public-Facing Application) takes priority over T1595:
    # script_kiddie_tool_names tags a session with both at once (a known
    # exploit/scanning tool typed directly), and running one is a more
    # specific, further-along signal than the general active-scanning
    # T1595/T1087/T1082 reconnaissance bucket below.
    if "T1190" in tag_set:
        return "execution", "vulnerability_exploitation"
    if "T1087" in tag_set or "T1082" in tag_set or "T1595" in tag_set:
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


def _deception_action(risk_level: RiskLevel) -> DeceptionAction | None:
    if risk_level not in {"medium", "high", "critical"}:
        return None
    delay = {"medium": 0.5, "high": 1.0, "critical": 2.0}[risk_level]
    return DeceptionAction(
        action="adaptive_response_delay",
        delay_seconds=delay,
        rationale="Slow suspicious interaction while preserving a believable session.",
    )


def _alert_action(
    risk_level: RiskLevel,
    evidence: list[EvidenceItem],
) -> AlertAction | None:
    if risk_level not in {"medium", "high", "critical"}:
        return None
    return AlertAction(
        action="notify_analyst",
        priority="critical" if risk_level == "critical" else risk_level,
        minimum_risk_level=risk_level,
        rationale="The observed session crossed the live analyst notification threshold.",
        supporting_evidence=[item.text for item in evidence],
    )


def _analyst_recommendation(
    risk_level: RiskLevel,
    behavior_stage: BehaviorStage,
    intent: Intent,
    persona_context: PersonaContext,
    evidence: list[EvidenceItem],
) -> AnalystRecommendation | None:
    supporting_evidence = [item.text for item in evidence]

    if risk_level in {"high", "critical"}:
        return AnalystRecommendation(
                action="escalate_incident_review",
                priority="critical" if risk_level == "critical" else "high",
                rationale=(
                    "High-risk classifier output should be reviewed before "
                    "any external enforcement action."
                ),
                supporting_evidence=supporting_evidence,
        )

    if intent == "credential_theft":
        return AnalystRecommendation(
                action="rotate_exposed_credentials",
                priority="high",
                rationale=(
                    "Credential-access behavior indicates possible interest "
                    "in reusable secrets."
                ),
                supporting_evidence=supporting_evidence,
        )

    if intent == "vulnerability_exploitation":
        return AnalystRecommendation(
                action="increase_source_monitoring",
                priority="high",
                rationale=(
                    "A known exploit or scanning tool was run directly "
                    "against the service, warranting closer monitoring of "
                    "this source."
                ),
                supporting_evidence=supporting_evidence,
        )

    if (
        behavior_stage == "collection"
        and persona_context.decoy_files_surfaced
    ):
        return AnalystRecommendation(
                action="review_decoy_exposure",
                priority="medium",
                rationale=(
                    "Surfaced decoy files provide analyst context for "
                    "follow-up investigation."
                ),
                supporting_evidence=persona_context.decoy_files_surfaced,
        )

    if behavior_stage == "discovery":
        return AnalystRecommendation(
                action="increase_source_monitoring",
                priority=(
                    "medium"
                    if risk_level in {"medium", "high", "critical"}
                    else "low"
                ),
                rationale=(
                    "Discovery activity may precede credential access, "
                    "collection, or exploitation attempts."
                ),
                supporting_evidence=supporting_evidence,
        )

    if behavior_stage == "execution":
        return AnalystRecommendation(
                action="preserve_session_transcript",
                priority="medium",
                rationale=(
                    "Interactive execution behavior is useful for analyst "
                    "review and replay."
                ),
                supporting_evidence=supporting_evidence,
        )

    # This function is only ever called once a rule has matched (see
    # summarize_rule_evaluation) -- a "complete" classification must always
    # give an analyst somewhere to look next, even when the matched rule's
    # behavior_stage/intent didn't fit one of the more specific cases above
    # (eg. a brute_force_bot match carrying only T1110, with no discovery,
    # collection, or execution signal alongside it).
    return AnalystRecommendation(
            action="increase_source_monitoring",
            priority="low" if risk_level in {"none", "low"} else "medium",
            rationale=(
                "This session matched a classification rule; monitor the "
                "source for further activity even though no more specific "
                "follow-up action is indicated yet."
            ),
            supporting_evidence=supporting_evidence,
    )


def _unique_ordered(values) -> list[str]:
    seen = set()
    unique_values = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique_values.append(value)
    return unique_values
