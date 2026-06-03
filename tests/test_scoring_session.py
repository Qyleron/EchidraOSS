from tests.conftest import make_features

from classifier.rules.engine import RuleEvaluation, RuleMatch
from classifier.scoring.session import summarize_rule_evaluation


def make_match(
    rule_id,
    actor_label,
    confidence,
    risk_score,
    mitre_tags=None,
    evidence=None,
):
    return RuleMatch(
        rule_id=rule_id,
        name=rule_id.replace("_", " ").title(),
        actor_label=actor_label,
        confidence=confidence,
        risk_score=risk_score,
        mitre_tags=mitre_tags or [],
        evidence=evidence or [],
    )


def test_empty_rule_evaluation_returns_no_risk_summary():
    summary = summarize_rule_evaluation(RuleEvaluation(matched_rules=[]))

    assert summary.actor_label is None
    assert summary.actor_votes == {
        "automated_scanner": 0,
        "brute_force_bot": 0,
        "commodity_bot": 0,
        "script_kiddie": 0,
        "skilled_human_operator": 0,
    }
    assert summary.confidence == 0.0
    assert summary.risk_score == 0
    assert summary.risk_level == "none"
    assert summary.behavior_stage == "none"
    assert summary.intent == "unknown"
    assert summary.safeguard_recommendations == []
    assert summary.classifier_version == "1.0.0"
    assert summary.rules_version == "unversioned"
    assert summary.persona_context.persona_id is None
    assert summary.persona_context.decoy_files_surfaced == []
    assert summary.mitre_tags == []
    assert summary.evidence == []
    assert summary.matched_rule_ids == []


def test_summary_aggregates_risk_evidence_and_mitre_tags():
    evaluation = RuleEvaluation(rules_version="1.0.0", matched_rules=[
        make_match(
            "automated_discovery_burst",
            "automated_scanner",
            0.72,
            35,
            mitre_tags=["T1087", "T1082"],
            evidence=["High command rate."],
        ),
        make_match(
            "sensitive_file_probe",
            "commodity_bot",
            0.78,
            55,
            mitre_tags=["T1005", "T1552.001", "T1082"],
            evidence=["Sensitive file read.", "Decoy was surfaced."],
        ),
    ])
    features = make_features(
        persona_id="ubuntu_web_server",
        decoy_files_surfaced=["/var/www/html/wp-config.php"],
        decoy_files_surfaced_count=1,
    )

    summary = summarize_rule_evaluation(evaluation, features)

    assert summary.classifier_version == "1.0.0"
    assert summary.rules_version == "1.0.0"
    assert summary.actor_label == "commodity_bot"
    assert summary.actor_votes == {
        "automated_scanner": 1,
        "brute_force_bot": 0,
        "commodity_bot": 1,
        "script_kiddie": 0,
        "skilled_human_operator": 0,
    }
    assert summary.confidence == 0.39
    assert summary.risk_score == 45
    assert summary.risk_level == "medium"
    assert summary.behavior_stage == "credential_access"
    assert summary.intent == "credential_theft"
    assert [
        recommendation.action
        for recommendation in summary.safeguard_recommendations
    ] == [
        "rotate_exposed_credentials",
    ]
    assert summary.safeguard_recommendations[0].priority == "high"
    assert (
        summary.safeguard_recommendations[0].tool_category
        == "IAM or secrets manager"
    )
    assert summary.persona_context.persona_id == "ubuntu_web_server"
    assert summary.persona_context.decoy_files_surfaced == [
        "/var/www/html/wp-config.php",
    ]
    assert summary.mitre_tags == ["T1087", "T1082", "T1005", "T1552.001"]
    assert [item.text for item in summary.evidence] == [
        "High command rate.",
        "Sensitive file read.",
        "Decoy was surfaced.",
    ]
    assert summary.matched_rule_ids == [
        "automated_discovery_burst",
        "sensitive_file_probe",
    ]


def test_risk_level_thresholds_are_stable():
    assert _risk_level_for_score(0) == "none"
    assert _risk_level_for_score(1) == "low"
    assert _risk_level_for_score(40) == "medium"
    assert _risk_level_for_score(65) == "high"
    assert _risk_level_for_score(85) == "critical"


def test_summary_maps_discovery_behavior_stage_and_intent():
    evaluation = RuleEvaluation(matched_rules=[
        make_match(
            "automated_discovery_burst",
            "automated_scanner",
            0.72,
            35,
            mitre_tags=["T1087", "T1082"],
        ),
    ])

    summary = summarize_rule_evaluation(evaluation)

    assert summary.behavior_stage == "discovery"
    assert summary.intent == "reconnaissance"


def test_summary_maps_interactive_execution_stage_and_intent():
    evaluation = RuleEvaluation(matched_rules=[
        make_match(
            "interactive_low_and_slow",
            "skilled_human_operator",
            0.64,
            45,
            mitre_tags=["T1059"],
        ),
    ])

    summary = summarize_rule_evaluation(evaluation)

    assert summary.behavior_stage == "execution"
    assert summary.intent == "interactive_operation"
    assert [
        recommendation.action
        for recommendation in summary.safeguard_recommendations
    ] == [
        "preserve_session_transcript",
    ]


def test_summary_recommends_escalation_for_high_risk_activity():
    evaluation = RuleEvaluation(matched_rules=[
        make_match(
            "high_risk_collection",
            "skilled_human_operator",
            0.91,
            88,
            mitre_tags=["T1005"],
            evidence=["Bulk sensitive data access."],
        ),
    ])

    summary = summarize_rule_evaluation(evaluation)

    assert [
        recommendation.action
        for recommendation in summary.safeguard_recommendations
    ] == [
        "escalate_incident_review",
    ]
    assert summary.safeguard_recommendations[0].priority == "critical"
    assert summary.safeguard_recommendations[0].supporting_evidence == [
        "Bulk sensitive data access.",
    ]


def test_summary_recommends_decoy_review_for_collection_with_decoys():
    evaluation = RuleEvaluation(matched_rules=[
        make_match(
            "sensitive_file_probe",
            "commodity_bot",
            0.78,
            55,
            mitre_tags=["T1005"],
            evidence=["Sensitive file read."],
        ),
    ])
    features = make_features(
        decoy_files_surfaced=["/var/www/html/wp-config.php"],
        decoy_files_surfaced_count=1,
    )

    summary = summarize_rule_evaluation(evaluation, features)

    assert [
        recommendation.action
        for recommendation in summary.safeguard_recommendations
    ] == [
        "review_decoy_exposure",
    ]
    assert summary.safeguard_recommendations[0].supporting_evidence == [
        "/var/www/html/wp-config.php",
    ]


def _risk_level_for_score(score):
    evaluation = RuleEvaluation(matched_rules=[
        make_match("rule", "automated_scanner", 1.0, score),
    ])
    return summarize_rule_evaluation(evaluation).risk_level
