import uuid

from classifier.features.session import SessionFeatures
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


def _risk_level_for_score(score):
    evaluation = RuleEvaluation(matched_rules=[
        make_match("rule", "automated_scanner", 1.0, score),
    ])
    return summarize_rule_evaluation(evaluation).risk_level
