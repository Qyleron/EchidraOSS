import asyncio
import json
import logging
import uuid

import pytest
from pydantic import ValidationError

import classifier.pipeline as pipeline_module
from classifier.pipeline import (
    classify_session,
    classify_session_jsonl,
    classify_session_jsonl_file,
    classify_session_jsonl_lines,
    classify_session_record,
    schedule_auto_classification,
)
from classifier.rules.engine import ClassificationRule, RuleSet
from classifier.schemas.session import SessionRecord


def make_session(
    commands,
    duration_seconds=12.0,
    end_reason="disconnect",
    decoy_files_surfaced=None,
):
    started_at = 100.0
    command_events = [
        {
            "cmd": command,
            "timestamp": started_at + offset,
        }
        for command, offset in commands
    ]

    return SessionRecord.parse_obj({
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": "tcp_shell",
        "peer_ip": "127.0.0.1",
        "peer_port": 4444,
        "persona_id": "generic_linux",
        "started_at": started_at,
        "ended_at": started_at + duration_seconds,
        "duration_seconds": duration_seconds,
        "end_reason": end_reason,
        "command_count": len(command_events),
        "commands": command_events,
        "decoy_files_surfaced": decoy_files_surfaced or [],
    })


def make_record(**overrides):
    session = make_session(
        [
            ("whoami", 1.0),
            ("hostname", 3.0),
            ("ls", 6.0),
            ("cat /etc/passwd", 9.0),
        ],
        duration_seconds=13.0,
        decoy_files_surfaced=["/etc/passwd"],
    )
    record = json.loads(session.json())
    record.update(overrides)
    return record


def test_classify_session_runs_default_post_session_pipeline():
    session = make_session(
        [
            ("whoami", 1.0),
            ("hostname", 3.0),
            ("ls", 6.0),
            ("cat /etc/passwd", 9.0),
        ],
        duration_seconds=13.0,
        decoy_files_surfaced=["/etc/passwd"],
    )

    summary = classify_session(session)

    assert summary.rules_version == "1.0.0"
    assert summary.actor_label == "commodity_bot"
    assert summary.risk_level == "medium"
    assert summary.behavior_stage == "credential_access"
    assert summary.intent == "credential_theft"
    assert summary.matched_rule_ids == [
        "sensitive_file_probe",
        "interactive_low_and_slow",
    ]
    assert summary.feature_summary is not None
    assert summary.feature_summary.session_id == str(session.session_id)
    assert summary.feature_summary.command_count == 4
    assert summary.feature_summary.sensitive_file_read_count == 1
    assert summary.deception_action.action == "adaptive_response_delay"
    assert summary.alert_action.action == "notify_analyst"
    assert summary.analyst_recommendation.action == "rotate_exposed_credentials"


def test_active_classification_is_always_marked_partial():
    session = make_session(
        [("whoami", 1.0), ("hostname", 2.0), ("ls", 3.0)],
        duration_seconds=4.0,
    )

    summary = classify_session(session, active=True)

    assert summary.classification_status == "partial"
    assert "active session" in summary.insufficient_data_reason
    assert summary.matched_rule_ids == ["automated_discovery_burst"]


def test_authentication_attempt_rule_ignores_unfinished_username_only():
    """A single unfinished username line (no password yet) must not match --
    the rule requires a completed USER+PASS submission (auth_attempt_count >= 2)."""
    session = make_session([("USER admin", 1.0)], duration_seconds=2.0)
    record = json.loads(session.json())
    record["protocol"] = "ftp"

    summary = classify_session(SessionRecord.parse_obj(record), active=True)

    assert "authentication_attempt" not in summary.matched_rule_ids


def test_authentication_attempt_rule_matches_completed_credential_submission():
    session = make_session(
        [("USER admin", 1.0), ("PASS hunter2", 1.5)], duration_seconds=2.0
    )
    record = json.loads(session.json())
    record["protocol"] = "ftp"

    summary = classify_session(SessionRecord.parse_obj(record), active=True)

    assert summary.classification_status == "partial"
    assert "authentication_attempt" in summary.matched_rule_ids
    assert summary.alert_action.action == "notify_analyst"


def test_classify_session_accepts_custom_ruleset():
    rule = ClassificationRule.parse_obj({
        "id": "logout_observed",
        "name": "Logout observed",
        "actor_label": "script_kiddie",
        "confidence": 0.51,
        "risk_score": 10,
        "mitre_tags": [],
        "evidence": ["Session ended with an explicit logout command."],
        "conditions": [
            {
                "field": "exit_command_present",
                "operator": "equals",
                "value": True,
            },
        ],
    })
    session = make_session(
        [
            ("whoami", 1.0),
            ("exit", 2.0),
        ],
        end_reason="logout",
    )

    summary = classify_session(
        session,
        RuleSet(rules_version="custom-test", rules=[rule]),
    )

    assert summary.rules_version == "custom-test"
    assert summary.actor_label == "script_kiddie"
    assert summary.risk_level == "low"
    assert summary.matched_rule_ids == ["logout_observed"]
    assert summary.feature_summary is not None
    assert summary.feature_summary.exit_command_present is True


def test_classify_session_record_validates_and_classifies_decoded_logs():
    record = make_record()

    summary = classify_session_record(record)

    assert summary.feature_summary is not None
    assert summary.feature_summary.session_id == record["session_id"]
    assert summary.behavior_stage == "credential_access"
    assert summary.matched_rule_ids == [
        "sensitive_file_probe",
        "interactive_low_and_slow",
    ]


def test_classify_session_jsonl_classifies_logger_lines():
    record = make_record()

    summary = classify_session_jsonl(json.dumps(record))

    assert summary.feature_summary is not None
    assert summary.feature_summary.command_count == 4
    assert summary.intent == "credential_theft"


def test_classify_session_record_rejects_invalid_logs():
    record = make_record(command_count=99)

    with pytest.raises(ValidationError, match="command_count"):
        classify_session_record(record)


def test_classify_session_jsonl_rejects_malformed_json():
    """Malformed JSON input should raise JSONDecodeError without crashing."""
    malformed_json = '{"session_id": "truncated-no-closing'

    with pytest.raises(json.JSONDecodeError):
        classify_session_jsonl(malformed_json)


def test_classify_session_jsonl_lines_classifies_multiple_records():
    first_record = make_record()
    second_record = make_record()

    summaries = classify_session_jsonl_lines([
        json.dumps(first_record),
        "",
        json.dumps(second_record),
    ])

    assert [summary.feature_summary.command_count for summary in summaries] == [
        4,
        4,
    ]
    assert [summary.intent for summary in summaries] == [
        "credential_theft",
        "credential_theft",
    ]


def test_classify_session_jsonl_file_classifies_existing_logs(tmp_path):
    log_path = tmp_path / "sessions.jsonl"
    records = [
        make_record(),
        make_record(),
    ]
    log_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    summaries = classify_session_jsonl_file(log_path)

    assert len(summaries) == 2
    assert [summary.rules_version for summary in summaries] == [
        "1.0.0",
        "1.0.0",
    ]


class _AlwaysFullQueue:
    """Stand-in for the classification queue that always rejects puts."""

    def put_nowait(self, item):
        raise asyncio.QueueFull()


def _use_fake_clock(monkeypatch):
    """Give the drop-logging rate limiter a clock the test controls, instead
    of racing real wall-clock time against _DROP_LOG_INTERVAL_SECONDS."""
    fake_now = [1_000.0]
    monkeypatch.setattr(pipeline_module.time, "monotonic", lambda: fake_now[0])
    return fake_now


def test_queue_full_drops_log_first_immediately_then_aggregate(monkeypatch, caplog):
    """The first drop must never be silent, but a flood dropping many
    sessions a second must not log one warning per drop either -- only the
    first and the next one past the rate-limit interval should log,
    carrying the accumulated count."""
    monkeypatch.setattr(pipeline_module, "_classification_queue", _AlwaysFullQueue())
    monkeypatch.setattr(pipeline_module, "_dropped_queue_full_count", 0)
    monkeypatch.setattr(pipeline_module, "_dropped_queue_full_last_logged", 0.0)
    fake_now = _use_fake_clock(monkeypatch)
    session = make_session([("whoami", 1.0)], duration_seconds=2.0)

    with caplog.at_level(logging.WARNING, logger=pipeline_module.logger.name):
        schedule_auto_classification(session)  # 1st drop -> logs immediately
        fake_now[0] += 1
        schedule_auto_classification(session)  # within interval -> suppressed
        fake_now[0] += 1
        schedule_auto_classification(session)  # within interval -> suppressed

    assert len(caplog.records) == 1
    assert "dropped 1 session" in caplog.records[0].message

    fake_now[0] += pipeline_module._DROP_LOG_INTERVAL_SECONDS
    with caplog.at_level(logging.WARNING, logger=pipeline_module.logger.name):
        schedule_auto_classification(session)  # past the interval -> flushes

    assert len(caplog.records) == 2
    assert "dropped 3 session" in caplog.records[1].message


def test_no_workers_started_drops_log_first_immediately_then_aggregate(monkeypatch, caplog):
    monkeypatch.setattr(pipeline_module, "_classification_queue", None)
    monkeypatch.setattr(pipeline_module, "_dropped_no_workers_count", 0)
    monkeypatch.setattr(pipeline_module, "_dropped_no_workers_last_logged", 0.0)
    fake_now = _use_fake_clock(monkeypatch)
    session = make_session([("whoami", 1.0)], duration_seconds=2.0)

    with caplog.at_level(logging.WARNING, logger=pipeline_module.logger.name):
        schedule_auto_classification(session)
        fake_now[0] += 1
        schedule_auto_classification(session)

    assert len(caplog.records) == 1
    assert "dropped 1 session" in caplog.records[0].message

    fake_now[0] += pipeline_module._DROP_LOG_INTERVAL_SECONDS
    with caplog.at_level(logging.WARNING, logger=pipeline_module.logger.name):
        schedule_auto_classification(session)

    assert len(caplog.records) == 2
    assert "dropped 2 session" in caplog.records[1].message
