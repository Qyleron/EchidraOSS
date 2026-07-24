from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from classifier.pipeline import classify_session, classify_session_record
from classifier.schemas.session import SessionRecord
from classifier.storage import cli as storage_cli
from classifier.storage.config import (
    database_url_placeholder,
    get_database_url,
    redact_database_url,
)
from classifier.storage.models import (
    AlertEventRecord,
    ClassifierRunRecord,
    DashboardReportSummary,
    DashboardUserRecord,
    IssueRecord,
    ManualLabelInput,
    ManualLabelRecord,
    MitreTechnique,
    PersonaConfigInput,
    StoredClassifierRun,
    StoredSessionEvent,
)
from classifier.storage.repository import (
    DatabaseDriverMissingError,
    DatabaseNotConfiguredError,
    PersonaConfigAlreadyExistsError,
    PostgresClassifierRepository,
    _alert_password_key,
    _decrypt_alert_password,
    _encrypt_alert_password,
    classifier_run_insert_params,
    classifier_run_statements,
    manual_label_insert_params,
    classifier_signal_insert_params,
    classifier_run_list_query,
    dashboard_user_from_row,
    dashboard_user_insert_params,
    issue_from_row,
    issue_insert_params,
    issue_list_query,
    issue_upsert_statements,
    session_event_insert_params,
    session_insert_params,
    manual_label_from_row,
    manual_label_list_query,
    stored_classifier_run_from_rows,
)
from tests.test_classifier_pipeline import make_record


def test_database_url_reads_env_value(monkeypatch):
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://user:pass@db/echidra")

    assert get_database_url() == "postgresql://user:pass@db/echidra"


def test_database_url_returns_none_for_blank_env(monkeypatch):
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", " ")

    assert get_database_url() is None


def test_database_url_placeholder_detects_template_values():
    database_url = "postgresql://YOUR_USER:YOUR_PASSWORD@localhost:5432/echidra"

    assert database_url_placeholder(database_url) == "YOUR_USER"


def test_redact_database_url_hides_uri_password():
    database_url = "postgresql://echidra:p%40ss%2Fword@localhost:5432/echidra"

    assert (
        redact_database_url(database_url)
        == "postgresql://echidra:***@localhost:5432/echidra"
    )


def test_redact_database_url_hides_keyword_password():
    conninfo = "host=localhost dbname=echidra user=echidra password='p@ss word'"

    assert redact_database_url(conninfo) == (
        "host=localhost dbname=echidra user=echidra password=***"
    )


def test_repository_requires_database_url(monkeypatch):
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)

    with pytest.raises(DatabaseNotConfiguredError, match="ECHIDRA_DATABASE_URL"):
        PostgresClassifierRepository()


def _fake_persisted_salt_fetch_one(stored: dict):
    """Mimic UPSERT_ALERT_PASSWORD_SALT_SQL's ON CONFLICT ... COALESCE
    semantics: the first candidate salt persisted "wins" and every later
    call returns that same value, regardless of the new candidate passed in."""

    def fake_fetch_one(database_url, sql, params):
        if stored.get("value") is None:
            stored["value"] = params["salt"]
        return {"smtp_password_salt": stored["value"]}

    return fake_fetch_one


def test_alert_password_encryption_round_trips_plaintext(monkeypatch):
    monkeypatch.setenv("ECHIDRA_ALERT_SECRET", "test-alert-secret")
    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        _fake_persisted_salt_fetch_one({}),
    )

    database_url = "postgresql://example/echidra"
    encrypted = _encrypt_alert_password(database_url, "secret-password")

    assert encrypted is not None
    assert encrypted != "secret-password"
    assert _decrypt_alert_password(database_url, encrypted) == "secret-password"


def test_alert_password_salt_is_per_installation_not_hardcoded(monkeypatch):
    """Two installations (independent persisted salts) with the same
    ECHIDRA_ALERT_SECRET must derive different keys -- a fixed source-embedded
    salt would make the derived key identical across every deployment."""
    monkeypatch.setenv("ECHIDRA_ALERT_SECRET", "test-alert-secret")

    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        _fake_persisted_salt_fetch_one({}),
    )
    key_a = _alert_password_key("postgresql://install-a/echidra")

    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        _fake_persisted_salt_fetch_one({}),
    )
    key_b = _alert_password_key("postgresql://install-b/echidra")

    assert key_a != key_b


def test_alert_password_key_is_cached_and_skips_redundant_salt_lookup(monkeypatch):
    """PBKDF2 here is deliberately expensive (480k iterations) and the salt
    lookup is a DB round trip -- both must only happen once per (secret,
    database_url), not on every encrypt/decrypt call (eg. once per alert
    email dispatched)."""
    monkeypatch.setenv("ECHIDRA_ALERT_SECRET", "cache-test-secret")

    calls = {"count": 0}

    def counting_fetch_one(database_url, sql, params):
        calls["count"] += 1
        return {"smtp_password_salt": params["salt"]}

    monkeypatch.setattr("classifier.storage.repository._fetch_one", counting_fetch_one)

    database_url = "postgresql://cache-test/echidra"
    first = _alert_password_key(database_url)
    second = _alert_password_key(database_url)

    assert first == second
    assert calls["count"] == 1


def test_count_alert_events_returns_total_regardless_of_list_limit(monkeypatch):
    """count_alert_events must reflect every stored row, not the <=500-row
    cap list_alert_events applies for the history table."""
    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        lambda database_url, sql, params: {"total": 734},
    )

    total = PostgresClassifierRepository("postgresql://example/echidra").count_alert_events()

    assert total == 734


def test_insert_alert_event_persists_channel(monkeypatch):
    """A Slack-channel alert event must round-trip its channel, not silently
    default back to "email" (the column default) once actually stored."""
    captured = {}

    def fake_execute_insert(database_url, sql, params):
        captured.update(params)

    monkeypatch.setattr("classifier.storage.repository._execute_insert", fake_execute_insert)

    event = AlertEventRecord(
        persona_id="generic_linux",
        risk_level="high",
        channel="slack",
        contact_email=None,
        success=True,
    )
    PostgresClassifierRepository("postgresql://example/echidra").insert_alert_event(event)

    assert captured["channel"] == "slack"
    assert captured["contact_email"] is None


def test_list_alert_events_reads_back_channel(monkeypatch):
    monkeypatch.setattr(
        "classifier.storage.repository._fetch_all",
        lambda database_url, sql, params: [
            {
                "id": uuid4(),
                "run_id": None,
                "session_id": None,
                "persona_id": "generic_linux",
                "risk_level": "high",
                "actor_label": None,
                "channel": "slack",
                "contact_email": None,
                "sent_at": datetime.now(timezone.utc),
                "success": True,
                "error_message": None,
            }
        ],
    )

    events = PostgresClassifierRepository("postgresql://example/echidra").list_alert_events()

    assert events[0].channel == "slack"


def test_classifier_run_record_captures_searchable_summary_fields():
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    run_id = uuid4()

    record = ClassifierRunRecord.from_session_summary(
        session=session,
        summary=summary,
        run_id=run_id,
    )

    assert record.id == run_id
    assert record.session_id == session.session_id
    assert record.protocol == "tcp_shell"
    assert record.persona_id == "generic_linux"
    assert record.actor_label == "commodity_bot"
    assert record.risk_level == "medium"
    assert record.intent == "credential_theft"
    assert record.session_record["session_id"] == str(session.session_id)
    assert record.summary["matched_rule_ids"] == [
        "sensitive_file_probe",
        "interactive_low_and_slow",
    ]


def test_classifier_run_insert_params_match_storage_columns():
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)

    params = classifier_run_insert_params(record)

    assert params["id"] == record.id
    assert params["session_id"] == session.session_id
    assert params["risk_score"] == summary.risk_score
    assert params["risk_level"] == "medium"
    assert params["classification_status"] == summary.classification_status
    assert params["insufficient_data_reason"] == summary.insufficient_data_reason
    assert len(params) == 10


def test_session_insert_params_match_storage_columns():
    session = SessionRecord.parse_obj(
        make_record(latitude=12.9716, longitude=77.5946)
    )
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)

    params = session_insert_params(record)

    assert params["id"] == session.session_id
    assert params["protocol"] == "tcp_shell"
    assert params["peer_ip"] == "127.0.0.1"
    assert params["peer_port"] == 4444
    assert params["latitude"] == 12.9716
    assert params["longitude"] == 77.5946
    assert params["persona_id"] == "generic_linux"
    assert params["end_reason"] == "disconnect"
    assert params["country"] is None  # 127.0.0.1 is private/localhost
    assert len(params) == 11


def test_session_event_insert_params_normalize_timeline_and_exposures():
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)

    params = session_event_insert_params(record)

    assert params[0] == {
        "session_id": session.session_id,
        "event_index": 0,
        "event_type": "command",
        "event_value": "whoami",
        "observed_at": 101.0,
    }
    assert params[3]["event_value"] == "cat /etc/passwd"
    assert params[-1]["event_index"] == 4
    assert params[-1]["event_type"] == "decoy_file"
    assert params[-1]["event_value"] == "/etc/passwd"
    assert params[-1]["observed_at"] is None


def test_classifier_signal_insert_params_normalize_analysis_fields():
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)

    signals = classifier_signal_insert_params(record)
    signal_pairs = {
        (signal["signal_type"], signal["signal_key"], signal["signal_value"])
        for signal in signals
    }
    commodity_bot_vote = next(
        signal
        for signal in signals
        if signal["signal_type"] == "actor_vote"
        and signal["signal_key"] == "commodity_bot"
    )
    assert commodity_bot_vote["signal_value"] == "1"
    assert ("version", "classifier", "1.0.0") in signal_pairs
    assert ("matched_rule", "rule_id", "sensitive_file_probe") in signal_pairs
    assert ("mitre_tag", "attack_id", "T1005") in signal_pairs
    assert ("feature", "command_count", "4") in signal_pairs
    assert ("analyst_recommendation", "rotate_exposed_credentials", "high") in signal_pairs
    assert ("alert_action", "notify_analyst", "medium") in signal_pairs
    assert signals[0]["signal_index"] == 0
    assert signals[-1]["signal_index"] == len(signals) - 1


def test_classifier_run_statements_include_parent_and_child_writes():
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)

    statements = classifier_run_statements(record)
    statement_order = [
        sql.lstrip().splitlines()[0]
        for sql, _params in statements
    ]
    event_count = len(record.session_record["commands"]) + len(
        record.session_record["decoy_files_surfaced"]
    )
    signal_count = len(classifier_signal_insert_params(record))

    assert statement_order == (
        ["DELETE FROM session_events", "INSERT INTO sessions ("]
        + ["INSERT INTO session_events ("] * event_count
        + ["INSERT INTO classifier_runs ("]
        + ["INSERT INTO classifier_signals ("] * signal_count
    )


def test_manual_label_insert_params_match_storage_columns():
    label = ManualLabelRecord(
        **ManualLabelInput(
            session_id=uuid4(),
            actor_label="skilled_human_operator",
            risk_level="high",
            notes="Analyst confirmed interactive behavior.",
            labeled_by="analyst@example.com",
        ).dict()
    )

    params = manual_label_insert_params(label)

    assert params["id"] == label.id
    assert params["session_id"] == label.session_id
    assert params["actor_label"] == "skilled_human_operator"
    assert params["notes"] == "Analyst confirmed interactive behavior."
    assert params["labeled_by"] == "analyst@example.com"
    assert params["created_at"] == label.created_at


def test_stored_classifier_run_from_rows_includes_session_and_signals():
    session = SessionRecord.parse_obj(
        make_record(latitude=12.9716, longitude=77.5946)
    )
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)
    run_row = classifier_run_insert_params(record)
    session_params = session_insert_params(record)
    run_row.update(
        {
            "protocol": session_params["protocol"],
            "peer_ip": session_params["peer_ip"],
            "peer_port": session_params["peer_port"],
            "latitude": session_params["latitude"],
            "longitude": session_params["longitude"],
            "persona_id": session_params["persona_id"],
            "started_at": session_params["started_at"],
            "ended_at": session_params["ended_at"],
            "end_reason": session_params["end_reason"],
        }
    )
    signal_rows = [
        {
            "signal_index": 0,
            "signal_type": "version",
            "signal_key": "classifier",
            "signal_value": "1.0.0",
        },
        {
            "signal_index": 1,
            "signal_type": "matched_rule",
            "signal_key": "rule_id",
            "signal_value": "sensitive_file_probe",
        },
    ]

    stored_run = stored_classifier_run_from_rows(run_row, signal_rows)

    assert stored_run.id == record.id
    assert stored_run.session_id == session.session_id
    assert stored_run.protocol == "tcp_shell"
    assert stored_run.peer_ip == "127.0.0.1"
    assert stored_run.latitude == 12.9716
    assert stored_run.longitude == 77.5946
    assert stored_run.actor_label == "commodity_bot"
    assert stored_run.signals[1].signal_value == "sensitive_file_probe"
    assert stored_run.classification_status == summary.classification_status
    assert stored_run.insufficient_data_reason == summary.insufficient_data_reason


def test_stored_classifier_run_distinguishes_partial_from_complete_classification():
    """A run stored mid-session (real-time partial classification) must be
    told apart from a fully closed session once read back -- previously
    classification_status/insufficient_data_reason were computed but never
    made it into classifier_runs at all."""
    session = SessionRecord.parse_obj(make_record())
    active_summary = classify_session(session, active=True)
    assert active_summary.classification_status == "partial"

    record = ClassifierRunRecord.from_session_summary(session, active_summary)
    run_row = classifier_run_insert_params(record)
    session_params = session_insert_params(record)
    run_row.update(
        {
            "protocol": session_params["protocol"],
            "peer_ip": session_params["peer_ip"],
            "peer_port": session_params["peer_port"],
            "latitude": session_params["latitude"],
            "longitude": session_params["longitude"],
            "persona_id": session_params["persona_id"],
            "started_at": session_params["started_at"],
            "ended_at": session_params["ended_at"],
            "end_reason": session_params["end_reason"],
        }
    )

    stored_run = stored_classifier_run_from_rows(run_row, [])

    assert stored_run.classification_status == "partial"


def test_classifier_run_record_rejects_invalid_classification_status():
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    valid = ClassifierRunRecord.from_session_summary(session, summary)

    with pytest.raises(ValidationError, match="Classification status must be one of"):
        ClassifierRunRecord(**{**valid.dict(), "classification_status": "bogus_status"})


def test_stored_classifier_run_rejects_invalid_classification_status():
    with pytest.raises(ValidationError, match="Classification status must be one of"):
        StoredClassifierRun(
            id=uuid4(),
            session_id=uuid4(),
            protocol="tcp_shell",
            persona_id="generic_linux",
            started_at=1.0,
            ended_at=2.0,
            end_reason="disconnect",
            confidence=0.5,
            risk_score=10,
            risk_level="low",
            behavior_stage="reconnaissance",
            intent="unknown",
            classification_status="bogus_status",
        )


def test_manual_label_from_row_returns_storage_model():
    label = ManualLabelRecord(
        **ManualLabelInput(
            session_id=uuid4(),
            actor_label="commodity_bot",
            notes="Confirmed from command sequence.",
        ).dict()
    )
    row = manual_label_insert_params(label)

    stored_label = manual_label_from_row(row)

    assert stored_label == label


def test_dashboard_user_insert_params_match_storage_columns():
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash="pbkdf2_sha256$1$salt$digest",
    )

    params = dashboard_user_insert_params(user)

    assert params["id"] == user.id
    assert params["email"] == "analyst@example.com"
    assert params["password_hash"] == "pbkdf2_sha256$1$salt$digest"
    assert params["created_at"] == user.created_at


def test_dashboard_user_from_row_returns_storage_model():
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash="pbkdf2_sha256$1$salt$digest",
    )
    row = dashboard_user_insert_params(user)

    stored_user = dashboard_user_from_row(row)

    assert stored_user == user


def test_login_rate_limit_methods_are_backed_by_the_database(monkeypatch):
    """The login rate limiter must go through the repository (shared across
    every API worker process) rather than any process-local cache."""
    fetch_calls = []
    statement_calls = []
    insert_calls = []

    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        lambda database_url, sql, params: fetch_calls.append((sql, params)) or {"total": 3},
    )
    monkeypatch.setattr(
        "classifier.storage.repository._execute_statements",
        lambda database_url, statements: statement_calls.append(statements),
    )
    monkeypatch.setattr(
        "classifier.storage.repository._execute_insert",
        lambda database_url, sql, params: insert_calls.append((sql, params)),
    )

    repository = PostgresClassifierRepository("postgresql://example/echidra")

    total = repository.count_recent_login_failures("127.0.0.1:analyst@example.com", 900)
    assert total == 3
    assert fetch_calls[0][1] == {"key": "127.0.0.1:analyst@example.com", "window_seconds": 900}

    repository.record_login_failure("127.0.0.1:analyst@example.com", window_seconds=900)
    assert len(statement_calls[0]) == 2
    assert statement_calls[0][1][1] == {"key": "127.0.0.1:analyst@example.com"}

    repository.clear_login_failures("127.0.0.1:analyst@example.com")
    assert insert_calls[0][1] == {"key": "127.0.0.1:analyst@example.com"}


def test_issue_from_row_includes_mitre_techniques():
    issue_id = uuid4()
    row = {
        "id": issue_id,
        "title": "SSH password authentication is being targeted.",
        "severity": "high",
        "evidence": "37 brute-force sessions across 4 personas.",
        "recommended_fix": "Disable password login, enforce SSH keys.",
        "impact": "Reduces credential-access exposure.",
        "session_count": 37,
        "persona_count": 4,
        "status": "open",
        "created_at": datetime.now(timezone.utc),
    }
    mitre_rows = [
        {"issue_id": issue_id, "technique_index": 0, "technique_id": "T1110", "technique_name": "Brute Force"},
        {"issue_id": issue_id, "technique_index": 1, "technique_id": "T1078", "technique_name": "Valid Accounts"},
    ]

    issue = issue_from_row(row, mitre_rows)

    assert issue.id == issue_id
    assert issue.status == "open"
    assert [technique.id for technique in issue.mitre] == ["T1110", "T1078"]
    assert issue.mitre[0].name == "Brute Force"


def test_repository_list_issues_batches_mitre_techniques(monkeypatch):
    issue_id_1 = uuid4()
    issue_id_2 = uuid4()
    rows = [
        {
            "id": issue_id_1,
            "title": "SSH password authentication is being targeted.",
            "severity": "high",
            "evidence": "37 brute-force sessions across 4 personas.",
            "recommended_fix": "Disable password login.",
            "impact": "Reduces credential-access exposure.",
            "session_count": 37,
            "persona_count": 4,
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        },
        {
            "id": issue_id_2,
            "title": "Attackers fingerprint the system before staging payloads.",
            "severity": "medium",
            "evidence": "24 sessions ran whoami.",
            "recommended_fix": "Trim shell banner detail.",
            "impact": "Shortens attacker dwell time before detection.",
            "session_count": 24,
            "persona_count": 3,
            "status": "open",
            "created_at": datetime.now(timezone.utc),
        },
    ]
    mitre_rows = [
        {"issue_id": issue_id_1, "technique_index": 0, "technique_id": "T1110", "technique_name": "Brute Force"},
        {
            "issue_id": issue_id_2,
            "technique_index": 0,
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
        },
    ]
    fetch_all_calls = []

    def fake_fetch_all(database_url, sql, params):
        fetch_all_calls.append((sql, params))
        if "FROM issues" in sql:
            return rows
        return mitre_rows

    monkeypatch.setattr("classifier.storage.repository._fetch_all", fake_fetch_all)

    issues = PostgresClassifierRepository("postgresql://example/echidra").list_issues(status="open")

    # One query for issues, one batched query for all their MITRE techniques (no N+1).
    assert len(fetch_all_calls) == 2
    assert fetch_all_calls[1][1] == {"issue_ids": [issue_id_1, issue_id_2]}
    assert [issue.id for issue in issues] == [issue_id_1, issue_id_2]
    assert issues[0].mitre[0].id == "T1110"
    assert issues[1].mitre[0].id == "T1082"


def test_list_session_events_returns_ordered_timeline(monkeypatch):
    session_id = uuid4()
    rows = [
        {"event_index": 0, "event_type": "command", "event_value": "whoami", "observed_at": 100.0},
        {"event_index": 1, "event_type": "command", "event_value": "cat /etc/passwd", "observed_at": 101.5},
        {"event_index": 2, "event_type": "decoy_file", "event_value": "/etc/passwd", "observed_at": None},
    ]
    calls = []

    def fake_fetch_all(database_url, sql, params):
        calls.append(params)
        return rows

    monkeypatch.setattr("classifier.storage.repository._fetch_all", fake_fetch_all)

    events = PostgresClassifierRepository("postgresql://example/echidra").list_session_events(session_id)

    assert calls == [{"session_id": session_id}]
    assert events == [StoredSessionEvent(**row) for row in rows]


def test_get_analytics_summary_aggregates_all_dimensions_without_driver(monkeypatch):
    """All six aggregate queries must run via the simple per-call fallback
    (no psycopg installed / cursor-reuse path not exercised here)."""
    query_results = iter(
        [
            [{"hour": 9, "count": 3}, {"hour": 14, "count": 5}],
            [
                {"date": "2026-07-01", "risk_level": "critical", "count": 1},
                {"date": "2026-07-01", "risk_level": "high", "count": 2},
                {"date": "2026-07-01", "risk_level": "medium", "count": 3},
                {"date": "2026-07-02", "risk_level": "low", "count": 4},
                {"date": "2026-07-02", "risk_level": "none", "count": 1},
            ],
            [{"key": "credential_theft", "count": 2}, {"key": "reconnaissance", "count": 6}],
            [{"key": "whoami", "count": 9}],
            [{"key": "generic_linux", "count": 5}],
            [{"key": "United States", "count": 3}],
        ]
    )

    def raise_driver_missing():
        raise DatabaseDriverMissingError("psycopg is not installed")

    monkeypatch.setattr("classifier.storage.repository._load_psycopg", raise_driver_missing)
    monkeypatch.setattr(
        "classifier.storage.repository._fetch_all",
        lambda database_url, sql, params: next(query_results),
    )

    summary = PostgresClassifierRepository(
        "postgresql://example/echidra"
    ).get_analytics_summary(from_ts=1000.0, to_ts=2000.0)

    assert summary.intent_counts == {"credential_theft": 2, "reconnaissance": 6}
    assert summary.attacks_by_hour["09"] == 3
    assert summary.attacks_by_hour["14"] == 5
    assert summary.attacks_by_hour["00"] == 0  # hours with no data default to 0
    # critical folds into high, none folds into low.
    assert summary.risk_trend == [
        {"date": "2026-07-01", "high": 3, "medium": 3, "low": 0},
        {"date": "2026-07-02", "high": 0, "medium": 0, "low": 5},
    ]
    assert summary.top_commands == [{"command": "whoami", "count": 9}]
    assert summary.top_personas == [{"persona_id": "generic_linux", "count": 5}]
    assert summary.top_countries == [{"country": "United States", "count": 3}]


def test_repository_update_issue_status_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr("classifier.storage.repository._execute_insert", lambda *args, **kwargs: None)
    monkeypatch.setattr("classifier.storage.repository._fetch_one", lambda *args, **kwargs: None)

    result = PostgresClassifierRepository("postgresql://example/echidra").update_issue_status(
        uuid4(), "closed"
    )

    assert result is None


def test_repository_update_issue_status_returns_updated_record(monkeypatch):
    issue_id = uuid4()
    row = {
        "id": issue_id,
        "title": "The same scanner ASNs revisit after short cooldowns to re-validate access.",
        "severity": "medium",
        "evidence": "12 sessions from 3 ASNs returned within 24 hours of a prior scan.",
        "recommended_fix": "Throttle by ASN with an escalating cooldown.",
        "impact": "Frees analyst attention for genuine attacker sessions.",
        "session_count": 12,
        "persona_count": 3,
        "status": "closed",
        "created_at": datetime.now(timezone.utc),
    }
    mitre_rows = [
        {"issue_id": issue_id, "technique_index": 0, "technique_id": "T1595", "technique_name": "Active Scanning"}
    ]

    monkeypatch.setattr("classifier.storage.repository._execute_insert", lambda *args, **kwargs: None)
    monkeypatch.setattr("classifier.storage.repository._fetch_one", lambda *args, **kwargs: row)
    monkeypatch.setattr("classifier.storage.repository._fetch_all", lambda *args, **kwargs: mitre_rows)

    updated = PostgresClassifierRepository("postgresql://example/echidra").update_issue_status(
        issue_id, "closed"
    )

    assert updated.status == "closed"
    assert updated.mitre[0].id == "T1595"


def make_issue(**overrides):
    fields = {
        "title": "SSH password authentication is being targeted.",
        "severity": "high",
        "evidence": "37 brute-force sessions across 4 personas.",
        "recommended_fix": "Disable password login, enforce SSH keys.",
        "impact": "Reduces credential-access exposure.",
        "session_count": 37,
        "persona_count": 4,
        "status": "open",
        "mitre": [MitreTechnique(id="T1110", name="Brute Force")],
    }
    fields.update(overrides)
    return IssueRecord(**fields)


def test_issue_insert_params_match_storage_columns():
    issue = make_issue()

    params = issue_insert_params(issue)

    assert params["id"] == issue.id
    assert params["title"] == issue.title
    assert params["severity"] == "high"
    assert params["session_count"] == 37
    assert params["persona_count"] == 4
    assert params["status"] == "open"


def test_issue_upsert_statements_includes_parent_and_child_writes():
    issue = make_issue(
        mitre=[
            MitreTechnique(id="T1110", name="Brute Force"),
            MitreTechnique(id="T1078", name="Valid Accounts"),
        ]
    )

    statements = issue_upsert_statements(issue)

    assert "INSERT INTO issues" in statements[0][0]
    assert "ON CONFLICT (id) DO UPDATE" in statements[0][0]
    assert "status" not in statements[0][0].split("DO UPDATE SET")[1]
    assert "DELETE FROM issue_mitre_techniques" in statements[1][0]
    assert statements[1][1] == {"issue_id": issue.id}
    assert len(statements) == 4
    assert statements[2][1]["technique_id"] == "T1110"
    assert statements[3][1]["technique_id"] == "T1078"


def test_repository_aggregate_classifier_runs_by_actor_and_technique_queries_signals(monkeypatch):
    rows = [{"actor_label": "automated_scanner", "mitre_tag": "T1087", "session_count": 24, "persona_count": 3, "max_risk_rank": 2}]
    calls = []

    def fake_fetch_all(database_url, sql, params):
        calls.append(sql)
        return rows

    monkeypatch.setattr("classifier.storage.repository._fetch_all", fake_fetch_all)

    result = PostgresClassifierRepository(
        "postgresql://example/echidra"
    ).aggregate_classifier_runs_by_actor_and_technique()

    assert result == rows
    assert "classifier_signals" in calls[0]
    assert "signal_type = 'mitre_tag'" in calls[0]
    assert "classifier_runs.actor_label" in calls[0]


def test_repository_upsert_issue_refetches_persisted_status(monkeypatch):
    issue = make_issue(status="open")
    persisted_row = {**issue.dict(exclude={"mitre"}), "status": "closed"}
    mitre_rows = [
        {"issue_id": issue.id, "technique_index": 0, "technique_id": "T1110", "technique_name": "Brute Force"}
    ]

    monkeypatch.setattr("classifier.storage.repository._execute_statements", lambda *args, **kwargs: None)
    monkeypatch.setattr("classifier.storage.repository._fetch_one", lambda *args, **kwargs: persisted_row)
    monkeypatch.setattr("classifier.storage.repository._fetch_all", lambda *args, **kwargs: mitre_rows)

    result = PostgresClassifierRepository("postgresql://example/echidra").upsert_issue(issue)

    # Even though the in-memory issue says "open", the DB already had this
    # issue closed by an analyst — the upsert must not silently reopen it.
    assert result.status == "closed"
    assert result.mitre[0].id == "T1110"


def test_dashboard_report_summary_combines_database_aggregates_without_driver(monkeypatch):
    """When psycopg itself is unavailable, fall back to the simple per-call helpers."""
    overview = {
        "total_runs": 12,
        "elevated_runs": 4,
        "distinct_personas": 3,
        "manual_labels": 2,
        "average_risk_score": 42.5,
    }
    grouped_rows = iter(
        [
            [{"key": "high", "count": 4}, {"key": "low", "count": 8}],
            [{"key": "commodity_bot", "count": 7}],
            [{"key": "reconnaissance", "count": 6}],
        ]
    )

    def raise_driver_missing():
        raise DatabaseDriverMissingError("psycopg is not installed")

    monkeypatch.setattr(
        "classifier.storage.repository._load_psycopg",
        raise_driver_missing,
    )
    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        lambda database_url, sql, params: overview,
    )
    monkeypatch.setattr(
        "classifier.storage.repository._fetch_all",
        lambda database_url, sql, params: next(grouped_rows),
    )

    summary = PostgresClassifierRepository(
        "postgresql://example/echidra"
    ).get_dashboard_report_summary()

    assert summary == DashboardReportSummary(
        **overview,
        risk_counts={"high": 4, "low": 8},
        actor_counts={"commodity_bot": 7},
        intent_counts={"reconnaissance": 6},
    )


class _FakeCursor:
    """Stand-in for a psycopg cursor serving one canned result per execute()."""

    def __init__(self, result_sequence):
        self._results = list(result_sequence)

    def execute(self, sql, params):
        pass

    def fetchall(self):
        return self._results.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _FakeConnection:
    """Stand-in for a psycopg connection that always hands back one cursor."""

    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self, row_factory=None):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_dashboard_report_summary_reuses_one_connection_when_driver_available(monkeypatch):
    """Regression test: overview + all three count queries must run even when
    the overview row is found (previously, a stray indent meant risk/actor/
    intent counts were only computed when overview was None, raising a
    NameError as soon as a real database had any classifier runs)."""
    overview_row = {
        "total_runs": 12,
        "elevated_runs": 4,
        "distinct_personas": 3,
        "manual_labels": 2,
        "average_risk_score": 42.5,
    }
    cursor = _FakeCursor(
        [
            [overview_row],
            [{"key": "high", "count": 4}, {"key": "low", "count": 8}],
            [{"key": "commodity_bot", "count": 7}],
            [{"key": "reconnaissance", "count": 6}],
        ]
    )
    connection = _FakeConnection(cursor)

    class _FakeRows:
        dict_row = object()

    class _FakePsycopg:
        rows = _FakeRows()

        @staticmethod
        def connect(database_url, **kwargs):
            return connection

    monkeypatch.setattr(
        "classifier.storage.repository._load_psycopg",
        lambda: _FakePsycopg,
    )

    summary = PostgresClassifierRepository(
        "postgresql://example/echidra"
    ).get_dashboard_report_summary()

    assert summary == DashboardReportSummary(
        **overview_row,
        risk_counts={"high": 4, "low": 8},
        actor_counts={"commodity_bot": 7},
        intent_counts={"reconnaissance": 6},
    )


def test_get_persona_analytics_reuses_one_connection_when_driver_available(monkeypatch):
    """get_persona_analytics shares _fetch_aggregate_batch with
    get_dashboard_report_summary -- exercise its own seven-query order with a
    real (fake) psycopg connection/cursor, not just the per-call fallback."""
    cursor = _FakeCursor(
        [
            [{"total": 9}],
            [{"date": "2026-07-01", "count": 3}],
            [{"key": "reconnaissance", "count": 5}],
            [{"key": "high", "count": 2}],
            [{"technique_id": "T1110", "count": 4}],
            [{"hour": 14, "count": 6}],
            [{"key": "United States", "count": 1}],
        ]
    )
    connection = _FakeConnection(cursor)

    class _FakeRows:
        dict_row = object()

    class _FakePsycopg:
        rows = _FakeRows()

        @staticmethod
        def connect(database_url, **kwargs):
            return connection

    monkeypatch.setattr(
        "classifier.storage.repository._load_psycopg",
        lambda: _FakePsycopg,
    )
    monkeypatch.setattr(
        "classifier.storage.repository.load_mitre_technique_catalog",
        lambda: {},
    )

    analytics = PostgresClassifierRepository(
        "postgresql://example/echidra"
    ).get_persona_analytics("generic_linux")

    assert analytics.sessions_captured == 9
    assert analytics.sessions_trend == [{"date": "2026-07-01", "count": 3}]
    assert analytics.intent_counts == {"reconnaissance": 5}
    assert analytics.risk_counts == {"high": 2}
    assert analytics.top_techniques == [{"id": "T1110", "name": "T1110", "count": 4}]
    assert analytics.peak_hours == [{"hour": 14, "count": 6}]
    assert analytics.top_countries == [{"country": "United States", "count": 1}]


def test_classifier_run_list_query_applies_supported_filters():
    session_id = uuid4()

    sql, params = classifier_run_list_query(
        session_id=session_id,
        risk_level="high",
        actor_label="commodity_bot",
        persona_id="ubuntu_web_server",
        limit=25,
    )

    assert "FROM classifier_runs" in sql
    assert "JOIN sessions" in sql
    assert "classifier_runs.session_id = %(session_id)s" in sql
    assert "classifier_runs.risk_level = %(risk_level)s" in sql
    assert "classifier_runs.actor_label = %(actor_label)s" in sql
    assert "sessions.persona_id = %(persona_id)s" in sql
    assert "ORDER BY sessions.started_at DESC, classifier_runs.id DESC" in sql
    assert "LIMIT %(limit)s" in sql
    assert params == {
        "session_id": session_id,
        "risk_level": "high",
        "actor_label": "commodity_bot",
        "persona_id": "ubuntu_web_server",
        "limit": 25,
    }


def test_classifier_run_list_query_applies_date_range_filter():
    """sessions.html previously fetched a flat limit=500 (most-recent-first)
    and filtered by date range only client-side -- a range older than the
    500th-most-recent session would silently lose matching data. This must
    filter server-side against sessions.started_at instead."""
    sql, params = classifier_run_list_query(from_ts=1000.0, to_ts=2000.0, limit=25)

    assert "sessions.started_at >= %(from_ts)s" in sql
    assert "sessions.started_at <= %(to_ts)s" in sql
    assert params == {"from_ts": 1000.0, "to_ts": 2000.0, "limit": 25}


def test_classifier_run_list_query_omits_range_filter_when_not_given():
    sql, params = classifier_run_list_query(limit=25)

    assert "from_ts" not in sql
    assert "to_ts" not in sql
    assert params == {"limit": 25}


def test_manual_label_list_query_applies_supported_filters():
    session_id = uuid4()
    classifier_run_id = uuid4()

    sql, params = manual_label_list_query(
        session_id=session_id,
        classifier_run_id=classifier_run_id,
        limit=10,
    )

    assert "FROM manual_labels" in sql
    assert "session_id = %(session_id)s" in sql
    assert "classifier_run_id = %(classifier_run_id)s" in sql
    assert "ORDER BY created_at DESC, id DESC" in sql
    assert "LIMIT %(limit)s" in sql
    assert params == {
        "session_id": session_id,
        "classifier_run_id": classifier_run_id,
        "limit": 10,
    }


def test_issue_list_query_applies_status_filter():
    sql, params = issue_list_query(status="open", limit=10)

    assert "FROM issues" in sql
    assert "status = %(status)s" in sql
    assert "ORDER BY session_count DESC, created_at DESC" in sql
    assert "LIMIT %(limit)s" in sql
    assert params == {"status": "open", "limit": 10}


def test_issue_list_query_omits_filter_when_status_not_given():
    sql, params = issue_list_query(limit=10)

    assert "WHERE" not in sql
    assert params == {"limit": 10}


def test_issue_list_query_clamps_limit_to_maximum():
    _, params = issue_list_query(limit=10_000)

    assert params["limit"] == 500


def test_storage_cli_init_db_requires_database_url(monkeypatch, capsys):
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)

    exit_code = storage_cli.main(["init-db"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "ECHIDRA_DATABASE_URL is not set" in captured.err
    assert "postgresql://" not in captured.err


def test_storage_cli_init_db_reports_placeholder_database_url(
    monkeypatch,
    tmp_path,
    capsys,
):
    schema_path = tmp_path / "schema.sql"
    schema_path.write_text("CREATE TABLE example(id integer);", encoding="utf-8")
    database_url = "postgresql://YOUR_USER:secret@example.local:5432/echidra"

    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)

    def failing_apply_schema(url, path):
        raise AssertionError("should not attempt to connect with placeholders")

    monkeypatch.setattr(storage_cli, "apply_schema", failing_apply_schema)

    exit_code = storage_cli.main(["init-db", "--schema", str(schema_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "still contains the placeholder YOUR_USER" in captured.err
    assert "secret" not in captured.err


def test_storage_cli_init_db_applies_schema_without_printing_url(
    monkeypatch,
    tmp_path,
    capsys,
):
    schema_path = tmp_path / "schema.sql"
    schema_path.write_text("CREATE TABLE example(id integer);", encoding="utf-8")
    database_url = "postgresql://user:secret@example.local:5432/echidra"
    calls = []

    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)
    monkeypatch.setattr(
        storage_cli,
        "apply_schema",
        lambda url, path: calls.append((url, path)),
    )

    exit_code = storage_cli.main(["init-db", "--schema", str(schema_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == [(database_url, schema_path)]
    assert captured.out == (
        "Connecting to postgresql://user:***@example.local:5432/echidra ...\n"
        "database initialized\n"
    )
    assert "secret" not in captured.out
    assert "secret" not in captured.err


def test_storage_cli_init_db_redacts_database_url_in_errors(
    monkeypatch,
    tmp_path,
    capsys,
):
    schema_path = tmp_path / "schema.sql"
    schema_path.write_text("CREATE TABLE example(id integer);", encoding="utf-8")
    database_url = "postgresql://user:secret@example.local:5432/echidra"

    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)

    def failing_apply_schema(url, path):
        raise RuntimeError(f"could not connect to {url}")

    monkeypatch.setattr(storage_cli, "apply_schema", failing_apply_schema)

    exit_code = storage_cli.main(["init-db", "--schema", str(schema_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "postgresql://user:***@example.local:5432/echidra" in captured.err
    assert "secret" not in captured.err


def test_storage_cli_init_db_can_seed_demo_issues_when_requested(
    monkeypatch,
    tmp_path,
    capsys,
):
    schema_path = tmp_path / "schema.sql"
    schema_path.write_text("CREATE TABLE example(id integer);", encoding="utf-8")
    database_url = "postgresql://user:secret@example.local:5432/echidra"
    calls = []

    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)
    monkeypatch.setattr(
        storage_cli,
        "apply_schema",
        lambda url, path: calls.append(("schema", url, path)),
    )
    monkeypatch.setattr(
        storage_cli,
        "seed_demo_issues",
        lambda url, path=None: calls.append(("seed", url, path)),
    )

    exit_code = storage_cli.main(
        ["init-db", "--schema", str(schema_path), "--seed-demo-issues"]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls[0] == ("schema", database_url, schema_path)
    assert calls[1][0] == "seed"
    assert calls[1][1] == database_url
    assert captured.out == (
        "Connecting to postgresql://user:***@example.local:5432/echidra ...\n"
        "database initialized\n"
    )
    assert "secret" not in captured.out


def test_storage_cli_sync_issues_requires_database_url(monkeypatch, capsys):
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)

    exit_code = storage_cli.main(["sync-issues"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "ECHIDRA_DATABASE_URL is not set" in captured.err
    assert "postgresql://" not in captured.err


def test_storage_cli_sync_issues_reports_placeholder_database_url(monkeypatch, capsys):
    database_url = "postgresql://YOUR_USER:secret@example.local:5432/echidra"
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)

    def failing_sync(**kwargs):
        raise AssertionError("should not attempt to connect with placeholders")

    monkeypatch.setattr(storage_cli, "sync_issues_from_classifier_runs", failing_sync)

    exit_code = storage_cli.main(["sync-issues"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "still contains the placeholder YOUR_USER" in captured.err
    assert "secret" not in captured.err


def test_storage_cli_sync_issues_runs_sync_and_prints_count(monkeypatch, capsys):
    database_url = "postgresql://user:secret@example.local:5432/echidra"
    calls = []

    def fake_sync(**kwargs):
        calls.append(kwargs)
        return [object(), object()]

    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)
    monkeypatch.setattr(storage_cli, "sync_issues_from_classifier_runs", fake_sync)

    exit_code = storage_cli.main(["sync-issues"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls[0]["database_url"] == database_url
    assert captured.out == "synced 2 issue(s)\n"
    assert "secret" not in captured.out


def test_storage_cli_sync_issues_redacts_database_url_in_errors(monkeypatch, capsys):
    database_url = "postgresql://user:secret@example.local:5432/echidra"
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", database_url)

    def failing_sync(**kwargs):
        raise RuntimeError(f"could not connect to {kwargs['database_url']}")

    monkeypatch.setattr(storage_cli, "sync_issues_from_classifier_runs", failing_sync)

    exit_code = storage_cli.main(["sync-issues"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "postgresql://user:***@example.local:5432/echidra" in captured.err
    assert "secret" not in captured.err


def test_create_persona_config_translates_unique_violation_to_conflict_error(monkeypatch):
    """A duplicate slug ID must surface as PersonaConfigAlreadyExistsError,
    from the DB's own unique constraint rather than a prior existence check
    (which would be a TOCTOU race between two concurrent create requests)."""
    import psycopg

    def raise_unique_violation(*args, **kwargs):
        raise psycopg.errors.UniqueViolation("duplicate key value violates unique constraint")

    monkeypatch.setattr("classifier.storage.repository._execute_insert", raise_unique_violation)

    repository = PostgresClassifierRepository("postgresql://example/echidra")

    with pytest.raises(PersonaConfigAlreadyExistsError):
        repository.create_persona_config("generic_linux", PersonaConfigInput(name="Generic Linux"))
