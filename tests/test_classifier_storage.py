from datetime import datetime, timezone
from uuid import uuid4

import pytest

from classifier.pipeline import classify_session_record
from classifier.schemas.session import SessionRecord
from classifier.storage import cli as storage_cli
from classifier.storage.config import (
    database_url_placeholder,
    get_database_url,
    redact_database_url,
)
from classifier.storage.models import (
    ClassifierRunRecord,
    DashboardReportSummary,
    DashboardUserRecord,
    IssueRecord,
    ManualLabelInput,
    ManualLabelRecord,
    MitreTechnique,
)
from classifier.storage.repository import (
    DatabaseNotConfiguredError,
    PostgresClassifierRepository,
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
    assert len(params) == 8


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
    assert ("recommendation", "rotate_exposed_credentials", "high") in signal_pairs
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


def test_dashboard_report_summary_combines_database_aggregates(monkeypatch):
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
    assert captured.out == "database initialized\n"
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
