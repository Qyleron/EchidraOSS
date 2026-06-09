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
    ManualLabelInput,
    ManualLabelRecord,
)
from classifier.storage.repository import (
    DatabaseNotConfiguredError,
    PostgresClassifierRepository,
    classifier_run_insert_params,
    classifier_run_statements,
    manual_label_insert_params,
    classifier_signal_insert_params,
    session_event_insert_params,
    session_insert_params,
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
    session = SessionRecord.parse_obj(make_record())
    summary = classify_session_record(make_record())
    record = ClassifierRunRecord.from_session_summary(session, summary)

    params = session_insert_params(record)

    assert params["id"] == session.session_id
    assert params["protocol"] == "tcp_shell"
    assert params["peer_ip"] == "127.0.0.1"
    assert params["peer_port"] == 4444
    assert params["persona_id"] == "generic_linux"
    assert params["end_reason"] == "disconnect"
    assert len(params) == 8


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
    sql_text = "\n".join(sql for sql, _params in statements)

    assert "DELETE FROM session_events" in sql_text
    assert "INSERT INTO sessions" in sql_text
    assert "INSERT INTO session_events" in sql_text
    assert "INSERT INTO classifier_runs" in sql_text
    assert "INSERT INTO classifier_signals" in sql_text


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
    assert "labeled_by" not in params


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
