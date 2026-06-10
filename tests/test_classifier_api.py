import importlib

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import ValidationError

from classifier.api import app
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage import (
    ClassifyAndStoreResponse,
    ClassifierRunRecord,
    DatabaseNotConfiguredError,
    ManualLabelInput,
    ManualLabelRecord,
    StoredClassifierRun,
)
from tests.test_classifier_pipeline import make_record

app_module = importlib.import_module("classifier.api.app")


def route_for(path, method):
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path:
            if method in route.methods:
                return route
    raise AssertionError(f"route not found: {method} {path}")


def test_health_endpoint_reports_ok():
    route = route_for("/health", "GET")

    assert route.endpoint() == {"status": "ok"}


def test_classify_session_route_uses_classifier_summary_contract():
    route = route_for("/classify/session", "POST")

    assert route.response_model is ClassificationSummary


def test_classify_and_store_route_uses_storage_response_contract():
    route = route_for("/classify/session/store", "POST")

    assert route.response_model is ClassifyAndStoreResponse


def test_get_classifier_run_route_uses_storage_run_contract():
    route = route_for("/classifier/runs/{run_id}", "GET")

    assert route.response_model is StoredClassifierRun


def test_get_manual_label_route_uses_manual_label_contract():
    route = route_for("/manual-labels/{label_id}", "GET")

    assert route.response_model is ManualLabelRecord


def test_classify_session_endpoint_returns_classifier_summary():
    route = route_for("/classify/session", "POST")
    session = SessionRecord.parse_obj(make_record())

    summary = route.endpoint(session)

    assert summary.classifier_version == "1.0.0"
    assert summary.rules_version == "1.0.0"
    assert summary.actor_label == "commodity_bot"
    assert summary.risk_level == "medium"
    assert summary.intent == "credential_theft"
    assert summary.matched_rule_ids == [
        "sensitive_file_probe",
        "interactive_low_and_slow",
    ]
    assert summary.feature_summary.command_count == 4


def test_classify_session_endpoint_rejects_invalid_session_record():
    record = make_record(command_count=99)

    with pytest.raises(ValidationError, match="command_count must match commands"):
        SessionRecord.parse_obj(record)


def test_classify_session_endpoint_maps_classify_session_value_error_to_http_exception(monkeypatch):
    route = route_for("/classify/session", "POST")
    session = SessionRecord.parse_obj(make_record())

    def failing_classify_session(_session):
        raise ValueError("unsupported feature evaluation")

    monkeypatch.setattr(app_module, "classify_session", failing_classify_session)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "unsupported feature evaluation"


def test_classify_session_endpoint_hides_unhandled_exception_details(monkeypatch):
    route = route_for("/classify/session", "POST")
    session = SessionRecord.parse_obj(make_record())

    def crashing_classify_session(_session):
        raise RuntimeError("database password was leaked into this error")

    monkeypatch.setattr(app_module, "classify_session", crashing_classify_session)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "internal server error"


def test_classify_and_store_endpoint_returns_run_id(monkeypatch):
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())
    saved_runs = []

    class FakeRepository:
        def save_classifier_run(self, stored_session, summary):
            record = ClassifierRunRecord.from_session_summary(
                session=stored_session,
                summary=summary,
            )
            saved_runs.append(record)
            return record

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(session)

    assert response.run_id == saved_runs[0].id
    assert response.summary.intent == "credential_theft"
    assert saved_runs[0].session_id == session.session_id


def test_classify_and_store_endpoint_reports_missing_database(monkeypatch):
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(
        app_module,
        "PostgresClassifierRepository",
        MissingDatabaseRepository,
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "ECHIDRA_DATABASE_URL must be set"


def test_classify_and_store_endpoint_hides_persistence_failures(monkeypatch):
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())

    class CrashingRepository:
        def __init__(self):
            pass

        def save_classifier_run(self, stored_session, summary):
            raise RuntimeError("failed to persist classifier run")

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", CrashingRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "internal server error"


def test_get_classifier_run_endpoint_returns_stored_run(monkeypatch):
    route = route_for("/classifier/runs/{run_id}", "GET")
    session = SessionRecord.parse_obj(make_record())
    summary = app_module.classify_session(session)
    record = ClassifierRunRecord.from_session_summary(session, summary)
    stored_run = StoredClassifierRun(
        id=record.id,
        session_id=record.session_id,
        protocol=record.protocol,
        peer_ip=record.session_record["peer_ip"],
        peer_port=record.session_record["peer_port"],
        persona_id=record.persona_id,
        started_at=record.session_record["started_at"],
        ended_at=record.session_record["ended_at"],
        end_reason=record.session_record["end_reason"],
        actor_label=record.actor_label,
        confidence=record.confidence,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        behavior_stage=record.behavior_stage,
        intent=record.intent,
        signals=[],
    )

    class FakeRepository:
        def get_classifier_run(self, run_id):
            assert run_id == record.id
            return stored_run

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(record.id)

    assert response == stored_run


def test_get_classifier_run_endpoint_reports_missing_run(monkeypatch):
    route = route_for("/classifier/runs/{run_id}", "GET")
    run_id = SessionRecord.parse_obj(make_record()).session_id

    class FakeRepository:
        def get_classifier_run(self, requested_run_id):
            assert requested_run_id == run_id
            return None

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(run_id)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "classifier run not found"


def test_get_classifier_run_endpoint_reports_missing_database(monkeypatch):
    route = route_for("/classifier/runs/{run_id}", "GET")
    run_id = SessionRecord.parse_obj(make_record()).session_id

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(
        app_module,
        "PostgresClassifierRepository",
        MissingDatabaseRepository,
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(run_id)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "ECHIDRA_DATABASE_URL must be set"


def test_get_manual_label_endpoint_returns_stored_label(monkeypatch):
    route = route_for("/manual-labels/{label_id}", "GET")
    label = ManualLabelRecord(
        **ManualLabelInput(
            session_id=SessionRecord.parse_obj(make_record()).session_id,
            actor_label="commodity_bot",
            labeled_by="analyst@example.com",
        ).dict()
    )

    class FakeRepository:
        def get_manual_label(self, label_id):
            assert label_id == label.id
            return label

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(label.id)

    assert response == label


def test_get_manual_label_endpoint_reports_missing_label(monkeypatch):
    route = route_for("/manual-labels/{label_id}", "GET")
    label_id = SessionRecord.parse_obj(make_record()).session_id

    class FakeRepository:
        def get_manual_label(self, requested_label_id):
            assert requested_label_id == label_id
            return None

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(label_id)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "manual label not found"


def test_classify_session_endpoint_accepts_json_requests_via_test_client():
    client = TestClient(app)
    response = client.post("/classify/session", json=make_record())

    assert response.status_code == 200
    body = response.json()
    assert body["classifier_version"] == "1.0.0"
    assert body["rules_version"] == "1.0.0"
    assert body["actor_label"] == "commodity_bot"
    assert body["risk_level"] == "medium"
    assert body["intent"] == "credential_theft"
    assert body["matched_rule_ids"] == [
        "sensitive_file_probe",
        "interactive_low_and_slow",
    ]
