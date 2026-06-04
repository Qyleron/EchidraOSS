import importlib
import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from pydantic import ValidationError

from classifier.api import app
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
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
