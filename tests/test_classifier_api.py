import importlib
import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
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


@pytest.mark.asyncio
async def test_health_endpoint_reports_ok():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_classify_session_route_uses_classifier_summary_contract():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/classify/session", json=make_record())

    assert response.status_code == 200
    ClassificationSummary.parse_obj(response.json())


@pytest.mark.asyncio
async def test_classify_session_endpoint_returns_classifier_summary():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        payload = make_record()
        response = await client.post("/classify/session", json=payload)
        body = response.json()

    assert response.status_code == 200
    assert body["classifier_version"] == "1.0.0"
    assert body["rules_version"] == "1.0.0"
    assert body["actor_label"] == "commodity_bot"
    assert body["risk_level"] == "medium"
    assert body["intent"] == "credential_theft"
    assert body["matched_rule_ids"] == [
        "sensitive_file_probe",
        "interactive_low_and_slow",
    ]
    assert body["feature_summary"]["command_count"] == 4


@pytest.mark.asyncio
async def test_classify_session_endpoint_rejects_invalid_session_record():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        record = make_record(command_count=99)
        response = await client.post("/classify/session", json=record)

    assert response.status_code == 422
    assert "command_count must match commands" in response.text


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
