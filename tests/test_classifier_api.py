import hashlib
import hmac
import importlib

import pytest
from fastapi import HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.responses import Response

from classifier.api import app
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage import (
    ClassifyAndStoreResponse,
    ClassifierRunRecord,
    DashboardUserRecord,
    DatabaseNotConfiguredError,
    ManualLabelInput,
    ManualLabelRecord,
    StoredClassifierRun,
)
from tests.test_classifier_pipeline import make_record

app_module = importlib.import_module("classifier.api.app")


@pytest.fixture(autouse=True)
def clear_dashboard_session_secret(monkeypatch):
    monkeypatch.delenv("ECHIDRA_SESSION_SECRET", raising=False)


class FakeRequest:
    def __init__(self, cookies=None, headers=None):
        self.cookies = cookies or {}
        self.headers = headers or {}


def dashboard_cookie(email="analyst@example.com"):
    user = DashboardUserRecord(email=email, password_hash="hash")
    return {
        app_module.DASHBOARD_AUTH_COOKIE:
        app_module._dashboard_session_cookie_value(user)
    }


def dashboard_request(cookies=None, headers=None, authenticated=True):
    if cookies is None and authenticated:
        cookies = dashboard_cookie()
    return FakeRequest(cookies=cookies, headers=headers)


def route_for(path, method):
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path:
            if method in route.methods:
                return route
    raise AssertionError(f"route not found: {method} {path}")


def test_health_endpoint_reports_ok():
    route = route_for("/health", "GET")

    assert route.endpoint() == {"status": "ok"}


def test_dashboard_route_serves_dashboard_html():
    route = route_for("/dashboard", "GET")

    response = route.endpoint(dashboard_request())

    assert isinstance(response, FileResponse)
    assert str(response.path).endswith("dashboard/public/index.html")
    assert response.media_type == "text/html"


def test_auth_route_serves_auth_html():
    route = route_for("/auth", "GET")

    response = route.endpoint()

    assert isinstance(response, FileResponse)
    assert str(response.path).endswith("dashboard/public/auth.html")
    assert response.media_type == "text/html"


def test_dashboard_assets_are_whitelisted_and_served():
    route = route_for("/assets/{filename}", "GET")

    banner = route.endpoint("Qyleron_Banner.png")
    logo = route.endpoint("qyleron_logo.png")

    assert isinstance(banner, FileResponse)
    assert str(banner.path).endswith("assets/Qyleron_Banner.png")
    assert isinstance(logo, FileResponse)
    assert str(logo.path).endswith("assets/qyleron_logo.png")

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint("../README.md")

    assert exc_info.value.status_code == 404


def test_dashboard_route_reports_missing_asset(monkeypatch, tmp_path):
    route = route_for("/dashboard", "GET")
    missing_path = tmp_path / "missing-dashboard.html"

    monkeypatch.setattr(app_module, "DASHBOARD_INDEX_PATH", missing_path)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request())

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "dashboard not found"


def test_dashboard_route_redirects_to_auth_without_session_cookie():
    route = route_for("/dashboard", "GET")

    response = route.endpoint(dashboard_request(authenticated=False))

    assert isinstance(response, RedirectResponse)
    assert response.status_code == 303
    assert response.headers["location"] == "/auth"


def test_dashboard_route_accepts_valid_session_cookie():
    route = route_for("/dashboard", "GET")

    response = route.endpoint(dashboard_request())

    assert isinstance(response, FileResponse)


def test_signup_dashboard_user_hashes_password_and_sets_cookie(monkeypatch):
    route = route_for("/auth/signup", "POST")
    saved = {}

    class FakeRepository:
        def get_dashboard_user_by_email(self, email):
            assert email == "analyst@example.com"
            return None

        def create_dashboard_user(self, *, email, password_hash):
            saved["email"] = email
            saved["password_hash"] = password_hash
            return DashboardUserRecord(email=email, password_hash=password_hash)

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    response = Response()
    payload = app_module.DashboardSignupInput(
        email="Analyst@Example.com",
        password="password1",
    )

    body = route.endpoint(payload, response)

    assert body == {"authenticated": True, "email": "analyst@example.com"}
    assert saved["email"] == "analyst@example.com"
    assert saved["password_hash"] != "password1"
    assert app_module._verify_password("password1", saved["password_hash"])
    assert app_module.DASHBOARD_AUTH_COOKIE in response.headers["set-cookie"]


def test_signup_dashboard_user_rejects_duplicate_email(monkeypatch):
    route = route_for("/auth/signup", "POST")
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash=app_module._hash_password("password1"),
    )

    class FakeRepository:
        def get_dashboard_user_by_email(self, email):
            return user

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardSignupInput(
        email="analyst@example.com",
        password="password1",
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(payload, Response())

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "email already registered"


def test_login_dashboard_user_sets_cookie_for_valid_credentials(monkeypatch):
    route = route_for("/auth/login", "POST")
    password_hash = app_module._hash_password("password1")
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash=password_hash,
    )

    class FakeRepository:
        def get_dashboard_user_by_email(self, email):
            assert email == "analyst@example.com"
            return user

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    response = Response()
    payload = app_module.DashboardLoginInput(
        email="Analyst@Example.com",
        password="password1",
    )

    body = route.endpoint(payload, response)

    assert body == {"authenticated": True, "email": "analyst@example.com"}
    assert app_module.DASHBOARD_AUTH_COOKIE in response.headers["set-cookie"]
    assert "Max-Age=28800" in response.headers["set-cookie"]


def test_login_dashboard_user_rejects_invalid_credentials(monkeypatch):
    route = route_for("/auth/login", "POST")
    password_hash = app_module._hash_password("password1")
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash=password_hash,
    )

    class FakeRepository:
        def get_dashboard_user_by_email(self, email):
            return user

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardLoginInput(
        email="analyst@example.com",
        password="wrongpass1",
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(payload, Response())

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid email or password"


def test_dashboard_password_validation_requires_length_letter_and_number():
    with pytest.raises(ValidationError, match="at least 8"):
        app_module.DashboardSignupInput(email="a@example.com", password="short1")
    with pytest.raises(ValidationError, match="letter"):
        app_module.DashboardSignupInput(email="a@example.com", password="12345678")
    with pytest.raises(ValidationError, match="number"):
        app_module.DashboardSignupInput(email="a@example.com", password="password")
    with pytest.raises(ValidationError, match="whitespace"):
        app_module.DashboardSignupInput(email="a@example.com", password="password 1")
    with pytest.raises(ValidationError, match="at most 128"):
        app_module.DashboardSignupInput(
            email="a@example.com",
            password=f"a1{'x' * 127}",
        )


def test_dashboard_login_applies_password_format_validation():
    with pytest.raises(ValidationError, match="at least 8"):
        app_module.DashboardLoginInput(email="a@example.com", password="short1")


def test_dashboard_email_validation_rejects_invalid_format():
    invalid_emails = [
        "not-an-email",
        ".analyst@example.com",
        "analyst..name@example.com",
        "analyst@-example.com",
        "analyst@example-.com",
    ]

    for email in invalid_emails:
        with pytest.raises(ValidationError, match="valid email"):
            app_module.DashboardSignupInput(email=email, password="password1")


def test_dashboard_session_cookie_rejects_expired_value(monkeypatch):
    issued_at = 1_000
    user = DashboardUserRecord(email="analyst@example.com", password_hash="hash")
    payload = f"{user.id}:{user.email}:{issued_at}"
    signature = hmac.new(
        app_module._dashboard_session_secret().encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    monkeypatch.setattr(
        app_module.time,
        "time",
        lambda: issued_at + app_module.SESSION_MAX_AGE_SECONDS + 1,
    )

    assert not app_module._verify_dashboard_session_cookie(f"{payload}:{signature}")


def test_dashboard_cookie_secure_flag_reads_environment(monkeypatch):
    monkeypatch.setenv("ECHIDRA_COOKIE_SECURE", "true")

    assert app_module._dashboard_cookie_secure()


def test_classify_session_route_uses_classifier_summary_contract():
    route = route_for("/classify/session", "POST")

    assert route.response_model is ClassificationSummary


def test_classify_and_store_route_uses_storage_response_contract():
    route = route_for("/classify/session/store", "POST")

    assert route.response_model is ClassifyAndStoreResponse


def test_get_classifier_run_route_uses_storage_run_contract():
    route = route_for("/classifier/runs/{run_id}", "GET")

    assert route.response_model is StoredClassifierRun


def test_list_classifier_runs_route_uses_storage_run_list_contract():
    route = route_for("/classifier/runs", "GET")

    assert route.response_model == list[StoredClassifierRun]


def test_get_manual_label_route_uses_manual_label_contract():
    route = route_for("/manual-labels/{label_id}", "GET")

    assert route.response_model is ManualLabelRecord


def test_list_manual_labels_route_uses_manual_label_list_contract():
    route = route_for("/manual-labels", "GET")

    assert route.response_model == list[ManualLabelRecord]


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

    response = route.endpoint(record.id, dashboard_request())

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
        route.endpoint(run_id, dashboard_request())

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
        route.endpoint(run_id, dashboard_request())

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "ECHIDRA_DATABASE_URL must be set"


def test_list_classifier_runs_endpoint_passes_filters(monkeypatch):
    route = route_for("/classifier/runs", "GET")
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
        def list_classifier_runs(
            self,
            *,
            session_id,
            risk_level,
            actor_label,
            persona_id,
            limit,
        ):
            assert session_id == session.session_id
            assert risk_level == "medium"
            assert actor_label == "commodity_bot"
            assert persona_id == "generic_linux"
            assert limit == 25
            return [stored_run]

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(
        dashboard_request(),
        session_id=session.session_id,
        risk_level="medium",
        actor_label="commodity_bot",
        persona_id="generic_linux",
        limit=25,
    )

    assert response == [stored_run]


def test_list_classifier_runs_endpoint_reports_missing_database(monkeypatch):
    route = route_for("/classifier/runs", "GET")

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(
        app_module,
        "PostgresClassifierRepository",
        MissingDatabaseRepository,
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(), limit=100)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "ECHIDRA_DATABASE_URL must be set"


def test_list_classifier_runs_endpoint_requires_dashboard_session():
    route = route_for("/classifier/runs", "GET")

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(authenticated=False), limit=100)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


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

    response = route.endpoint(label.id, dashboard_request())

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
        route.endpoint(label_id, dashboard_request())

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "manual label not found"


def test_list_manual_labels_endpoint_passes_filters(monkeypatch):
    route = route_for("/manual-labels", "GET")
    session_id = SessionRecord.parse_obj(make_record()).session_id
    classifier_run_id = SessionRecord.parse_obj(make_record()).session_id
    label = ManualLabelRecord(
        **ManualLabelInput(
            session_id=session_id,
            classifier_run_id=classifier_run_id,
            actor_label="commodity_bot",
        ).dict()
    )

    class FakeRepository:
        def list_manual_labels(self, *, session_id, classifier_run_id, limit):
            assert session_id == label.session_id
            assert classifier_run_id == label.classifier_run_id
            assert limit == 30
            return [label]

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(
        dashboard_request(),
        session_id=label.session_id,
        classifier_run_id=label.classifier_run_id,
        limit=30,
    )

    assert response == [label]


def test_list_manual_labels_endpoint_reports_missing_database(monkeypatch):
    route = route_for("/manual-labels", "GET")

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(
        app_module,
        "PostgresClassifierRepository",
        MissingDatabaseRepository,
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(), limit=100)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "ECHIDRA_DATABASE_URL must be set"


def test_classify_session_route_accepts_session_record_body_model():
    route = route_for("/classify/session", "POST")

    assert route.body_field is not None
    assert route.body_field.type_ is SessionRecord
