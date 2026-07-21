import hashlib
import hmac
import importlib
import re
from datetime import datetime, timezone

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
    DashboardReportSummary,
    DashboardUserRecord,
    DatabaseNotConfiguredError,
    IssueRecord,
    IssueStatusUpdate,
    ManualLabelInput,
    ManualLabelRecord,
    PersonaConfigAlreadyExistsError,
    PersonaConfigInput,
    PersonaConfigRecord,
    StoredClassifierRun,
)
from tests.test_classifier_pipeline import make_record

app_module = importlib.import_module("classifier.api.app")


@pytest.fixture(autouse=True)
def clear_dashboard_session_secret(monkeypatch):
    monkeypatch.delenv("ECHIDRA_SESSION_SECRET", raising=False)
    monkeypatch.delenv(app_module.INGEST_API_KEY_ENV, raising=False)
    monkeypatch.delenv(app_module.ALLOW_SIGNUPS_ENV, raising=False)


class FakeRequest:
    def __init__(self, cookies=None, headers=None):
        self.cookies = cookies or {}
        self.headers = headers or {}


class _SessionVersionMixin:
    """Shared by test FakeRepository doubles so a dashboard_request() cookie
    still passes the session_version revocation check added for
    /auth/logout, without every endpoint-specific double needing to
    reimplement it. dashboard_cookie() always signs session_version=1
    (DashboardUserRecord's default), so returning 1 here matches it."""

    def get_dashboard_user_session_version(self, user_id):
        return 1


class _DefaultAuthOnlyRepository(_SessionVersionMixin):
    """Autouse default repository so any test using dashboard_request()
    authenticates successfully even if it never touches the database for
    anything else. Individual tests that monkeypatch their own
    PostgresClassifierRepository simply override this for their duration."""


@pytest.fixture(autouse=True)
def default_dashboard_repository(monkeypatch):
    monkeypatch.setattr(app_module, "PostgresClassifierRepository", _DefaultAuthOnlyRepository)


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


def ingest_request(api_key=None):
    headers = {}
    if api_key is not None:
        headers[app_module.INGEST_API_KEY_HEADER] = api_key
    return FakeRequest(headers=headers)


def route_for(path, method):
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path:
            if method in route.methods:
                return route
    raise AssertionError(f"route not found: {method} {path}")


def test_health_endpoint_reports_ok():
    route = route_for("/health", "GET")

    assert route.endpoint() == {"status": "ok"}


def test_root_route_redirects_to_dashboard():
    route = route_for("/", "GET")

    response = route.endpoint()

    assert isinstance(response, RedirectResponse)
    assert response.headers["location"] == "/dashboard"
    assert response.status_code == 307


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


def test_dashboard_route_sets_no_store_cache_headers():
    """A logged-out browser must never be able to restore this page from the
    back-forward cache and see stale authenticated content -- no-store makes
    the page ineligible for bfcache in the first place."""
    route = route_for("/dashboard", "GET")

    response = route.endpoint(dashboard_request())

    assert response.headers["cache-control"] == "no-store, must-revalidate"
    assert response.headers["pragma"] == "no-cache"


def test_dashboard_page_route_sets_no_store_cache_headers():
    route = route_for("/dashboard/{page_name}", "GET")

    response = route.endpoint("sessions", dashboard_request())

    assert isinstance(response, FileResponse)
    assert response.headers["cache-control"] == "no-store, must-revalidate"
    assert response.headers["pragma"] == "no-cache"


# _apply_dashboard_no_store_headers only runs as part of the real ASGI
# middleware stack, unlike route_for(...).endpoint(...) above which calls the
# handler function directly and bypasses middleware entirely -- these need an
# actual TestClient request to exercise it.
@pytest.mark.parametrize(
    "path",
    [
        "/reports/summary",
        "/analytics/summary?from_ts=0&to_ts=1",
        "/classifier/runs",
        "/issues",
        "/manual-labels",
        "/persona-configs",
        "/alerts/config",
        "/alerts/events",
        "/alerts/events/count",
        "/personas",
    ],
)
def test_dashboard_json_api_routes_get_no_store_cache_headers(path):
    """Every dashboard JSON endpoint reads the same session cookie as
    /dashboard itself, so a cached response body could otherwise be replayed
    for a since-logged-out or different session sharing the same URL --
    this must hold even when the request is unauthenticated (401), since an
    error response for a session-scoped URL shouldn't be cacheable either."""
    from fastapi.testclient import TestClient

    client = TestClient(app_module.app)

    response = client.get(path)

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store, must-revalidate"
    assert response.headers["pragma"] == "no-cache"


@pytest.mark.parametrize("path", ["/health", "/assets/qyleron_logo.png"])
def test_public_routes_are_exempt_from_no_store_cache_headers(path):
    """Static/public routes must stay normally cacheable -- the middleware
    protects by default, so this confirms the exemption allowlist actually
    takes effect instead of blanket-covering every route."""
    from fastapi.testclient import TestClient

    client = TestClient(app_module.app)

    response = client.get(path)

    assert response.status_code == 200
    assert "cache-control" not in response.headers


def test_auth_route_no_store_header_is_not_duplicated_by_middleware():
    """/auth already sets the header explicitly (route_for test above);
    the middleware must use setdefault so it doesn't add a second,
    duplicate Cache-Control header on top of it."""
    from fastapi.testclient import TestClient

    client = TestClient(app_module.app)

    response = client.get("/auth")

    assert response.headers["cache-control"] == "no-store, must-revalidate"
    raw_cache_control_headers = [
        value for key, value in response.headers.raw if key.lower() == b"cache-control"
    ]
    assert len(raw_cache_control_headers) == 1


def test_personas_endpoint_never_returns_decoy_credential_values():
    """/personas must expose only a count, never the actual username/password."""
    route = route_for("/personas", "GET")

    presets = route.endpoint(dashboard_request())

    assert presets, "expected at least one preset persona"
    for preset in presets:
        assert not hasattr(preset, "fake_credentials")
        assert isinstance(preset.decoy_credential_count, int)
    generic = next(p for p in presets if p.persona_id == "generic_linux")
    expected_count = len(app_module.PRESET_PERSONAS["generic_linux"].fake_credentials)
    assert generic.decoy_credential_count == expected_count


def test_signup_dashboard_user_hashes_password_and_sets_cookie(monkeypatch):
    route = route_for("/auth/signup", "POST")
    saved = {}

    class FakeRepository(_SessionVersionMixin):
        def create_dashboard_user_if_eligible(self, *, email, password_hash, allow_multiple):
            assert email == "analyst@example.com"
            assert allow_multiple is False
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

    class FakeRepository(_SessionVersionMixin):
        def create_dashboard_user_if_eligible(self, *, email, password_hash, allow_multiple):
            raise app_module.DashboardEmailAlreadyRegisteredError()

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardSignupInput(
        email="analyst@example.com",
        password="password1",
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(payload, Response())

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "email already registered"


def test_signup_dashboard_user_blocked_once_an_account_exists(monkeypatch):
    route = route_for("/auth/signup", "POST")

    class FakeRepository(_SessionVersionMixin):
        def create_dashboard_user_if_eligible(self, *, email, password_hash, allow_multiple):
            assert allow_multiple is False
            raise app_module.DashboardSignupNotAllowedError()

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardSignupInput(
        email="second-analyst@example.com",
        password="password1",
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(payload, Response())

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "signup is currently unavailable."


def test_signup_dashboard_user_allowed_when_env_override_set(monkeypatch):
    monkeypatch.setenv(app_module.ALLOW_SIGNUPS_ENV, "true")
    route = route_for("/auth/signup", "POST")

    class FakeRepository(_SessionVersionMixin):
        def create_dashboard_user_if_eligible(self, *, email, password_hash, allow_multiple):
            assert allow_multiple is True
            return DashboardUserRecord(email=email, password_hash=password_hash)

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardSignupInput(
        email="second-analyst@example.com",
        password="password1",
    )

    body = route.endpoint(payload, Response())

    assert body == {"authenticated": True, "email": "second-analyst@example.com"}


def test_login_dashboard_user_sets_cookie_for_valid_credentials(monkeypatch):
    route = route_for("/auth/login", "POST")
    password_hash = app_module._hash_password("password1")
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash=password_hash,
    )

    class FakeRepository(_SessionVersionMixin):
        def get_dashboard_user_by_email(self, email):
            assert email == "analyst@example.com"
            return user

        def count_recent_login_failures(self, key, window_seconds):
            return 0

        def clear_login_failures(self, key):
            pass

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    response = Response()
    payload = app_module.DashboardLoginInput(
        email="Analyst@Example.com",
        password="password1",
    )

    body = route.endpoint(payload, FakeRequest(), response)

    assert body == {"authenticated": True, "email": "analyst@example.com"}
    assert app_module.DASHBOARD_AUTH_COOKIE in response.headers["set-cookie"]
    assert f"Max-Age={app_module.SESSION_MAX_AGE_SECONDS}" in response.headers["set-cookie"]


def test_login_dashboard_user_rejects_invalid_credentials(monkeypatch):
    route = route_for("/auth/login", "POST")
    password_hash = app_module._hash_password("password1")
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash=password_hash,
    )

    class FakeRepository(_SessionVersionMixin):
        def get_dashboard_user_by_email(self, email):
            return user

        def count_recent_login_failures(self, key, window_seconds):
            return 0

        def record_login_failure(self, key, *, window_seconds):
            pass

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardLoginInput(
        email="analyst@example.com",
        password="wrongpass1",
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(payload, FakeRequest(), Response())

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid email or password"


def test_login_dashboard_user_locks_out_after_repeated_failures(monkeypatch):
    route = route_for("/auth/login", "POST")
    user = DashboardUserRecord(
        email="analyst@example.com",
        password_hash=app_module._hash_password("password1"),
    )
    # Shared across FakeRepository instances -- simulates the DB-backed
    # store persisting across the fresh PostgresClassifierRepository()
    # constructed on every request.
    failures = []

    class FakeRepository(_SessionVersionMixin):
        def get_dashboard_user_by_email(self, email):
            return user

        def count_recent_login_failures(self, key, window_seconds):
            return len(failures)

        def record_login_failure(self, key, *, window_seconds):
            failures.append(key)

        def clear_login_failures(self, key):
            failures.clear()

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    payload = app_module.DashboardLoginInput(
        email="analyst@example.com",
        password="wrongpass1",
    )

    for _ in range(app_module.LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        with pytest.raises(HTTPException) as exc_info:
            route.endpoint(payload, FakeRequest(), Response())
        assert exc_info.value.status_code == 401

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(payload, FakeRequest(), Response())

    assert exc_info.value.status_code == 429

    # A correct password is also rejected while the lockout window is active.
    good_payload = app_module.DashboardLoginInput(email="analyst@example.com", password="password1")
    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(good_payload, FakeRequest(), Response())
    assert exc_info.value.status_code == 429


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
    signature = app_module._dashboard_session_cookie_signature(
        user.id, user.session_version, issued_at
    )
    cookie_value = f"{user.id}:{user.session_version}:{issued_at}:{signature}"
    monkeypatch.setattr(
        app_module.time,
        "time",
        lambda: issued_at + app_module.SESSION_MAX_AGE_SECONDS + 1,
    )

    assert not app_module._verify_dashboard_session_cookie(cookie_value)


def test_dashboard_session_cookie_rejects_stale_session_version(monkeypatch):
    """A cookie signed with an outdated session_version must be rejected
    even though its signature and age are still valid -- this is what makes
    /auth/logout actually revoke a session instead of just clearing the
    browser's copy of the cookie."""
    user = DashboardUserRecord(email="analyst@example.com", password_hash="hash")
    cookie_value = app_module._dashboard_session_cookie_value(user)

    class FakeRepository:
        def get_dashboard_user_session_version(self, user_id):
            assert user_id == user.id
            return user.session_version + 1  # rotated since this cookie was issued

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    assert not app_module._verify_dashboard_session_cookie(cookie_value)


def test_dashboard_session_cookie_accepts_matching_session_version(monkeypatch):
    user = DashboardUserRecord(email="analyst@example.com", password_hash="hash")
    cookie_value = app_module._dashboard_session_cookie_value(user)

    class FakeRepository:
        def get_dashboard_user_session_version(self, user_id):
            return user.session_version

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    assert app_module._verify_dashboard_session_cookie(cookie_value)


def test_dashboard_session_cookie_rejects_deleted_user(monkeypatch):
    user = DashboardUserRecord(email="analyst@example.com", password_hash="hash")
    cookie_value = app_module._dashboard_session_cookie_value(user)

    class FakeRepository:
        def get_dashboard_user_session_version(self, user_id):
            return None  # user no longer exists

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    assert not app_module._verify_dashboard_session_cookie(cookie_value)


def test_dashboard_session_cookie_user_id_rejects_forged_signature():
    """A cookie whose signature doesn't check out must not yield a trusted
    user id -- otherwise an attacker could forge an arbitrary user id and
    call /auth/logout to force-invalidate someone else's session, since
    logout takes no other auth."""
    real_user_id = DashboardUserRecord(email="a@example.com", password_hash="hash").id
    forged = f"{real_user_id}:1:1000:not-a-real-signature"

    assert app_module._dashboard_session_cookie_user_id(forged) is None


def test_dashboard_session_cookie_user_id_accepts_valid_signature():
    user = DashboardUserRecord(email="analyst@example.com", password_hash="hash")
    cookie_value = app_module._dashboard_session_cookie_value(user)

    assert app_module._dashboard_session_cookie_user_id(cookie_value) == user.id


def test_logout_dashboard_rotates_session_version_and_clears_cookie(monkeypatch):
    route = route_for("/auth/logout", "POST")
    user = DashboardUserRecord(email="analyst@example.com", password_hash="hash")
    cookie_value = app_module._dashboard_session_cookie_value(user)
    rotated = []

    class FakeRepository:
        def rotate_dashboard_user_session(self, user_id):
            rotated.append(user_id)

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    request = FakeRequest(cookies={app_module.DASHBOARD_AUTH_COOKIE: cookie_value})
    response = Response()

    body = route.endpoint(request, response)

    assert body == {"authenticated": False}
    assert rotated == [user.id]
    assert f"{app_module.DASHBOARD_AUTH_COOKIE}=\"\"" in response.headers["set-cookie"]


def test_logout_dashboard_without_cookie_still_clears_cookie(monkeypatch):
    """No auth cookie present -- nothing to revoke, but logout must still
    succeed and clear whatever cookie the browser may have."""
    route = route_for("/auth/logout", "POST")

    class FakeRepository:
        def rotate_dashboard_user_session(self, user_id):
            raise AssertionError("should not be called without a cookie")

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)
    request = FakeRequest(cookies={})
    response = Response()

    body = route.endpoint(request, response)

    assert body == {"authenticated": False}


def test_dashboard_cookie_secure_flag_reads_environment(monkeypatch):
    monkeypatch.setenv("ECHIDRA_COOKIE_SECURE", "true")

    assert app_module._dashboard_cookie_secure()


def test_fallback_session_secret_persists_and_reuses_same_value(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "_FALLBACK_SESSION_SECRET_PATH", tmp_path / ".dashboard_session_secret")

    first = app_module._load_or_create_fallback_session_secret()
    second = app_module._load_or_create_fallback_session_secret()

    assert first == second
    assert (tmp_path / ".dashboard_session_secret").read_text(encoding="utf-8").strip() == first


def test_fallback_session_secret_converges_when_workers_race(tmp_path, monkeypatch):
    """Simulate two worker processes starting at once: both see no file at
    first, but only one can win the atomic create -- the loser must adopt
    the winner's secret instead of persisting its own different candidate,
    or workers would sign/verify session cookies with different secrets."""
    monkeypatch.setattr(app_module, "_FALLBACK_SESSION_SECRET_PATH", tmp_path / ".dashboard_session_secret")

    # The "winning" worker already created and wrote the file...
    (tmp_path / ".dashboard_session_secret").write_text("winner-secret-value", encoding="utf-8")

    # ...but this call's initial read raced before that write landed, so it
    # still attempts (and fails) to create the file itself.
    real_read = app_module._read_fallback_session_secret
    calls = {"count": 0}

    def read_empty_first_time(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return None
        return real_read(*args, **kwargs)

    monkeypatch.setattr(app_module, "_read_fallback_session_secret", read_empty_first_time)

    result = app_module._load_or_create_fallback_session_secret()

    assert result == "winner-secret-value"


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

    def failing_classify_session(_session, **_kwargs):
        raise ValueError("unsupported feature evaluation")

    monkeypatch.setattr(app_module, "classify_session", failing_classify_session)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "unsupported feature evaluation"


def test_classify_session_endpoint_hides_unhandled_exception_details(monkeypatch):
    route = route_for("/classify/session", "POST")
    session = SessionRecord.parse_obj(make_record())

    def crashing_classify_session(_session, **_kwargs):
        raise RuntimeError("database password was leaked into this error")

    monkeypatch.setattr(app_module, "classify_session", crashing_classify_session)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "internal server error"


def test_classify_and_store_endpoint_returns_run_id(monkeypatch):
    monkeypatch.setenv(app_module.INGEST_API_KEY_ENV, "test-ingest-key")
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())
    saved_runs = []

    class FakeRepository(_SessionVersionMixin):
        def count_sessions_from_ip(self, peer_ip):
            return 0

        def save_classifier_run(self, stored_session, summary):
            record = ClassifierRunRecord.from_session_summary(
                session=stored_session,
                summary=summary,
            )
            saved_runs.append(record)
            return record

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(session, ingest_request("test-ingest-key"))

    assert response.run_id == saved_runs[0].id
    assert response.summary.intent == "credential_theft"
    assert saved_runs[0].session_id == session.session_id


def test_classify_and_store_endpoint_reports_missing_database(monkeypatch):
    monkeypatch.setenv(app_module.INGEST_API_KEY_ENV, "test-ingest-key")
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
        route.endpoint(session, ingest_request("test-ingest-key"))

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "ECHIDRA_DATABASE_URL must be set"


def test_classify_and_store_endpoint_hides_persistence_failures(monkeypatch):
    monkeypatch.setenv(app_module.INGEST_API_KEY_ENV, "test-ingest-key")
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())

    class CrashingRepository:
        def __init__(self):
            pass

        def count_sessions_from_ip(self, peer_ip):
            return 0

        def save_classifier_run(self, stored_session, summary):
            raise RuntimeError("failed to persist classifier run")

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", CrashingRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session, ingest_request("test-ingest-key"))

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "internal server error"


def test_classify_and_store_endpoint_fails_closed_without_configured_key():
    """No ECHIDRA_INGEST_API_KEY set at all -> 503, not a silent accept."""
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session, ingest_request("anything"))

    assert exc_info.value.status_code == 503
    assert app_module.INGEST_API_KEY_ENV in exc_info.value.detail


def test_classify_and_store_endpoint_rejects_missing_or_wrong_key(monkeypatch):
    monkeypatch.setenv(app_module.INGEST_API_KEY_ENV, "correct-key")
    route = route_for("/classify/session/store", "POST")
    session = SessionRecord.parse_obj(make_record())

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session, ingest_request(None))
    assert exc_info.value.status_code == 401

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session, ingest_request("wrong-key"))
    assert exc_info.value.status_code == 401


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

    class FakeRepository(_SessionVersionMixin):
        def get_classifier_run(self, run_id):
            assert run_id == record.id
            return stored_run

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(record.id, dashboard_request())

    assert response == stored_run


def test_get_classifier_run_endpoint_reports_missing_run(monkeypatch):
    route = route_for("/classifier/runs/{run_id}", "GET")
    run_id = SessionRecord.parse_obj(make_record()).session_id

    class FakeRepository(_SessionVersionMixin):
        def get_classifier_run(self, requested_run_id):
            assert requested_run_id == run_id
            return None

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(run_id, dashboard_request())

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "classifier run not found"


def test_get_classifier_run_endpoint_fails_auth_when_database_missing(monkeypatch):
    """A missing database now fails the dashboard auth check itself (the
    session_version revocation lookup needs it), before the endpoint's own
    DatabaseNotConfiguredError handling is ever reached."""
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

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_list_session_events_endpoint_returns_ordered_timeline(monkeypatch):
    from classifier.storage import StoredSessionEvent

    route = route_for("/sessions/{session_id}/events", "GET")
    session_id = SessionRecord.parse_obj(make_record()).session_id
    events = [
        StoredSessionEvent(event_index=0, event_type="command", event_value="whoami", observed_at=100.0),
        StoredSessionEvent(event_index=1, event_type="decoy_file", event_value="/etc/passwd", observed_at=None),
    ]

    class FakeRepository(_SessionVersionMixin):
        def list_session_events(self, requested_session_id):
            assert requested_session_id == session_id
            return events

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(session_id, dashboard_request())

    assert response == events


def test_list_session_events_endpoint_fails_auth_when_database_missing(monkeypatch):
    """A missing database now fails the dashboard auth check itself (the
    session_version revocation lookup needs it), before the endpoint's own
    DatabaseNotConfiguredError handling is ever reached."""
    route = route_for("/sessions/{session_id}/events", "GET")
    session_id = SessionRecord.parse_obj(make_record()).session_id

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(
        app_module,
        "PostgresClassifierRepository",
        MissingDatabaseRepository,
    )

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session_id, dashboard_request())

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_list_session_events_endpoint_requires_dashboard_auth():
    route = route_for("/sessions/{session_id}/events", "GET")
    session_id = SessionRecord.parse_obj(make_record()).session_id

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(session_id, dashboard_request(authenticated=False))

    assert exc_info.value.status_code == 401


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

    class FakeRepository(_SessionVersionMixin):
        def list_classifier_runs(
            self,
            *,
            session_id,
            risk_level,
            actor_label,
            persona_id,
            from_ts,
            to_ts,
            limit,
        ):
            assert session_id == session.session_id
            assert risk_level == "medium"
            assert actor_label == "commodity_bot"
            assert persona_id == "generic_linux"
            assert from_ts is None
            assert to_ts is None
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


def test_list_classifier_runs_endpoint_passes_date_range_to_repository(monkeypatch):
    route = route_for("/classifier/runs", "GET")

    class FakeRepository(_SessionVersionMixin):
        def list_classifier_runs(self, **kwargs):
            assert kwargs["from_ts"] == 1000.0
            assert kwargs["to_ts"] == 2000.0
            return []

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(
        dashboard_request(), from_ts=1000.0, to_ts=2000.0, limit=100
    )

    assert response == []


def test_list_classifier_runs_endpoint_fails_auth_when_database_missing(monkeypatch):
    """A missing database now fails the dashboard auth check itself (the
    session_version revocation lookup needs it), before the endpoint's own
    DatabaseNotConfiguredError handling is ever reached."""
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

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_list_classifier_runs_endpoint_requires_dashboard_session():
    route = route_for("/classifier/runs", "GET")

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(authenticated=False), limit=100)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_dashboard_report_summary_endpoint_returns_aggregates(monkeypatch):
    route = route_for("/reports/summary", "GET")
    summary = DashboardReportSummary(
        total_runs=12,
        elevated_runs=4,
        distinct_personas=3,
        manual_labels=2,
        average_risk_score=42.5,
        risk_counts={"high": 4, "low": 8},
        actor_counts={"commodity_bot": 7},
        intent_counts={"reconnaissance": 6},
    )

    class FakeRepository(_SessionVersionMixin):
        def get_dashboard_report_summary(self):
            return summary

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    assert route.endpoint(dashboard_request()) == summary
    assert route.response_model is DashboardReportSummary


def test_dashboard_report_summary_endpoint_requires_dashboard_session():
    route = route_for("/reports/summary", "GET")

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(authenticated=False))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_analytics_summary_endpoint_returns_aggregates(monkeypatch):
    from classifier.storage import AnalyticsSummary

    route = route_for("/analytics/summary", "GET")
    summary = AnalyticsSummary(
        intent_counts={"reconnaissance": 6},
        attacks_by_hour={f"{hour:02d}": 0 for hour in range(24)},
        risk_trend=[{"date": "2026-07-01", "high": 1, "medium": 2, "low": 3}],
        top_commands=[{"command": "whoami", "count": 9}],
        top_personas=[{"persona_id": "generic_linux", "count": 5}],
        top_countries=[{"country": "United States", "count": 3}],
    )

    class FakeRepository(_SessionVersionMixin):
        def get_analytics_summary(self, from_ts, to_ts):
            assert from_ts == 1000.0
            assert to_ts == 2000.0
            return summary

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(dashboard_request(), from_ts=1000.0, to_ts=2000.0)

    assert response == summary
    assert route.response_model is AnalyticsSummary


def test_analytics_summary_endpoint_requires_dashboard_session():
    route = route_for("/analytics/summary", "GET")

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(authenticated=False), from_ts=1000.0, to_ts=2000.0)

    assert exc_info.value.status_code == 401


def test_analytics_summary_endpoint_fails_auth_when_database_missing(monkeypatch):
    """A missing database now fails the dashboard auth check itself (the
    session_version revocation lookup needs it), before the endpoint's own
    DatabaseNotConfiguredError handling is ever reached."""
    route = route_for("/analytics/summary", "GET")

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", MissingDatabaseRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(), from_ts=1000.0, to_ts=2000.0)

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

    class FakeRepository(_SessionVersionMixin):
        def get_manual_label(self, label_id):
            assert label_id == label.id
            return label

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(label.id, dashboard_request())

    assert response == label


def test_get_manual_label_endpoint_reports_missing_label(monkeypatch):
    route = route_for("/manual-labels/{label_id}", "GET")
    label_id = SessionRecord.parse_obj(make_record()).session_id

    class FakeRepository(_SessionVersionMixin):
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

    class FakeRepository(_SessionVersionMixin):
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


def test_list_manual_labels_endpoint_fails_auth_when_database_missing(monkeypatch):
    """A missing database now fails the dashboard auth check itself (the
    session_version revocation lookup needs it), before the endpoint's own
    DatabaseNotConfiguredError handling is ever reached."""
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

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_classify_session_route_accepts_session_record_body_model():
    route = route_for("/classify/session", "POST")

    assert route.body_field is not None
    assert route.body_field.type_ is SessionRecord


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
    }
    fields.update(overrides)
    return IssueRecord(**fields)


def test_list_issues_endpoint_returns_stored_issues(monkeypatch):
    route = route_for("/issues", "GET")
    issue = make_issue()

    class FakeRepository(_SessionVersionMixin):
        def list_issues(self, *, status, limit):
            assert status == "open"
            assert limit == 50
            return [issue]

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(dashboard_request(), status="open", limit=50)

    assert response == [issue]


def test_list_issues_endpoint_requires_dashboard_session():
    route = route_for("/issues", "GET")

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(authenticated=False), status=None, limit=100)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_list_issues_endpoint_fails_auth_when_database_missing(monkeypatch):
    """A missing database now fails the dashboard auth check itself (the
    session_version revocation lookup needs it), before the endpoint's own
    DatabaseNotConfiguredError handling is ever reached."""
    route = route_for("/issues", "GET")

    class MissingDatabaseRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", MissingDatabaseRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(), status=None, limit=100)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_update_issue_status_endpoint_returns_updated_issue(monkeypatch):
    route = route_for("/issues/{issue_id}/status", "PATCH")
    issue = make_issue(status="closed")

    class FakeRepository(_SessionVersionMixin):
        def update_issue_status(self, issue_id, status):
            assert issue_id == issue.id
            assert status == "closed"
            return issue

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    response = route.endpoint(issue.id, IssueStatusUpdate(status="closed"), dashboard_request())

    assert response == issue


def test_update_issue_status_endpoint_reports_missing_issue(monkeypatch):
    route = route_for("/issues/{issue_id}/status", "PATCH")
    issue_id = make_issue().id

    class FakeRepository(_SessionVersionMixin):
        def update_issue_status(self, requested_issue_id, status):
            assert requested_issue_id == issue_id
            return None

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(issue_id, IssueStatusUpdate(status="closed"), dashboard_request())

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "issue not found"


def test_update_issue_status_endpoint_requires_dashboard_session():
    route = route_for("/issues/{issue_id}/status", "PATCH")
    issue_id = make_issue().id

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(
            issue_id,
            IssueStatusUpdate(status="closed"),
            dashboard_request(authenticated=False),
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "dashboard auth required"


def test_issue_status_update_rejects_unsupported_status_value():
    with pytest.raises(ValidationError, match="status must be one of"):
        IssueStatusUpdate(status="archived")


def test_create_persona_config_endpoint_binds_persona_id_as_path_param(monkeypatch):
    """persona_id must be a path parameter, matching the GET/PUT/DELETE routes
    for the same resource, not an implicit query parameter."""
    route = route_for("/persona-configs/{persona_id}", "POST")
    payload = PersonaConfigInput(name="Custom demo box", running_processes=["nginx"])

    class FakeRepository(_SessionVersionMixin):
        def create_persona_config(self, persona_id, config):
            assert persona_id == "custom_demo_box"
            assert config is payload
            return PersonaConfigRecord(
                id=persona_id,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                **config.dict(),
            )

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    result = route.endpoint(dashboard_request(), payload, persona_id="custom_demo_box")

    assert result.id == "custom_demo_box"
    assert result.name == "Custom demo box"


def test_create_persona_config_endpoint_reports_conflict_on_duplicate_id(monkeypatch):
    """The repository's unique-constraint handling (not a prior existence
    check) is what produces this 409 -- see PersonaConfigAlreadyExistsError."""
    route = route_for("/persona-configs/{persona_id}", "POST")
    payload = PersonaConfigInput(name="Custom demo box", running_processes=["nginx"])

    class FakeRepository(_SessionVersionMixin):
        def create_persona_config(self, persona_id, config):
            raise PersonaConfigAlreadyExistsError(persona_id)

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    with pytest.raises(HTTPException) as exc_info:
        route.endpoint(dashboard_request(), payload, persona_id="custom_demo_box")

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "persona config already exists"


def test_persona_id_path_param_is_constrained_to_a_slug_on_every_route():
    """persona_id ends up as a Postgres primary key, a URL path segment, and
    the ECHIDRA_PERSONA env var lookup key -- constrain it the same way on
    every route so an empty/oversized/exotic-charset value 422s before ever
    reaching the repository, instead of only being caught (or not) once it
    gets there."""
    routes = [
        ("/persona-configs/{persona_id}", "POST"),
        ("/persona-configs/{persona_id}", "GET"),
        ("/persona-configs/{persona_id}", "PUT"),
        ("/persona-configs/{persona_id}", "DELETE"),
        ("/persona-configs/{persona_id}/analytics", "GET"),
    ]
    for path, method in routes:
        route = route_for(path, method)
        [persona_id_param] = [f for f in route.dependant.path_params if f.name == "persona_id"]
        assert persona_id_param.field_info.regex == app_module._PERSONA_ID_PATTERN, (path, method)


@pytest.mark.parametrize(
    "persona_id",
    [
        "",
        "Ubuntu_Web_Server",  # uppercase
        "1generic_linux",  # leading digit
        "_generic_linux",  # leading underscore
        "generic linux",  # space
        "generic-linux",  # hyphen (existing presets use underscores only)
        "../etc/passwd",
        "a" * 65,  # one over the 64-char cap
    ],
)
def test_persona_id_pattern_rejects_non_slug_values(persona_id):
    assert re.fullmatch(app_module._PERSONA_ID_PATTERN, persona_id) is None


@pytest.mark.parametrize(
    "persona_id",
    ["generic_linux", "ubuntu_web_server", "a", "a1", "a" * 64],
)
def test_persona_id_pattern_accepts_valid_slugs(persona_id):
    assert re.fullmatch(app_module._PERSONA_ID_PATTERN, persona_id) is not None


def test_count_alert_events_endpoint_returns_authoritative_total(monkeypatch):
    """The dashboard's Total Alerts tile needs this separate count endpoint
    since list_alert_events_endpoint is capped at 500 rows."""
    route = route_for("/alerts/events/count", "GET")

    class FakeRepository(_SessionVersionMixin):
        def count_alert_events(self):
            return 734

    monkeypatch.setattr(app_module, "PostgresClassifierRepository", FakeRepository)

    result = route.endpoint(dashboard_request())

    assert result == {"total": 734}
