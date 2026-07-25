"""Tests for classifier/alerts.py: email/Slack channel routing and the raw
Slack webhook POST helper."""

import uuid

import pytest

from classifier import alerts as alerts_module
from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord
from classifier.storage.models import AlertConfigRecord, PersonaConfigRecord


def _session():
    started_at = 100.0
    commands = [
        {"cmd": "whoami", "timestamp": started_at + 1.0},
        {"cmd": "hostname", "timestamp": started_at + 3.0},
        {"cmd": "ls", "timestamp": started_at + 6.0},
        {"cmd": "cat /etc/passwd", "timestamp": started_at + 9.0},
    ]
    return SessionRecord.parse_obj(
        {
            "schema_version": 1,
            "session_id": str(uuid.uuid4()),
            "protocol": "tcp_shell",
            "peer_ip": "127.0.0.1",
            "peer_port": 4444,
            "persona_id": "generic_linux",
            "started_at": started_at,
            "ended_at": started_at + 13.0,
            "duration_seconds": 13.0,
            "end_reason": "disconnect",
            "command_count": len(commands),
            "commands": commands,
            "decoy_files_surfaced": ["/etc/passwd"],
        }
    )


def _session_and_summary():
    session = _session()
    summary = classify_session(session)
    assert summary.alert_action is not None  # sanity: this session must trigger an alert
    return session, summary


def _alert_config(**overrides):
    values = dict(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username=None,
        smtp_password_configured=False,
        smtp_from_email="alerts@example.com",
        smtp_use_tls=True,
        global_min_risk_level="low",
    )
    values.update(overrides)
    return AlertConfigRecord(**values)


def _persona_config(*, validate=True, **overrides):
    values = dict(
        id="generic_linux",
        name="Generic Linux",
        alert_routing_level="slack",
        alert_min_risk_level=None,
        contact_email=None,
        slack_webhook="https://hooks.slack.com/services/T000/B000/XXXX",
    )
    values.update(overrides)
    if not validate:
        # PersonaConfigRecord now requires slack_webhook/contact_email to
        # match alert_routing_level at save time -- .construct() bypasses
        # that to simulate a row saved before this validation existed
        # (eg. its webhook was cleared out-of-band), so _maybe_send_alert's
        # own per-channel defense-in-depth check is still exercised.
        return PersonaConfigRecord.construct(**values)
    return PersonaConfigRecord(**values)


class _FakeRepository:
    def __init__(self, alert_config, persona_config):
        self._alert_config = alert_config
        self._persona_config = persona_config
        self.inserted_events = []

    def get_alert_config(self):
        return self._alert_config

    def get_persona_config(self, persona_id):
        return self._persona_config

    def insert_alert_event(self, event):
        self.inserted_events.append(event)
        return event


def _patch_repository(monkeypatch, alert_config, persona_config):
    fake = _FakeRepository(alert_config, persona_config)
    monkeypatch.setattr(alerts_module, "PostgresClassifierRepository", lambda *a, **k: fake)
    return fake


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_slack_post_sends_json_payload_and_succeeds(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["body"] = request.data
        captured["timeout"] = timeout
        return _FakeResponse(200)

    monkeypatch.setattr(alerts_module.urllib.request, "urlopen", fake_urlopen)

    err = alerts_module._slack_post("https://hooks.slack.com/services/T/B/X", "hello")

    assert err is None
    assert captured["url"] == "https://hooks.slack.com/services/T/B/X"
    assert captured["method"] == "POST"
    assert b'"text": "hello"' in captured["body"]
    assert captured["timeout"] == 10


def test_slack_post_rejects_non_https_webhook(monkeypatch):
    called = False

    def fake_urlopen(*args, **kwargs):
        nonlocal called
        called = True
        return _FakeResponse(200)

    monkeypatch.setattr(alerts_module.urllib.request, "urlopen", fake_urlopen)

    err = alerts_module._slack_post("http://hooks.slack.com/services/T/B/X", "hello")

    assert err == "slack_webhook must be an https:// URL"
    assert called is False


def test_slack_post_returns_error_on_non_2xx_status(monkeypatch):
    monkeypatch.setattr(alerts_module.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(500))

    err = alerts_module._slack_post("https://hooks.slack.com/services/T/B/X", "hello")

    assert err == "slack webhook returned HTTP 500"


def test_slack_post_returns_error_on_network_exception(monkeypatch):
    def fake_urlopen(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(alerts_module.urllib.request, "urlopen", fake_urlopen)

    err = alerts_module._slack_post("https://hooks.slack.com/services/T/B/X", "hello")

    assert err == "connection refused"


def test_smtp_send_fails_closed_when_repository_has_no_password(monkeypatch):
    class FakeRepository:
        def get_alert_smtp_password(self):
            return None

    monkeypatch.setattr(alerts_module, "PostgresClassifierRepository", FakeRepository)

    err = alerts_module._smtp_send(
        _alert_config(smtp_username="alerts@example.com"), "dest@example.com", "subject", "body"
    )

    assert err == "smtp_username is set but no SMTP password is configured"


def test_smtp_send_hides_raw_exception_when_credential_load_fails(monkeypatch, caplog):
    """An unexpected error while loading the SMTP password (eg. a raw DB
    driver error) must not leak into the returned message -- it ends up in
    the dashboard's test-email response and the persisted alert_events log,
    neither of which should show internals."""

    class FakeRepository:
        def get_alert_smtp_password(self):
            raise RuntimeError("connection to server at 10.0.0.5 failed: password authentication failed")

    monkeypatch.setattr(alerts_module, "PostgresClassifierRepository", FakeRepository)

    with caplog.at_level("ERROR"):
        err = alerts_module._smtp_send(
            _alert_config(smtp_username="alerts@example.com"), "dest@example.com", "subject", "body"
        )

    assert err == "could not load SMTP credentials"
    assert "10.0.0.5" not in err
    assert "password authentication failed" not in err
    assert any("Could not load SMTP credentials" in record.message for record in caplog.records)


def test_smtp_send_logs_in_with_repository_returned_password(monkeypatch):
    class FakeRepository:
        def get_alert_smtp_password(self):
            return "the-real-password"

    monkeypatch.setattr(alerts_module, "PostgresClassifierRepository", FakeRepository)

    logins = []
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def starttls(self, context=None):
            pass

        def login(self, username, password):
            logins.append((username, password))

        def sendmail(self, from_addr, to_addrs, message):
            sent.append((from_addr, to_addrs))

    monkeypatch.setattr(alerts_module.smtplib, "SMTP", FakeSMTP)

    err = alerts_module._smtp_send(
        _alert_config(smtp_username="alerts@example.com"), "dest@example.com", "subject", "body"
    )

    assert err is None
    assert logins == [("alerts@example.com", "the-real-password")]
    assert sent == [("alerts@example.com", ["dest@example.com"])]


def test_smtp_send_uses_implicit_tls_on_port_465(monkeypatch):
    """Port 465 servers expect TLS from the first byte -- STARTTLS on a
    plaintext smtplib.SMTP connection is a different, incompatible protocol,
    so this must use smtplib.SMTP_SSL instead."""
    class FakeRepository:
        def get_alert_smtp_password(self):
            return "the-real-password"

    monkeypatch.setattr(alerts_module, "PostgresClassifierRepository", FakeRepository)

    logins = []
    sent = []
    ssl_calls = []
    plain_smtp_calls = []

    class FakeSMTP_SSL:
        def __init__(self, host, port, timeout=10, context=None):
            ssl_calls.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def login(self, username, password):
            logins.append((username, password))

        def sendmail(self, from_addr, to_addrs, message):
            sent.append((from_addr, to_addrs))

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            plain_smtp_calls.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def starttls(self, context=None):
            raise AssertionError("starttls() must not be called on an implicit-TLS connection")

        def login(self, username, password):
            logins.append((username, password))

        def sendmail(self, from_addr, to_addrs, message):
            sent.append((from_addr, to_addrs))

    monkeypatch.setattr(alerts_module.smtplib, "SMTP_SSL", FakeSMTP_SSL)
    monkeypatch.setattr(alerts_module.smtplib, "SMTP", FakeSMTP)

    err = alerts_module._smtp_send(
        _alert_config(smtp_username="alerts@example.com", smtp_port=465),
        "dest@example.com",
        "subject",
        "body",
    )

    assert err is None
    assert ssl_calls == [("smtp.example.com", 465)]
    assert plain_smtp_calls == []
    assert logins == [("alerts@example.com", "the-real-password")]
    assert sent == [("alerts@example.com", ["dest@example.com"])]


def test_maybe_send_alert_dispatches_to_slack_only_when_routing_is_slack(monkeypatch):
    session, summary = _session_and_summary()
    repository = _patch_repository(
        monkeypatch,
        _alert_config(),
        _persona_config(alert_routing_level="slack"),
    )
    monkeypatch.setattr(alerts_module, "_slack_post", lambda url, text: None)

    alerts_module._maybe_send_alert(None, session, summary)

    assert len(repository.inserted_events) == 1
    event = repository.inserted_events[0]
    assert event.channel == "slack"
    assert event.contact_email is None
    assert event.success is True


def test_maybe_send_alert_dispatches_to_both_channels_when_routing_is_both(monkeypatch):
    session, summary = _session_and_summary()
    repository = _patch_repository(
        monkeypatch,
        _alert_config(),
        _persona_config(alert_routing_level="both", contact_email="analyst@example.com"),
    )
    monkeypatch.setattr(alerts_module, "_smtp_send", lambda config, recipient, subject, body, html_body=None: None)
    monkeypatch.setattr(alerts_module, "_slack_post", lambda url, text: None)

    alerts_module._maybe_send_alert(None, session, summary)

    channels = {event.channel for event in repository.inserted_events}
    assert channels == {"email", "slack"}


def test_maybe_send_alert_skips_slack_channel_when_webhook_not_configured(monkeypatch):
    session, summary = _session_and_summary()
    repository = _patch_repository(
        monkeypatch,
        _alert_config(),
        _persona_config(
            validate=False,
            alert_routing_level="both",
            contact_email="analyst@example.com",
            slack_webhook=None,
        ),
    )
    monkeypatch.setattr(alerts_module, "_smtp_send", lambda config, recipient, subject, body, html_body=None: None)

    alerts_module._maybe_send_alert(None, session, summary)

    assert len(repository.inserted_events) == 1
    assert repository.inserted_events[0].channel == "email"


def test_maybe_send_alert_skips_entirely_when_routing_is_none(monkeypatch):
    session, summary = _session_and_summary()
    repository = _patch_repository(
        monkeypatch,
        _alert_config(),
        _persona_config(alert_routing_level="none"),
    )

    alerts_module._maybe_send_alert(None, session, summary)

    assert repository.inserted_events == []


def test_maybe_send_alert_records_slack_failure(monkeypatch):
    session, summary = _session_and_summary()
    repository = _patch_repository(
        monkeypatch,
        _alert_config(),
        _persona_config(alert_routing_level="slack"),
    )
    monkeypatch.setattr(alerts_module, "_slack_post", lambda url, text: "connection refused")

    alerts_module._maybe_send_alert(None, session, summary)

    event = repository.inserted_events[0]
    assert event.success is False
    assert event.error_message == "connection refused"
