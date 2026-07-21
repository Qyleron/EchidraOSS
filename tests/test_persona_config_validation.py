"""Validation coverage for PersonaConfigInput -- an analyst-submitted
persona config is a real trust boundary (it's saved to Postgres and later
reconstituted into the live honeypot's Persona object), so these fields
need more than the bare `str`/`list[str]` types they started as."""

import pytest
from pydantic import ValidationError

from classifier.storage.models import DecoyFile, PersonaConfigInput


def valid_fields(**overrides):
    fields = {"name": "Custom demo box"}
    fields.update(overrides)
    return fields


def test_accepts_a_minimal_valid_config():
    config = PersonaConfigInput(**valid_fields())
    assert config.name == "Custom demo box"


def test_rejects_empty_name():
    with pytest.raises(ValidationError):
        PersonaConfigInput(**valid_fields(name=""))


def test_rejects_name_over_max_length():
    with pytest.raises(ValidationError):
        PersonaConfigInput(**valid_fields(name="a" * 101))


@pytest.mark.parametrize(
    "field,limit",
    [("os_banner", 256), ("ssh_banner", 256), ("hostname", 253), ("timezone", 64), ("internal_notes", 4_000)],
)
def test_rejects_string_fields_over_max_length(field, limit):
    with pytest.raises(ValidationError):
        PersonaConfigInput(**valid_fields(**{field: "a" * (limit + 1)}))


@pytest.mark.parametrize("service", ["ssh", "http", "ftp", "telnet"])
def test_rejects_enabled_service_without_a_port(service):
    with pytest.raises(ValidationError, match=f"{service}_port is required"):
        PersonaConfigInput(**valid_fields(**{f"{service}_enabled": True}))


@pytest.mark.parametrize("service", ["ssh", "http", "ftp", "telnet"])
def test_accepts_enabled_service_with_a_port(service):
    config = PersonaConfigInput(**valid_fields(**{f"{service}_enabled": True, f"{service}_port": 2222}))
    assert getattr(config, f"{service}_port") == 2222


def test_rejects_too_many_fake_users():
    with pytest.raises(ValidationError):
        PersonaConfigInput(**valid_fields(fake_users=[f"user{i}" for i in range(101)]))


def test_rejects_blank_fake_user_entry():
    with pytest.raises(ValidationError, match="blank"):
        PersonaConfigInput(**valid_fields(fake_users=["deploy", "   "]))


def test_rejects_oversized_running_process_entry():
    with pytest.raises(ValidationError, match="128 characters"):
        PersonaConfigInput(**valid_fields(running_processes=["a" * 129]))


def test_rejects_too_many_decoy_files():
    files = [DecoyFile(path=f"/tmp/f{i}", content="x") for i in range(51)]
    with pytest.raises(ValidationError):
        PersonaConfigInput(**valid_fields(decoy_files=files))


def test_rejects_duplicate_decoy_file_paths():
    files = [
        DecoyFile(path="/home/admin/notes.txt", content="a"),
        DecoyFile(path="/home/admin/notes.txt", content="b"),
    ]
    with pytest.raises(ValidationError, match="duplicate paths"):
        PersonaConfigInput(**valid_fields(decoy_files=files))


@pytest.mark.parametrize("bad_path", ["etc/passwd", "../etc/passwd", "/etc/../../passwd"])
def test_rejects_unsafe_decoy_file_paths(bad_path):
    with pytest.raises(ValidationError, match="safe absolute path"):
        DecoyFile(path=bad_path, content="x")


def test_rejects_oversized_decoy_file_content():
    with pytest.raises(ValidationError):
        DecoyFile(path="/tmp/big", content="x" * 65_537)


@pytest.mark.parametrize("bad_email", ["not-an-email", "missing-domain@", "@missing-local.com", "spaced out@example.com"])
def test_rejects_malformed_contact_email(bad_email):
    with pytest.raises(ValidationError, match="valid email"):
        PersonaConfigInput(**valid_fields(contact_email=bad_email))


def test_accepts_well_formed_contact_email():
    config = PersonaConfigInput(**valid_fields(contact_email="analyst@example.com"))
    assert config.contact_email == "analyst@example.com"


@pytest.mark.parametrize(
    "bad_webhook",
    [
        "http://hooks.slack.com/services/x",
        "hooks.slack.com/services/x",
        "ftp://example.com",
        "https://example.com/not-slack",  # https, but not hooks.slack.com
        "https://evil.com/?u=https://hooks.slack.com/services/x",  # domain check must anchor at the start
    ],
)
def test_rejects_non_slack_webhook(bad_webhook):
    with pytest.raises(ValidationError, match="hooks.slack.com"):
        PersonaConfigInput(**valid_fields(slack_webhook=bad_webhook))


def test_accepts_hooks_slack_com_webhook():
    config = PersonaConfigInput(
        **valid_fields(slack_webhook="https://hooks.slack.com/services/T000/B000/XXXX")
    )
    assert config.slack_webhook == "https://hooks.slack.com/services/T000/B000/XXXX"


def test_rejects_email_routing_without_contact_email():
    with pytest.raises(ValidationError, match="contact_email is required"):
        PersonaConfigInput(**valid_fields(alert_routing_level="email"))


def test_rejects_slack_routing_without_webhook():
    with pytest.raises(ValidationError, match="slack_webhook is required"):
        PersonaConfigInput(**valid_fields(alert_routing_level="slack"))


def test_rejects_both_routing_missing_either_destination():
    with pytest.raises(ValidationError, match="slack_webhook is required"):
        PersonaConfigInput(**valid_fields(alert_routing_level="both", contact_email="analyst@example.com"))


def test_accepts_both_routing_with_both_destinations():
    config = PersonaConfigInput(
        **valid_fields(
            alert_routing_level="both",
            contact_email="analyst@example.com",
            slack_webhook="https://hooks.slack.com/services/T000/B000/XXXX",
        )
    )
    assert config.alert_routing_level == "both"


def test_none_routing_does_not_require_any_destination():
    config = PersonaConfigInput(**valid_fields(alert_routing_level="none"))
    assert config.contact_email is None
    assert config.slack_webhook is None


def test_http_server_type_defaults_to_nginx():
    config = PersonaConfigInput(**valid_fields())
    assert config.http_server_type == "nginx"


@pytest.mark.parametrize("value", ["nginx", "apache", "busybox", "none"])
def test_accepts_every_valid_http_server_type(value):
    config = PersonaConfigInput(**valid_fields(http_server_type=value))
    assert config.http_server_type == value


def test_rejects_an_unrecognized_http_server_type():
    """A typo or unsupported value must be caught at save time -- the same
    trust-boundary reasoning as every other enum-like field in this model.
    See honeypot/network/http_handler.py's _server_kind(), which reads this
    field directly and has no fallback for anything outside this set."""
    with pytest.raises(ValidationError, match="http_server_type must be one of"):
        PersonaConfigInput(**valid_fields(http_server_type="lighttpd"))
