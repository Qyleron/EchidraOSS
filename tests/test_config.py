import pytest

from honeypot.network import config


def test_active_persona_is_cached_until_env_persona_changes(monkeypatch):
    """Persona validation should be reused while ECHIDRA_PERSONA is unchanged."""
    config.clear_active_persona_cache()
    monkeypatch.setenv("ECHIDRA_PERSONA", "generic_linux")

    first = config.get_active_persona()
    second = config.get_active_persona()

    assert first is second
    assert first.persona_id == "generic_linux"

    monkeypatch.setenv("ECHIDRA_PERSONA", "ubuntu_web_server")
    assert config.get_active_persona().persona_id == "ubuntu_web_server"

    config.clear_active_persona_cache()


def test_active_persona_defaults_when_env_is_unset(monkeypatch):
    """Clearing ECHIDRA_PERSONA should reload the generic Linux persona."""
    config.clear_active_persona_cache()
    monkeypatch.delenv("ECHIDRA_PERSONA", raising=False)

    assert config.get_active_persona().persona_id == "generic_linux"

    config.clear_active_persona_cache()


def test_int_from_env_rejects_invalid_values(monkeypatch):
    monkeypatch.setenv("ECHIDRA_PORT", "not-a-port")

    try:
        config._int_from_env("ECHIDRA_PORT", 2222)
    except ValueError as exc:
        assert "ECHIDRA_PORT must be an integer" in str(exc)
    else:
        raise AssertionError("expected invalid integer env var to fail")


def test_port_from_env_rejects_values_outside_tcp_port_range(monkeypatch):
    monkeypatch.setenv("ECHIDRA_PORT", "70000")

    with pytest.raises(ValueError, match="ECHIDRA_PORT must be between 1 and 65535"):
        config._port_from_env("ECHIDRA_PORT", 2222)


def test_positive_int_from_env_rejects_zero(monkeypatch):
    monkeypatch.setenv("ECHIDRA_MAX_CONNECTIONS", "0")

    with pytest.raises(ValueError, match="ECHIDRA_MAX_CONNECTIONS must be positive"):
        config._positive_int_from_env("ECHIDRA_MAX_CONNECTIONS", 100)


def test_positive_int_from_env_rejects_negative_values(monkeypatch):
    monkeypatch.setenv("ECHIDRA_READ_TIMEOUT", "-1")

    with pytest.raises(ValueError, match="ECHIDRA_READ_TIMEOUT must be positive"):
        config._positive_int_from_env("ECHIDRA_READ_TIMEOUT", 60)
