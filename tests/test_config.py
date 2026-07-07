import pytest

from honeypot.network import config


@pytest.fixture(autouse=True)
def clear_persona_db_lookup(monkeypatch):
    """Keep these tests deterministic regardless of a locally-configured
    ECHIDRA_DATABASE_URL — persona-from-DB behavior is tested explicitly
    below with a fake repository, never a real connection."""
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)
    yield
    config.clear_active_persona_cache()


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


def make_persona_config_record(**overrides):
    from classifier.storage import DecoyFile, PersonaConfigRecord

    fields = {
        "id": "custom_demo_box",
        "name": "Custom demo box",
        "os_banner": "Linux custom-demo-box 6.1.0-custom x86_64",
        "ssh_banner": "SSH-2.0-OpenSSH_9.0",
        "hostname": "custom-demo-box",
        "timezone": "America/New_York",
        "ssh_enabled": True,
        "ssh_port": 2222,
        "http_enabled": False,
        "ftp_enabled": False,
        "telnet_enabled": False,
        "fake_users": ["deploy", "backup"],
        "running_processes": ["nginx", "redis-server"],
        "decoy_files": [DecoyFile(path="/home/admin/notes.txt", content="todo: rotate keys")],
    }
    fields.update(overrides)
    return PersonaConfigRecord(**fields)


def test_active_persona_prefers_saved_persona_config_over_preset(monkeypatch):
    """A persona_configs row matching ECHIDRA_PERSONA should override the preset."""
    config.clear_active_persona_cache()
    monkeypatch.setenv("ECHIDRA_PERSONA", "custom_demo_box")
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://fake/fake")
    record = make_persona_config_record()

    class FakeRepository:
        def __init__(self):
            pass

        def get_persona_config(self, persona_id):
            assert persona_id == "custom_demo_box"
            return record

    monkeypatch.setattr("classifier.storage.PostgresClassifierRepository", FakeRepository)

    persona = config.get_active_persona()

    assert persona.persona_id == "custom_demo_box"
    assert persona.hostname == "custom-demo-box"
    assert persona.os_banner == "Linux custom-demo-box 6.1.0-custom x86_64"
    assert persona.timezone == "America/New_York"
    assert persona.fake_users == ("deploy", "backup")
    assert persona.running_processes == ("nginx", "redis-server")
    assert persona.open_ports_visible == (2222,)
    assert any(f.path == "/home/admin/notes.txt" for f in persona.fake_filesystem)
    # Fields the config schema doesn't capture yet still default sensibly.
    assert persona.username == "root"
    assert persona.home_dir == "/home/admin"


def test_active_persona_injects_home_dir_file_when_config_has_none_there(monkeypatch):
    """validate_persona() requires >=1 file under home_dir; a config with no
    decoy files placed there must still produce a valid persona."""
    config.clear_active_persona_cache()
    monkeypatch.setenv("ECHIDRA_PERSONA", "custom_demo_box")
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://fake/fake")
    record = make_persona_config_record(decoy_files=[])

    class FakeRepository:
        def __init__(self):
            pass

        def get_persona_config(self, persona_id):
            return record

    monkeypatch.setattr("classifier.storage.PostgresClassifierRepository", FakeRepository)

    persona = config.get_active_persona()  # must not raise

    assert any(
        f.path.startswith("/home/admin/") for f in persona.fake_filesystem
    )


def test_active_persona_falls_back_to_preset_when_no_matching_db_row(monkeypatch):
    config.clear_active_persona_cache()
    monkeypatch.setenv("ECHIDRA_PERSONA", "generic_linux")
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://fake/fake")

    class FakeRepository:
        def __init__(self):
            pass

        def get_persona_config(self, persona_id):
            return None

    monkeypatch.setattr("classifier.storage.PostgresClassifierRepository", FakeRepository)

    persona = config.get_active_persona()

    assert persona.persona_id == "generic_linux"
    assert persona.username == "root"


def test_active_persona_falls_back_to_preset_when_db_lookup_fails(monkeypatch):
    """A DB error (misconfiguration, connection drop) must not crash startup."""
    config.clear_active_persona_cache()
    monkeypatch.setenv("ECHIDRA_PERSONA", "generic_linux")
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://fake/fake")

    class CrashingRepository:
        def __init__(self):
            raise RuntimeError("connection refused")

    monkeypatch.setattr("classifier.storage.PostgresClassifierRepository", CrashingRepository)

    persona = config.get_active_persona()

    assert persona.persona_id == "generic_linux"


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
