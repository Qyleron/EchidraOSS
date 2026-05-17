from honeypot.network import config


def test_active_persona_is_cached_and_can_be_cleared(monkeypatch):
    """Persona validation should be reused until config is explicitly reloaded."""
    config.clear_active_persona_cache()
    monkeypatch.setattr(config, "PERSONA_ID", "generic_linux")

    first = config.get_active_persona()
    second = config.get_active_persona()

    assert first is second
    assert first.persona_id == "generic_linux"

    monkeypatch.setattr(config, "PERSONA_ID", "ubuntu_web_server")
    assert config.get_active_persona().persona_id == "generic_linux"

    config.clear_active_persona_cache()
    assert config.get_active_persona().persona_id == "ubuntu_web_server"

    config.clear_active_persona_cache()
