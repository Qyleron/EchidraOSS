import pytest

from honeypot.core.persona import (
    PRESET_PERSONAS,
    FakeFile,
    Persona,
    get_persona,
    validate_persona,
)
from honeypot.core.session import SessionState


"""
These tests cover the persona configuration layer.
Personas are what make the honeypot look like a specific organization/server
instead of a generic fake Linux box.
"""


def test_oss_persona_presets_are_available():
    """OSS should ship with exactly the five supported preset personas."""
    assert set(PRESET_PERSONAS) == {
        "ubuntu_web_server",
        "centos_database",
        "debian_mail_server",
        "generic_linux",
        "windows_smb_server",
    }


def test_session_uses_selected_persona_filesystem_and_identity():
    """A session should copy identity and fake files from the selected persona."""
    persona = get_persona("ubuntu_web_server")

    session = SessionState(("127.0.0.1", 4444), persona=persona)

    assert session.persona_id == "ubuntu_web_server"
    assert session.cwd == "/home/ubuntu"
    assert session.files["/var/www/html/wp-config.php"].startswith("define('DB_NAME'")


def test_unknown_persona_is_rejected_with_valid_options():
    """Selecting a typo or missing persona should fail clearly."""
    with pytest.raises(ValueError, match="Unknown persona"):
        get_persona("does_not_exist")


def test_persona_validation_rejects_invalid_file_paths():
    """Fake files must use safe absolute Linux paths."""
    persona = Persona(
        persona_id="invalid",
        os_banner="Linux invalid",
        ssh_banner="SSH-2.0-OpenSSH_9.0",
        hostname="invalid",
        uname_output="Linux invalid",
        timezone="UTC",
        fake_filesystem=(FakeFile(path="../secret", content="nope"),),
    )

    with pytest.raises(ValueError, match="Invalid fake filesystem path"):
        validate_persona(persona)
