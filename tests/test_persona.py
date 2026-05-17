import pytest

from honeypot.core.persona import (
    PRESET_PERSONAS,
    FakeCredential,
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
        "samba_file_server",
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


def test_legacy_windows_smb_persona_id_maps_to_samba_file_server():
    """Old configs should still load after the persona was renamed for clarity."""
    assert get_persona("windows_smb_server") == get_persona("samba_file_server")


def test_persona_validation_rejects_invalid_file_paths():
    """Fake files must use safe absolute Linux paths."""
    persona = Persona(
        persona_id="invalid",
        os_banner="Linux invalid",
        ssh_banner="SSH-2.0-OpenSSH_9.0",
        hostname="invalid",
        uname_output="Linux invalid",
        timezone="UTC",
        username="admin",
        home_dir="/home/admin",
        fake_filesystem=(FakeFile(path="../secret", content="nope"),),
    )

    with pytest.raises(ValueError, match="Invalid fake filesystem path"):
        validate_persona(persona)


def test_persona_validation_rejects_duplicate_file_paths():
    """Duplicate fake files would be silently overwritten in file_map."""
    persona = Persona(
        persona_id="invalid",
        os_banner="Linux invalid",
        ssh_banner="SSH-2.0-OpenSSH_9.0",
        hostname="invalid",
        uname_output="Linux invalid",
        timezone="UTC",
        username="admin",
        home_dir="/home/admin",
        fake_filesystem=(
            FakeFile(path="/home/admin/readme.txt", content="one"),
            FakeFile(path="/home/admin/readme.txt", content="two"),
        ),
    )

    with pytest.raises(ValueError, match="Duplicate fake filesystem path"):
        validate_persona(persona)


def test_persona_validation_rejects_empty_fake_credentials():
    """UI-submitted decoy credentials should not be empty placeholders."""
    persona = Persona(
        persona_id="invalid",
        os_banner="Linux invalid",
        ssh_banner="SSH-2.0-OpenSSH_9.0",
        hostname="invalid",
        uname_output="Linux invalid",
        timezone="UTC",
        username="admin",
        home_dir="/home/admin",
        fake_filesystem=(FakeFile(path="/home/admin/readme.txt", content="ok"),),
        fake_credentials=(FakeCredential(username="", password="secret"),),
    )

    with pytest.raises(ValueError, match="Fake credential"):
        validate_persona(persona)


def test_persona_validation_rejects_empty_fake_credential_password():
    """Empty decoy passwords should also be rejected."""
    persona = Persona(
        persona_id="invalid",
        os_banner="Linux invalid",
        ssh_banner="SSH-2.0-OpenSSH_9.0",
        hostname="invalid",
        uname_output="Linux invalid",
        timezone="UTC",
        username="admin",
        home_dir="/home/admin",
        fake_filesystem=(FakeFile(path="/home/admin/readme.txt", content="ok"),),
        fake_credentials=(FakeCredential(username="user", password=""),),
    )

    with pytest.raises(ValueError, match="Fake credential"):
        validate_persona(persona)


def test_persona_validation_requires_home_directory_content():
    """A persona should expose at least one fake file under its home directory."""
    persona = Persona(
        persona_id="invalid",
        os_banner="Linux invalid",
        ssh_banner="SSH-2.0-OpenSSH_9.0",
        hostname="invalid",
        uname_output="Linux invalid",
        timezone="UTC",
        username="admin",
        home_dir="/home/admin",
        fake_filesystem=(FakeFile(path="/etc/passwd", content="root:x:0:0\n"),),
    )

    with pytest.raises(ValueError, match="home_dir"):
        validate_persona(persona)
