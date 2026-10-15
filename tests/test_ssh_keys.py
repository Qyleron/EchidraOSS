import asyncssh

from honeypot.network.ssh_keys import ensure_host_key, ensure_host_keys


def test_generates_an_rsa_an_ecdsa_and_an_ed25519_key_once(tmp_path):
    key_path = tmp_path / "ssh_host_key"

    first = ensure_host_keys(str(key_path))
    second = ensure_host_keys(str(key_path))

    assert [key.get_algorithm() for key in first] == ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"]
    assert [key.export_public_key() for key in first] == [key.export_public_key() for key in second]
    for name in ("ssh_host_key", "ssh_host_key.rsa", "ssh_host_key.ecdsa"):
        assert (tmp_path / name).stat().st_mode & 0o777 == 0o600


def test_an_existing_ed25519_key_is_kept(tmp_path):
    """Installs from before the RSA and ECDSA keys existed keep presenting
    the Ed25519 key returning visitors already saw."""
    key_path = tmp_path / "ssh_host_key"
    original = ensure_host_key(str(key_path))

    keys = ensure_host_keys(str(key_path))

    assert keys[2].export_public_key() == original.export_public_key()


def test_generates_a_new_key_when_none_exists(tmp_path):
    key_path = tmp_path / "nested" / "ssh_host_key"

    key = ensure_host_key(str(key_path))

    assert key_path.exists()
    assert isinstance(key, asyncssh.SSHKey)


def test_reuses_the_same_key_across_restarts(tmp_path):
    """A honeypot that presents a different host key every restart is a
    tell, and breaks known_hosts pinning for repeat visitors -- the key
    must survive across process restarts, not just the current one."""
    key_path = tmp_path / "ssh_host_key"

    first = ensure_host_key(str(key_path))
    second = ensure_host_key(str(key_path))

    assert first.export_public_key() == second.export_public_key()


def test_generated_key_file_is_not_world_readable(tmp_path):
    key_path = tmp_path / "ssh_host_key"

    ensure_host_key(str(key_path))

    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600
