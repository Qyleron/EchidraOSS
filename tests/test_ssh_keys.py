import asyncssh

from honeypot.network.ssh_keys import ensure_host_key


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
