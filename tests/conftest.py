import uuid

import pytest

from classifier.features.session import SessionFeatures
from honeypot.network import config as honeypot_config


@pytest.fixture(autouse=True)
def clear_persona_db_lookup(monkeypatch):
    """Keep every test deterministic regardless of a locally-configured
    ECHIDRA_DATABASE_URL -- get_active_persona() looks up a real DB row
    first by design (so dashboard-saved persona customizations reach the
    live honeypot), which means any test that exercises it would otherwise
    silently pick up whatever a developer has saved via the Personas page
    on their own machine instead of the hardcoded preset the tests assume.
    Tests that want DB-backed persona behavior already opt back in
    explicitly with their own monkeypatch.setenv("ECHIDRA_DATABASE_URL",
    ...), which overrides this per-test."""
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)
    yield
    honeypot_config.clear_active_persona_cache()


def require_bound_server_address(server):
    """Return a server's bound address or skip when sockets are unavailable."""
    assert server.server is not None
    sockets = server.server.sockets or ()
    if not sockets:
        pytest.skip("asyncio server did not expose a bound socket")

    return sockets[0].getsockname()[:2]


def make_features(**overrides):
    data = {
        "session_id": uuid.uuid4(),
        "protocol": "tcp_shell",
        "persona_id": "generic_linux",
        "end_reason": "logout",
        "duration_seconds": 10.0,
        "command_count": 4,
        "commands_per_minute": 24.0,
        "unique_command_count": 3,
        "repeated_command_count": 1,
        "discovery_command_count": 3,
        "file_read_count": 1,
        "sensitive_file_read_count": 1,
        "decoy_files_surfaced": ["/etc/passwd"],
        "decoy_files_surfaced_count": 1,
        "exit_command_present": False,
        "inter_command_intervals_seconds": [1.0, 2.0, 3.0],
        "average_inter_command_interval_seconds": 2.0,
        "command_names": ["whoami", "ls", "cat", "ls"],
    }
    data.update(overrides)
    return SessionFeatures.parse_obj(data)
