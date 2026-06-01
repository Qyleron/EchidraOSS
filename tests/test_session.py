import time

from honeypot.core.session import SessionState


"""
These tests cover SessionState, the per-visitor memory object.
It stores the peer address, selected persona files, command history, and timing.
"""


def test_session_initialization():
    """A new session should start with default persona state and no commands."""
    session = SessionState(("127.0.0.1", 4444))

    assert session.peer == ("127.0.0.1", 4444)
    assert session.cwd == "/home/admin"
    assert session.command_count == 0
    assert isinstance(session.files, dict)


def test_command_logging():
    """log_command should save the raw command and increment the counter."""
    session = SessionState(("127.0.0.1", 4444))

    session.log_command("whoami")

    assert session.command_count == 1
    assert len(session.commands) == 1
    assert session.commands[0]["cmd"] == "whoami"


def test_last_active_updates():
    """last_active should move forward whenever the visitor sends a command."""
    session = SessionState(("127.0.0.1", 4444))

    old_time = session.last_active

    time.sleep(0.01)

    session.log_command("ls")

    assert session.last_active > old_time


def test_finalized_session_returns_structured_record():
    """Completed sessions should expose the stable shape used by JSONL logs."""
    session = SessionState(("127.0.0.1", 4444))
    session.log_command("whoami")

    session.finalize("logout")
    record = session.to_record()

    assert record["schema_version"] == 1
    assert record["session_id"] == session.session_id
    assert record["protocol"] == "tcp_shell"
    assert record["peer_ip"] == "127.0.0.1"
    assert record["peer_port"] == 4444
    assert record["persona_id"] == "generic_linux"
    assert record["end_reason"] == "logout"
    assert record["command_count"] == 1
    assert record["commands"][0]["cmd"] == "whoami"
    assert record["duration_seconds"] >= 0
