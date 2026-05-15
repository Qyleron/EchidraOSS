import time

from honeypot.core.session import SessionState


def test_session_initialization():
    session = SessionState(("127.0.0.1", 4444))

    assert session.peer == ("127.0.0.1", 4444)
    assert session.cwd == "/home/admin"
    assert session.command_count == 0
    assert isinstance(session.files, dict)


def test_command_logging():
    session = SessionState(("127.0.0.1", 4444))

    session.log_command("whoami")

    assert session.command_count == 1
    assert len(session.commands) == 1
    assert session.commands[0]["cmd"] == "whoami"


def test_last_active_updates():
    session = SessionState(("127.0.0.1", 4444))

    old_time = session.last_active

    time.sleep(0.01)

    session.log_command("ls")

    assert session.last_active > old_time