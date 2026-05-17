from honeypot.core.engine import InteractionEngine
from honeypot.core.persona import get_persona
from honeypot.core.session import SessionState


"""
These tests focus on InteractionEngine, the fake shell brain.
They call engine.process() directly, so they are fast and do not need sockets.
"""


def create_session():
    """Create a default generic_linux session for simple command tests."""
    return SessionState(("127.0.0.1", 4444))


def test_banner():
    """The first text a visitor sees should include OS text and a prompt."""
    engine = InteractionEngine()
    session = create_session()

    banner = engine.build_banner(session)

    assert "Linux" in banner
    assert "/home/admin$" in banner


def test_whoami():
    """whoami should return the username exposed by the active persona."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("whoami", session)

    assert "root" in response


def test_pwd():
    """pwd should show the session's current fake directory."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("pwd", session)

    assert "/home/admin" in response


def test_unknown_command():
    """Unknown commands should look like normal bash command-not-found errors."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("abcdef", session)

    assert "command not found" in response


def test_exit():
    """exit is represented internally by a close signal for ConnectionHandler."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("exit", session)

    assert response == "__CLOSE__"


def test_cat_existing_file():
    """cat should read files from the session's fake filesystem."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process(
        "cat /etc/passwd",
        session
    )

    assert "root:x:0:0" in response


def test_cat_missing_file():
    """cat should return a believable missing-file error for unknown paths."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process(
        "cat /fake/file",
        session
    )

    assert "No such file" in response


def test_engine_uses_persona_identity_and_environment():
    """A non-default persona should change identity, processes, and ports."""
    engine = InteractionEngine()
    session = SessionState(
        ("127.0.0.1", 4444),
        persona=get_persona("ubuntu_web_server"),
    )

    banner = engine.build_banner(session)
    uname = engine.process("uname -a", session)
    hostname = engine.process("hostname", session)
    whoami = engine.process("whoami", session)
    processes = engine.process("ps", session)
    ports = engine.process("netstat -tulpn", session)

    assert "Ubuntu 20.04.6 LTS" in banner
    assert "web-prod-01" in uname
    assert "web-prod-01" in hostname
    assert "ubuntu" in whoami
    assert "nginx" in processes
    assert "0.0.0.0:443" in ports


def test_engine_lists_persona_filesystem_paths():
    """ls should build directory listings from the selected persona's files."""
    engine = InteractionEngine()
    session = SessionState(
        ("127.0.0.1", 4444),
        persona=get_persona("ubuntu_web_server"),
    )

    response = engine.process("ls /var/www/html", session)

    assert "index.php" in response
    assert "wp-config.php" in response
