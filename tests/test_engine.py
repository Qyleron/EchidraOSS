from honeypot.core.engine import InteractionEngine
from honeypot.core.session import SessionState


def create_session():
    return SessionState(("127.0.0.1", 4444))


def test_banner():
    engine = InteractionEngine()
    session = create_session()

    banner = engine.build_banner(session)

    assert "Linux" in banner
    assert "/home/admin$" in banner


def test_whoami():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("whoami", session)

    assert "root" in response


def test_pwd():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("pwd", session)

    assert "/home/admin" in response


def test_unknown_command():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("abcdef", session)

    assert "command not found" in response


def test_exit():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("exit", session)

    assert response == "__CLOSE__"


def test_cat_existing_file():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process(
        "cat /etc/passwd",
        session
    )

    assert "root:x:0:0" in response


def test_cat_missing_file():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process(
        "cat /fake/file",
        session
    )

    assert "No such file" in response