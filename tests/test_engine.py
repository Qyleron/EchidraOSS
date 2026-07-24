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
    assert "root@ip-10-0-0-12:/home/admin# " in banner


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


def test_cd_into_known_directory_updates_cwd_and_prints_nothing():
    """A successful cd is silent, matching real bash, and moves session.cwd.

    Targets /home, not /home/admin -- session.cwd already starts at
    /home/admin (the persona's home_dir), so cd'ing there wouldn't actually
    exercise a move; the assertion would pass even if cd were a no-op."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("cd /home", session)

    assert session.cwd == "/home"
    assert response == session.prompt()


def test_cd_dotdot_moves_up_one_directory():
    engine = InteractionEngine()
    session = create_session()

    engine.process("cd /home/admin", session)
    engine.process("cd ..", session)

    assert session.cwd == "/home"


def test_cd_with_no_args_goes_home():
    engine = InteractionEngine()
    session = create_session()

    engine.process("cd /home", session)
    response = engine.process("cd", session)

    assert session.cwd == session.persona.home_dir
    assert response == session.prompt()


def test_cd_into_unknown_path_reports_bash_style_error():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("cd /nope", session)

    assert "bash: cd: /nope: No such file or directory" in response
    assert session.cwd == session.persona.home_dir


def test_cd_into_a_file_reports_not_a_directory():
    """cd on a path that resolves to a known file (not a directory) should
    say "Not a directory", matching real bash's distinct error for that case."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("cd /etc/passwd", session)

    assert "bash: cd: /etc/passwd: Not a directory" in response
    assert session.cwd == session.persona.home_dir


def test_unknown_command():
    """Unknown commands should look like normal bash command-not-found errors."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("abcdef", session)

    assert "command not found" in response


def test_exit():
    """exit is represented internally by a close signal for the shell's caller."""
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
    assert session.decoy_files_surfaced == []


def test_cat_existing_file_records_surfaced_decoy_once():
    """Successful file reads should preserve persona-aware exposure context."""
    engine = InteractionEngine()
    session = create_session()

    engine.process("cat /etc/passwd", session)
    engine.process("cat /etc/passwd", session)

    assert session.decoy_files_surfaced == ["/etc/passwd"]


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
    assert "ubuntu@web-prod-01:/home/ubuntu$ " in banner


def test_prompt_uses_dollar_sign_for_a_non_root_persona():
    """Bash's own convention: a "#" prompt implies root -- a non-root persona
    (eg. ubuntu_web_server) must not get one, or the prompt would contradict
    what `whoami`/`id` already report for that session."""
    session = SessionState(
        ("127.0.0.1", 4444),
        persona=get_persona("ubuntu_web_server"),
    )

    assert session.prompt() == "ubuntu@web-prod-01:/home/ubuntu$ "


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
    assert session.decoy_files_surfaced == [
        "/var/www/html/index.php",
        "/var/www/html/wp-config.php",
    ]


def test_engine_normalizes_cat_paths():
    """cat should resolve shell-style path components before lookup."""
    engine = InteractionEngine()
    session = create_session()

    parent_path = engine.process("cat /home/admin/../admin/notes.txt", session)
    slash_path = engine.process("cat /home//admin/./notes.txt", session)
    home_path = engine.process("cat ~/notes.txt", session)

    assert "TODO: rotate credentials" in parent_path
    assert "TODO: rotate credentials" in slash_path
    assert "TODO: rotate credentials" in home_path


def test_engine_normalizes_ls_paths_without_escaping_root():
    """Path traversal should collapse at fake root, like a normal Linux path."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("ls /../../etc", session)

    assert "hosts" in response
    assert "passwd" in response
