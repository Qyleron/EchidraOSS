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

    return SessionRecord.parse_obj({
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
    return SessionRecord.parse_obj({
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
    return SessionRecord.parse_obj({
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
    return SessionRecord.parse_obj({
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


def test_handles_malformed_shell_input_as_observed_command():
    """Malformed input should remain measurable without crashing extraction."""
    session = create_session([
        ("cat 'unterminated", 1.0),
    ])

    features = extract_session_features(session)

    assert features.command_names == ["cat"]
    assert features.file_read_count == 1
