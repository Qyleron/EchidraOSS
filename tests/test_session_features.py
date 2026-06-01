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


def test_handles_malformed_shell_input_as_observed_command():
    """Malformed input should remain measurable without crashing extraction."""
    session = create_session([
        ("cat 'unterminated", 1.0),
    ])

    features = extract_session_features(session)

    assert features.command_names == ["cat"]
    assert features.file_read_count == 1
