"""Rule-matching coverage for the FTP/Telnet/HTTP-specific rules in
default_rules.yaml, using the exact command strings each real protocol
handler logs (see ftp_handler.py, telnet_handler.py, http_handler.py) --
not synthetic shell commands -- so these tests fail if a handler's log
format ever drifts out of sync with what the rules actually match on."""

import uuid

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord


def make_session(protocol, commands, duration_seconds, persona_id="generic_linux"):
    started_at = 100.0
    command_events = [
        {"cmd": cmd, "timestamp": started_at + offset}
        for cmd, offset in commands
    ]
    return SessionRecord.parse_obj({
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": protocol,
        "peer_ip": "203.0.113.7",
        "peer_port": 44321,
        "persona_id": persona_id,
        "started_at": started_at,
        "ended_at": started_at + duration_seconds,
        "duration_seconds": duration_seconds,
        "end_reason": "disconnect",
        "command_count": len(command_events),
        "commands": command_events,
        "decoy_files_surfaced": [],
    })


def test_ftp_banner_probe_with_no_credentials_matches():
    """A scanner that connects and sends garbage instead of USER (or nothing
    recognizable at all) is a banner-grab, not a credential attempt."""
    session = make_session("ftp", [("SYST", 0.5)], duration_seconds=0.5)

    summary = classify_session(session)

    assert "ftp_banner_probe_no_credentials" in summary.matched_rule_ids
    assert "ftp_automated_credential_burst" not in summary.matched_rule_ids


def test_ftp_automated_credential_burst_matches_bot_speed_submission():
    session = make_session(
        "ftp",
        [("USER admin", 0.0), ("PASS admin123", 0.1)],
        duration_seconds=0.1,
    )

    summary = classify_session(session)

    assert "ftp_automated_credential_burst" in summary.matched_rule_ids


def test_ftp_manual_speed_credential_submission_does_not_match_burst_rule():
    """The same USER/PASS pair, submitted at plausible human typing speed,
    must not be flagged as an automated burst -- only authentication_attempt
    (protocol-agnostic) should fire."""
    session = make_session(
        "ftp",
        [("USER admin", 0.0), ("PASS admin123", 8.0)],
        duration_seconds=8.0,
    )

    summary = classify_session(session)

    assert "ftp_automated_credential_burst" not in summary.matched_rule_ids
    assert "authentication_attempt" in summary.matched_rule_ids


def test_telnet_banner_probe_with_no_credentials_matches():
    session = make_session("telnet", [("\xff\xfb\x01", 0.2)], duration_seconds=0.2)

    summary = classify_session(session)

    assert "telnet_banner_probe_no_credentials" in summary.matched_rule_ids


def test_telnet_automated_credential_burst_matches_mirai_style_submission():
    session = make_session(
        "telnet",
        [("login: admin", 0.0), ("password: xc3511", 0.05)],
        duration_seconds=0.05,
    )

    summary = classify_session(session)

    assert "telnet_automated_credential_burst" in summary.matched_rule_ids


def test_mirai_iot_credential_burst_matches_known_default_pair():
    session = make_session(
        "telnet",
        [("login: root", 0.0), ("password: xc3511", 8.0)],
        duration_seconds=8.0,
        persona_id="busybox_router",
    )

    summary = classify_session(session)

    assert "mirai_iot_credential_burst" in summary.matched_rule_ids


def test_mirai_iot_credential_burst_is_case_insensitive():
    session = make_session(
        "telnet",
        [("login: Root", 0.0), ("password: XC3511", 8.0)],
        duration_seconds=8.0,
        persona_id="busybox_router",
    )

    summary = classify_session(session)

    assert "mirai_iot_credential_burst" in summary.matched_rule_ids


def test_non_mirai_credential_pair_does_not_match_iot_rule():
    """An arbitrary (non-wordlist) credential pair should still be caught by
    the generic burst/attempt rules, but not misattributed to Mirai."""
    session = make_session(
        "telnet",
        [("login: alice", 0.0), ("password: hunter2", 0.05)],
        duration_seconds=0.05,
    )

    summary = classify_session(session)

    assert "mirai_iot_credential_burst" not in summary.matched_rule_ids
    assert "telnet_automated_credential_burst" in summary.matched_rule_ids


def test_http_sensitive_path_probe_matches_env_request():
    session = make_session(
        "http",
        [("GET /.env HTTP/1.1", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_sensitive_path_probe" in summary.matched_rule_ids


def test_http_ordinary_request_does_not_match_sensitive_path_probe():
    session = make_session(
        "http",
        [("GET /index.html HTTP/1.1", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_sensitive_path_probe" not in summary.matched_rule_ids


def test_http_credential_harvest_attempt_matches_login_form_post():
    session = make_session(
        "http",
        [("POST /wp-login.php: log=admin&pwd=hunter2", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_credential_harvest_attempt" in summary.matched_rule_ids


def test_http_post_without_credential_fields_does_not_match_harvest_rule():
    session = make_session(
        "http",
        [("POST /api/contact: message=hello HTTP/1.1", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_credential_harvest_attempt" not in summary.matched_rule_ids


def test_http_known_scanner_user_agent_matches_masscan():
    session = make_session(
        "http",
        [("User-Agent: masscan/1.3", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_known_scanner_user_agent" in summary.matched_rule_ids


def test_http_ordinary_browser_user_agent_does_not_match_scanner_rule():
    session = make_session(
        "http",
        [("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_known_scanner_user_agent" not in summary.matched_rule_ids


def test_single_command_matching_no_rule_returns_insufficient_data():
    """A 2-second session with one command that matches nothing has no
    command or timing evidence at all -- that's insufficient_data, not a
    low-confidence guess."""
    session = make_session("tcp_shell", [("ls", 0.0)], duration_seconds=2.0)

    summary = classify_session(session)

    assert summary.matched_rule_ids == []
    assert summary.classification_status == "insufficient_data"
    assert summary.actor_label is None


def test_single_command_matching_a_rule_returns_partial_not_complete():
    """A 2-second session with one command that does match a rule (eg.
    "sqlmap ..." triggering script_kiddie_tool_names) still only carries one
    command's worth of evidence -- classification_status must read
    "partial", not "complete", even though a rule fired and actor_label is
    populated."""
    session = make_session(
        "tcp_shell",
        [("sqlmap -u http://target", 0.0)],
        duration_seconds=2.0,
    )

    summary = classify_session(session)

    assert "script_kiddie_tool_names" in summary.matched_rule_ids
    assert summary.actor_label == "script_kiddie"
    assert summary.classification_status == "partial"


def test_repeat_connections_at_five_matches_brute_force_bot_with_t1110():
    """5+ connections from the same source IP in 24h is the documented
    threshold for repeat_connections_same_ip -- verify the boundary itself,
    not just that the rule exists."""
    session = make_session("tcp_shell", [("whoami", 0.0)], duration_seconds=0.1)

    summary = classify_session(session, connection_count_from_same_ip=5)

    assert "repeat_connections_same_ip" in summary.matched_rule_ids
    assert summary.actor_label == "brute_force_bot"
    assert "T1110" in summary.mitre_tags


def test_repeat_connections_at_four_does_not_match():
    """One connection short of the threshold must not fire the rule."""
    session = make_session("tcp_shell", [("whoami", 0.0)], duration_seconds=0.1)

    summary = classify_session(session, connection_count_from_same_ip=4)

    assert "repeat_connections_same_ip" not in summary.matched_rule_ids
