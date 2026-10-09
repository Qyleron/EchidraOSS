import os
import subprocess
import sys
import threading

import pytest

from echidra import cli

_real_ports_in_use = cli._ports_in_use
_real_active_systemd_units = cli._active_systemd_units


@pytest.fixture(autouse=True)
def _skip_real_port_preflight(monkeypatch):
    # 'echidra start' probes the real listener ports before spawning
    # anything; the start tests below fake the processes, so they mustn't
    # depend on whether those ports happen to be free on this machine.
    monkeypatch.setattr(cli, "_ports_in_use", lambda *args, **kwargs: [])
    # Likewise for 'systemctl is-active' -- a dev machine may really have the
    # deploy/systemd units installed.
    monkeypatch.setattr(cli, "_active_systemd_units", lambda: [])


def test_echidra_cli_no_command_prints_help(capsys):
    exit_code = cli.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "usage: echidra" in captured.out


def test_echidra_cli_help_lists_all_subcommands(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    captured = capsys.readouterr()
    for subcommand in ("init", "start", "stop", "classify", "status", "blocklist", "reset-password", "help"):
        assert subcommand in captured.out


def test_echidra_cli_rejects_the_renamed_serve_command(capsys):
    """'serve' was renamed to 'start' with no backward-compat alias -- guard
    against it silently working again (eg. a careless future merge)."""
    with pytest.raises(SystemExit):
        cli.main(["serve"])

    captured = capsys.readouterr()
    assert "invalid choice: 'serve'" in captured.err


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_echidra_init_creates_env_from_example_and_generates_api_key(monkeypatch, tmp_path, capsys):
    env_path = tmp_path / ".env"
    env_example_path = tmp_path / ".env.example"
    env_example_path.write_text("ECHIDRA_HOST=0.0.0.0\n", encoding="utf-8")
    monkeypatch.setattr(cli, "ENV_PATH", env_path)
    monkeypatch.setattr(cli, "ENV_EXAMPLE_PATH", env_example_path)
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)

    exit_code = cli.main(["init"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert env_path.exists()
    assert "ECHIDRA_HOST=0.0.0.0" in env_path.read_text(encoding="utf-8")
    assert "ECHIDRA_INGEST_API_KEY=" in env_path.read_text(encoding="utf-8")
    # The generated key must not be an empty value.
    generated_line = next(
        line for line in env_path.read_text(encoding="utf-8").splitlines()
        if line.startswith("ECHIDRA_INGEST_API_KEY=")
    )
    assert len(generated_line.split("=", 1)[1]) > 10
    assert "skipping database setup" in captured.out


def test_echidra_init_does_not_overwrite_existing_env_or_key(monkeypatch, tmp_path, capsys):
    env_path = tmp_path / ".env"
    env_path.write_text("ECHIDRA_INGEST_API_KEY=already-set-key\n", encoding="utf-8")
    monkeypatch.setattr(cli, "ENV_PATH", env_path)
    monkeypatch.setattr(cli, "ENV_EXAMPLE_PATH", tmp_path / "does-not-exist.example")
    monkeypatch.delenv("ECHIDRA_DATABASE_URL", raising=False)

    exit_code = cli.main(["init"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert env_path.read_text(encoding="utf-8").count("ECHIDRA_INGEST_API_KEY=") == 1
    assert "already-set-key" in env_path.read_text(encoding="utf-8")
    assert "already exists" in captured.out
    assert "already set" in captured.out


def test_echidra_init_runs_schema_setup_when_database_configured(monkeypatch, tmp_path, capsys):
    env_path = tmp_path / ".env"
    monkeypatch.setattr(cli, "ENV_PATH", env_path)
    monkeypatch.setattr(cli, "ENV_EXAMPLE_PATH", tmp_path / "does-not-exist.example")
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://example/echidra")

    calls = []

    def fake_storage_main(argv):
        calls.append(argv)
        return 0

    import classifier.storage.cli as storage_cli_module
    monkeypatch.setattr(storage_cli_module, "main", fake_storage_main)

    exit_code = cli.main(["init", "--seed-demo-issues"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == [["init-db", "--seed-demo-issues"]]
    assert "initializing database schema" in captured.out


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


def test_echidra_classify_delegates_to_classifier_cli(monkeypatch, tmp_path):
    input_path = tmp_path / "sessions.jsonl"
    input_path.write_text("", encoding="utf-8")
    calls = []

    def fake_classifier_main(argv):
        calls.append(argv)
        return 0

    import classifier.cli as classifier_cli_module
    monkeypatch.setattr(classifier_cli_module, "main", fake_classifier_main)

    exit_code = cli.main(["classify", str(input_path)])

    assert exit_code == 0
    assert calls == [["classify-jsonl", str(input_path)]]


def test_echidra_classify_passes_through_output_flag(monkeypatch, tmp_path):
    input_path = tmp_path / "sessions.jsonl"
    output_path = tmp_path / "out.jsonl"
    calls = []

    import classifier.cli as classifier_cli_module
    monkeypatch.setattr(classifier_cli_module, "main", lambda argv: calls.append(argv) or 0)

    cli.main(["classify", str(input_path), "-o", str(output_path)])

    assert calls == [["classify-jsonl", str(input_path), "--output", str(output_path)]]


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def test_port_is_open_returns_false_for_closed_port():
    # Port 1 is a privileged, essentially never-listening port in test environments.
    assert cli._port_is_open("127.0.0.1", 1, timeout=0.2) is False


def test_check_start_process_reports_not_running_when_no_pidfile(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")

    cli._check_start_process()

    captured = capsys.readouterr()
    assert "not running" in captured.out


def test_check_start_process_reports_running_with_pids(monkeypatch, tmp_path, capsys):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
    # This test's own PID stands in for a running child, but pytest's real
    # cmdline obviously doesn't contain "honeypot.main" -- bypass the
    # ownership check itself rather than trying to fake this process's argv.
    monkeypatch.setattr(cli, "_pid_is_echidra_process", lambda pid: True)

    cli._check_start_process()

    captured = capsys.readouterr()
    assert "running" in captured.out
    assert str(os.getpid()) in captured.out


def test_check_honeypot_listeners_reports_disabled_ports(monkeypatch, capsys):
    monkeypatch.setattr("honeypot.network.config.HOST", "0.0.0.0")
    monkeypatch.setattr("honeypot.network.config.PORT", 2222)
    monkeypatch.setattr("honeypot.network.config.HTTP_PORT", 0)
    monkeypatch.setattr("honeypot.network.config.FTP_PORT", 0)
    monkeypatch.setattr("honeypot.network.config.TELNET_PORT", 0)
    monkeypatch.setattr(cli, "_port_is_open", lambda host, port, timeout=2.0: False)

    cli._check_honeypot_listeners()

    captured = capsys.readouterr()
    assert "HTTP" in captured.out and "disabled" in captured.out
    assert "SSH-style shell" in captured.out and "not reachable" in captured.out


def test_check_api_reports_unreachable_when_connection_fails(capsys):
    # Nothing is listening on this port in the test environment.
    cli._check_api("127.0.0.1", 1)

    captured = capsys.readouterr()
    assert "unreachable" in captured.out


def test_check_database_reports_not_configured(monkeypatch, capsys):
    from classifier.storage import DatabaseNotConfiguredError

    class FakeRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    import classifier.storage as storage_module
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", FakeRepository)

    cli._check_database()

    captured = capsys.readouterr()
    assert "not configured" in captured.out


def test_check_database_reports_session_counts_when_connected(monkeypatch, capsys):
    from classifier.storage import DashboardReportSummary

    summary = DashboardReportSummary(
        total_runs=42,
        elevated_runs=7,
        distinct_personas=3,
        manual_labels=1,
        average_risk_score=30.0,
        risk_counts={"high": 7},
        actor_counts={},
        intent_counts={},
    )

    class FakeRepository:
        def get_dashboard_report_summary(self):
            return summary

    import classifier.storage as storage_module
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", FakeRepository)

    cli._check_database()

    captured = capsys.readouterr()
    assert "connected" in captured.out
    assert "42" in captured.out
    assert "7" in captured.out


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------


class _FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None
        self._terminated = False
        self.sent_signals = []

    def poll(self):
        return self.returncode

    def send_signal(self, signum):
        self.sent_signals.append(signum)
        self.returncode = 0

    def terminate(self):
        self._terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode


def test_cmd_start_stops_both_processes_when_one_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")
    processes = [_FakeProcess(pid=100), _FakeProcess(pid=200)]
    popen_calls = []

    def fake_popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return processes[len(popen_calls) - 1]

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: processes[0].__setattr__("returncode", 0))
    monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

    args = cli._build_parser().parse_args(["start", "--api-port", "8123"])
    exit_code = cli._cmd_start(args)

    assert len(popen_calls) == 2
    assert "-m" in popen_calls[0] and "honeypot.main" in popen_calls[0]
    assert "uvicorn" in popen_calls[1]
    assert exit_code == 0
    # The still-running process must have been terminated once the other exited.
    assert processes[1]._terminated is True


def test_cmd_start_returns_zero_for_signal_interrupts(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")
    processes = [_FakeProcess(pid=100), _FakeProcess(pid=200)]
    popen_calls = []

    def fake_popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return processes[len(popen_calls) - 1]

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: processes[0].__setattr__("returncode", -2))
    monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

    def fake_terminate(self):
        self._terminated = True

    monkeypatch.setattr(cli.subprocess.Popen, "terminate", fake_terminate, raising=False)

    args = cli._build_parser().parse_args(["start", "--api-port", "8123"])
    exit_code = cli._cmd_start(args)

    assert exit_code == 0


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------


def test_cmd_start_refuses_to_start_over_a_still_running_previous_instance(monkeypatch, tmp_path, capsys):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    pid_path.write_text(f"{proc.pid}\n", encoding="utf-8")
    popen_calls = []
    monkeypatch.setattr(cli.subprocess, "Popen", lambda cmd, **kw: popen_calls.append(cmd))
    # This fake process can't actually run `-m honeypot.main` without
    # starting the real honeypot -- exercise the real /proc read and
    # liveness check, but stub just the argv-shape predicate so this
    # unrelated `python -c ...` process is still recognized as "ours".
    monkeypatch.setattr(cli, "_argv_matches_echidra_child", lambda argv: True)

    try:
        args = cli._build_parser().parse_args(["start", "--api-port", "8123"])
        exit_code = cli._cmd_start(args)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "still appears to be running" in captured.out
    # Must refuse before spawning anything new on top of the stuck ports.
    assert popen_calls == []
    # The still-running instance's pidfile is left alone, not clobbered.
    assert pid_path.read_text(encoding="utf-8").strip() == str(proc.pid)


def test_cmd_start_refuses_when_a_port_is_already_in_use(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")
    monkeypatch.setattr(cli, "_ports_in_use", lambda *args, **kwargs: [("SSH-style shell", 2222)])
    popen_calls = []
    monkeypatch.setattr(cli.subprocess, "Popen", lambda cmd, **kw: popen_calls.append(cmd))

    exit_code = cli._cmd_start(cli._build_parser().parse_args(["start", "--api-port", "8123"]))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Port 2222 (SSH-style shell) is already in use." in captured.out
    assert "docker compose ps" in captured.out
    assert popen_calls == []


def test_ports_in_use_detects_a_port_held_by_another_listener():
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        taken_port = holder.getsockname()[1]

        busy = _real_ports_in_use("127.0.0.1", taken_port)

    assert ("API/dashboard", taken_port) in busy


def test_cmd_start_names_the_systemd_service_holding_the_ports(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")
    monkeypatch.setattr(cli, "_ports_in_use", lambda *args, **kwargs: [("SSH-style shell", 2222)])
    monkeypatch.setattr(cli, "_active_systemd_units", lambda: ["echidra-api", "echidra-honeypot"])
    monkeypatch.setattr(cli.subprocess, "Popen", lambda cmd, **kw: pytest.fail("should not spawn"))

    exit_code = cli._cmd_start(cli._build_parser().parse_args(["start"]))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "sudo systemctl disable --now echidra-api echidra-honeypot" in captured.out


def test_stop_points_at_systemd_when_echidra_runs_as_a_service(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")
    monkeypatch.setattr(cli, "_active_systemd_units", lambda: ["echidra-honeypot"])

    exit_code = cli._cmd_stop(cli._build_parser().parse_args(["stop"]))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "sudo systemctl stop echidra-honeypot" in captured.out


def test_active_systemd_units_reads_systemctl_is_active(monkeypatch):
    class Result:
        stdout = "active\ninactive\n"

    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: Result())

    assert cli.SYSTEMD_UNITS == ("echidra-api", "echidra-honeypot")
    assert _real_active_systemd_units() == ["echidra-api"]


def test_active_systemd_units_is_empty_without_systemctl(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(cli.subprocess, "run", missing)

    assert _real_active_systemd_units() == []


def test_start_binds_the_dashboard_to_loopback_by_default():
    assert cli._build_parser().parse_args(["start"]).api_host == "127.0.0.1"


def _set_listener_ports(monkeypatch, ssh=2222, http=8080, ftp=2121, telnet=2323):
    monkeypatch.setattr("honeypot.network.config.HOST", "0.0.0.0")
    monkeypatch.setattr("honeypot.network.config.PORT", ssh)
    monkeypatch.setattr("honeypot.network.config.HTTP_PORT", http)
    monkeypatch.setattr("honeypot.network.config.FTP_PORT", ftp)
    monkeypatch.setattr("honeypot.network.config.TELNET_PORT", telnet)


def test_start_summary_lists_decoys_dashboard_and_tunnel_hint(monkeypatch, capsys):
    _set_listener_ports(monkeypatch)

    cli._print_start_summary("127.0.0.1", 8000, 100, 200)

    out = capsys.readouterr().out
    assert "Echidra is running." in out
    assert "Decoys:     SSH 2222, HTTP 8080, FTP 2121, Telnet 2323 (listening on 0.0.0.0)" in out
    assert "Dashboard:  http://127.0.0.1:8000" in out
    assert "ssh -L 8000:127.0.0.1:8000 <user>@<server>" in out
    assert "PIDs:       decoys 100, dashboard 200" in out
    assert "'echidra stop'" in out


def test_start_summary_skips_disabled_decoys_and_tunnel_hint_off_loopback(monkeypatch, capsys):
    _set_listener_ports(monkeypatch, http=0, telnet=0)

    cli._print_start_summary("0.0.0.0", 9000, 100, 200)

    out = capsys.readouterr().out
    assert "Decoys:     SSH 2222, FTP 2121 (listening on 0.0.0.0)" in out
    assert "Dashboard:  http://0.0.0.0:9000" in out
    assert "ssh -L" not in out


def test_cmd_start_clears_a_stale_pidfile_before_starting(monkeypatch, tmp_path):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    pid_path.write_text("999999\n", encoding="utf-8")  # PID from a process that's long gone
    processes = [_FakeProcess(pid=100), _FakeProcess(pid=200)]
    popen_calls = []

    def fake_popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return processes[len(popen_calls) - 1]

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: processes[0].__setattr__("returncode", 0))
    monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

    args = cli._build_parser().parse_args(["start", "--api-port", "8123"])
    exit_code = cli._cmd_start(args)

    assert exit_code == 0
    assert len(popen_calls) == 2


def test_stop_reports_nothing_running_when_pidfile_is_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "PID_PATH", tmp_path / "echidra.pid")

    exit_code = cli._cmd_stop(cli._build_parser().parse_args(["stop"]))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "doesn't appear to be running" in captured.out


def test_stop_terminates_a_real_process_and_removes_pidfile(monkeypatch, tmp_path, capsys):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    pid_path.write_text(f"{proc.pid}\n", encoding="utf-8")
    # This fake process can't actually run `-m honeypot.main` without
    # starting the real honeypot -- exercise the real /proc read and
    # liveness check, but stub just the argv-shape predicate so this
    # unrelated `python -c ...` process is still recognized as "ours".
    monkeypatch.setattr(cli, "_argv_matches_echidra_child", lambda argv: True)
    # os.kill(pid, 0) still succeeds on an exited-but-unreaped zombie, and this
    # test is the process's real parent (unlike a real `echidra stop` reading
    # a pidfile written by an unrelated process) -- reap it concurrently so
    # _pid_is_alive() sees it disappear once SIGTERM lands.
    reaper = threading.Thread(target=proc.wait)
    reaper.start()

    exit_code = cli._cmd_stop(cli._build_parser().parse_args(["stop"]))
    reaper.join(timeout=5)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"Sent SIGTERM to PID {proc.pid}" in captured.out
    assert "Stopped." in captured.out
    assert not pid_path.exists()


def test_read_pid_file_rejects_zero_negative_and_out_of_range_values(monkeypatch, tmp_path):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    monkeypatch.setattr(cli, "_max_pid", lambda: 4194304)
    pid_path.write_text("0\n-1\n99999999999\n1234\n", encoding="utf-8")

    assert cli._read_pid_file() == [1234]


def test_stop_skips_a_stale_pid_that_no_longer_exists(monkeypatch, tmp_path, capsys):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    # A PID no live process will plausibly hold during the test run.
    pid_path.write_text("999999\n", encoding="utf-8")

    exit_code = cli._cmd_stop(cli._build_parser().parse_args(["stop"]))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert not pid_path.exists()
    assert "was not running" in captured.out
    assert "Stopped." not in captured.out


def test_stop_leaves_pidfile_when_permission_denied(monkeypatch, tmp_path, capsys):
    pid_path = tmp_path / "echidra.pid"
    monkeypatch.setattr(cli, "PID_PATH", pid_path)
    pid_path.write_text("4242\n", encoding="utf-8")
    # PID 4242 doesn't exist in the test environment, so the real ownership
    # check would fail closed before ever reaching os.kill -- bypass it
    # directly to exercise the PermissionError-from-os.kill path this test
    # is actually about.
    monkeypatch.setattr(cli, "_pid_is_echidra_process", lambda pid: True)

    def fake_kill(pid, sig):
        raise PermissionError()

    monkeypatch.setattr(cli.os, "kill", fake_kill)

    exit_code = cli._cmd_stop(cli._build_parser().parse_args(["stop"]))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "permission denied" in captured.out
    assert "Not fully stopped" in captured.out
    # Left in place so a retry (e.g. with sudo) can find the PID again.
    assert pid_path.exists()


# ---------------------------------------------------------------------------
# blocklist
# ---------------------------------------------------------------------------


def _attacker_row(ip, sessions=1, risk_rank=3, first=1_700_000_000.0, last=1_700_000_600.0):
    return {
        "peer_ip": ip,
        "session_count": sessions,
        "first_seen": first,
        "last_seen": last,
        "max_risk_rank": risk_rank,
    }


def _fake_blocklist_repository(monkeypatch, rows):
    calls = []

    class FakeRepository:
        def list_attacker_ips(self, **kwargs):
            calls.append(kwargs)
            return rows

    import classifier.storage as storage_module
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", FakeRepository)
    return calls


def test_blocklist_prints_one_public_ip_per_line_and_drops_private(monkeypatch, capsys):
    _fake_blocklist_repository(monkeypatch, [
        _attacker_row("45.155.205.7"),
        _attacker_row("10.0.0.5"),
        _attacker_row("127.0.0.1"),
        _attacker_row("2001:db8::1"),
        _attacker_row("not-an-ip"),
        _attacker_row("185.220.101.9"),
    ])

    exit_code = cli.main(["blocklist"])

    captured = capsys.readouterr()
    assert exit_code == 0
    # 2001:db8::/32 is documentation space, which ipaddress treats as private.
    assert captured.out.splitlines() == ["45.155.205.7", "185.220.101.9"]


def test_blocklist_include_private_keeps_internal_addresses(monkeypatch, capsys):
    _fake_blocklist_repository(monkeypatch, [_attacker_row("10.0.0.5"), _attacker_row("not-an-ip")])

    assert cli.main(["blocklist", "--include-private"]) == 0

    assert capsys.readouterr().out.splitlines() == ["10.0.0.5"]


def test_blocklist_exclude_drops_matching_ranges(monkeypatch, capsys):
    _fake_blocklist_repository(monkeypatch, [
        _attacker_row("45.155.205.7"),
        _attacker_row("45.155.205.200"),
        _attacker_row("185.220.101.9"),
    ])

    assert cli.main(["blocklist", "--exclude", "45.155.205.0/24", "--exclude", "2001:db8::/32"]) == 0

    assert capsys.readouterr().out.splitlines() == ["185.220.101.9"]


def test_blocklist_passes_window_and_thresholds_to_repository(monkeypatch):
    calls = _fake_blocklist_repository(monkeypatch, [])
    monkeypatch.setattr(cli.time, "time", lambda: 1_000_000.0)

    assert cli.main(["blocklist", "--since", "24h", "--min-risk", "high", "--min-sessions", "3"]) == 0

    assert calls == [{"since_ts": 1_000_000.0 - 86_400, "min_risk_rank": 3, "min_sessions": 3}]


def test_blocklist_defaults_to_seven_days_any_risk(monkeypatch):
    calls = _fake_blocklist_repository(monkeypatch, [])
    monkeypatch.setattr(cli.time, "time", lambda: 1_000_000.0)

    assert cli.main(["blocklist"]) == 0

    assert calls == [{"since_ts": 1_000_000.0 - 7 * 86_400, "min_risk_rank": 0, "min_sessions": 1}]


def test_blocklist_csv_includes_counts_times_and_risk(monkeypatch, capsys):
    _fake_blocklist_repository(monkeypatch, [
        _attacker_row("45.155.205.7", sessions=4, risk_rank=4, first=0.0, last=60.0),
        _attacker_row("185.220.101.9", sessions=1, risk_rank=0, first=0.0, last=0.0),
    ])

    assert cli.main(["blocklist", "--format", "csv"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "ip,sessions,first_seen_utc,last_seen_utc,max_risk",
        "45.155.205.7,4,1970-01-01T00:00:00Z,1970-01-01T00:01:00Z,critical",
        "185.220.101.9,1,1970-01-01T00:00:00Z,1970-01-01T00:00:00Z,unclassified",
    ]


def test_blocklist_writes_output_file(monkeypatch, tmp_path, capsys):
    _fake_blocklist_repository(monkeypatch, [_attacker_row("45.155.205.7")])
    output = tmp_path / "blocklist.txt"

    assert cli.main(["blocklist", "-o", str(output)]) == 0

    assert output.read_text() == "45.155.205.7\n"
    assert "Wrote 1 IPs" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["7", "0d", "1w", "abc", "1.5d"])
def test_blocklist_rejects_bad_since(value, capsys):
    with pytest.raises(SystemExit):
        cli.main(["blocklist", "--since", value])

    assert "invalid duration" in capsys.readouterr().err


def test_blocklist_rejects_bad_exclude(monkeypatch, capsys):
    calls = _fake_blocklist_repository(monkeypatch, [])

    assert cli.main(["blocklist", "--exclude", "not-a-cidr"]) == 2

    assert "invalid --exclude" in capsys.readouterr().err
    assert calls == []


def test_blocklist_rejects_zero_min_sessions(monkeypatch, capsys):
    calls = _fake_blocklist_repository(monkeypatch, [])

    assert cli.main(["blocklist", "--min-sessions", "0"]) == 2

    assert calls == []


def test_blocklist_reports_missing_database(monkeypatch, capsys):
    from classifier.storage import DatabaseNotConfiguredError

    class FakeRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    import classifier.storage as storage_module
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", FakeRepository)

    assert cli.main(["blocklist"]) == 1

    captured = capsys.readouterr()
    assert "no database configured" in captured.err
    assert captured.out == ""


# ---------------------------------------------------------------------------
# reset-password
# ---------------------------------------------------------------------------


def _fake_password_prompts(monkeypatch, *answers):
    import getpass

    replies = iter(answers)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(replies))


def _fake_reset_repository(monkeypatch, found=True):
    calls = []

    class FakeRepository:
        def reset_dashboard_user_password(self, email, password_hash):
            calls.append((email, password_hash))
            return found

    import classifier.storage as storage_module
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", FakeRepository)
    return calls


def test_reset_password_stores_a_verifiable_hash_for_the_normalized_email(monkeypatch, capsys):
    from classifier.passwords import verify_password

    _fake_password_prompts(monkeypatch, "NewPass123", "NewPass123")
    calls = _fake_reset_repository(monkeypatch)

    assert cli.main(["reset-password", "  Admin@Example.COM "]) == 0

    assert len(calls) == 1
    email, password_hash = calls[0]
    assert email == "admin@example.com"
    assert password_hash != "NewPass123"
    assert verify_password("NewPass123", password_hash)
    out = capsys.readouterr().out
    assert "Password updated for admin@example.com" in out
    assert "logged out" in out


def test_reset_password_rejects_a_weak_password_without_touching_the_database(monkeypatch, capsys):
    _fake_password_prompts(monkeypatch, "short")
    calls = _fake_reset_repository(monkeypatch)

    assert cli.main(["reset-password", "admin@example.com"]) == 2

    assert calls == []
    assert "at least 8 characters" in capsys.readouterr().err


def test_reset_password_rejects_mismatched_confirmation(monkeypatch, capsys):
    _fake_password_prompts(monkeypatch, "NewPass123", "NewPass124")
    calls = _fake_reset_repository(monkeypatch)

    assert cli.main(["reset-password", "admin@example.com"]) == 2

    assert calls == []
    assert "do not match" in capsys.readouterr().err


def test_reset_password_reports_an_unknown_email(monkeypatch, capsys):
    _fake_password_prompts(monkeypatch, "NewPass123", "NewPass123")
    _fake_reset_repository(monkeypatch, found=False)

    assert cli.main(["reset-password", "nobody@example.com"]) == 1

    assert "no dashboard user with email nobody@example.com" in capsys.readouterr().err


def test_reset_password_reports_missing_database(monkeypatch, capsys):
    from classifier.storage import DatabaseNotConfiguredError

    _fake_password_prompts(monkeypatch, "NewPass123", "NewPass123")

    class FakeRepository:
        def __init__(self):
            raise DatabaseNotConfiguredError("ECHIDRA_DATABASE_URL must be set")

    import classifier.storage as storage_module
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", FakeRepository)

    assert cli.main(["reset-password", "admin@example.com"]) == 1

    assert "no database configured" in capsys.readouterr().err
