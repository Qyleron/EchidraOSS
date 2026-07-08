import pytest

from echidra import cli


def test_echidra_cli_no_command_prints_help(capsys):
    exit_code = cli.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "usage: echidra" in captured.out


def test_echidra_cli_help_lists_all_four_subcommands(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])

    captured = capsys.readouterr()
    for subcommand in ("init", "serve", "classify", "status"):
        assert subcommand in captured.out


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
# serve
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


def test_cmd_serve_stops_both_processes_when_one_exits(monkeypatch):
    processes = [_FakeProcess(pid=100), _FakeProcess(pid=200)]
    popen_calls = []

    def fake_popen(cmd, **kwargs):
        popen_calls.append(cmd)
        return processes[len(popen_calls) - 1]

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: processes[0].__setattr__("returncode", 0))
    monkeypatch.setattr(cli.signal, "signal", lambda *args, **kwargs: None)

    args = cli._build_parser().parse_args(["serve", "--api-port", "8123"])
    exit_code = cli._cmd_serve(args)

    assert len(popen_calls) == 2
    assert "-m" in popen_calls[0] and "honeypot.main" in popen_calls[0]
    assert "uvicorn" in popen_calls[1]
    assert exit_code == 0
    # The still-running process must have been terminated once the other exited.
    assert processes[1]._terminated is True


def test_cmd_serve_returns_zero_for_signal_interrupts(monkeypatch):
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

    args = cli._build_parser().parse_args(["serve", "--api-port", "8123"])
    exit_code = cli._cmd_serve(args)

    assert exit_code == 0
