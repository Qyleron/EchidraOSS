"""Operator-facing `echidra` command: init, serve, classify, status.

This is a thin wrapper around existing entry points (honeypot.main,
classifier.cli, classifier.storage.cli, uvicorn) -- it exists so a fresh
clone can be set up and run with one memorable command instead of needing
to know four separate module invocations up front.
"""

from __future__ import annotations

import argparse
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = REPO_ROOT / ".env"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"


def main(argv: list[str] | None = None) -> int:
    """Run one `echidra` subcommand and return a process exit code.

    Raises SystemExit for invalid command-line arguments through argparse.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return _cmd_init(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "classify":
        return _cmd_classify(args)
    if args.command == "status":
        return _cmd_status(args)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="echidra",
        description="Set up, run, classify, and health-check an Echidra deployment.",
    )
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser(
        "init",
        help="create .env, generate a missing ingest API key, and initialize the database schema",
    )
    init_parser.add_argument(
        "--seed-demo-issues",
        action="store_true",
        help="also insert demo Intelligence-page issues (only meaningful with a database configured)",
    )

    serve_parser = subparsers.add_parser(
        "serve",
        help="run the honeypot listeners and the API/dashboard together until Ctrl+C",
    )
    serve_parser.add_argument("--api-host", default="0.0.0.0", help="API/dashboard bind host (default: 0.0.0.0)")
    serve_parser.add_argument("--api-port", type=int, default=8000, help="API/dashboard bind port (default: 8000)")

    classify_parser = subparsers.add_parser(
        "classify",
        help="classify every session record in a JSONL log file",
    )
    classify_parser.add_argument("input_path", help="path to a JSONL file emitted by SessionLogger")
    classify_parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        default=None,
        help="optional path for JSONL classifier summaries; defaults to stdout",
    )

    status_parser = subparsers.add_parser(
        "status",
        help="check whether the honeypot listeners, API, and database are up, and how many sessions are captured",
    )
    status_parser.add_argument("--api-host", default="127.0.0.1", help="API host to check (default: 127.0.0.1)")
    status_parser.add_argument("--api-port", type=int, default=8000, help="API port to check (default: 8000)")

    return parser


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    _ensure_env_file()
    _ensure_env_var("ECHIDRA_INGEST_API_KEY", lambda: secrets.token_urlsafe(32))

    from dotenv import load_dotenv

    load_dotenv(ENV_PATH, override=True)

    database_url = os.getenv("ECHIDRA_DATABASE_URL", "").strip()
    if not database_url:
        print()
        print("ECHIDRA_DATABASE_URL is not set -- skipping database setup.")
        print("The honeypot will still run and log to JSONL; the dashboard/API and")
        print("live alerting need a database. Set ECHIDRA_DATABASE_URL in .env, then")
        print("re-run 'echidra init' to create the schema.")
        return 0

    print()
    print("ECHIDRA_DATABASE_URL is set -- initializing database schema...")
    from classifier.storage.cli import main as storage_cli_main

    storage_argv = ["init-db"]
    if args.seed_demo_issues:
        storage_argv.append("--seed-demo-issues")
    return storage_cli_main(storage_argv)


def _ensure_env_file() -> None:
    if ENV_PATH.exists():
        print(f"{ENV_PATH} already exists, leaving it as-is.")
        return
    if ENV_EXAMPLE_PATH.exists():
        ENV_PATH.write_text(ENV_EXAMPLE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Created {ENV_PATH} from {ENV_EXAMPLE_PATH.name}.")
    else:
        ENV_PATH.touch()
        print(f"Created empty {ENV_PATH} ({ENV_EXAMPLE_PATH.name} not found).")


def _ensure_env_var(key: str, value_factory) -> None:
    from dotenv import dotenv_values, set_key

    if not ENV_PATH.exists():
        ENV_PATH.touch()
    current = dotenv_values(ENV_PATH).get(key)
    if current:
        print(f"{key} is already set in {ENV_PATH.name}.")
        return
    value = value_factory()
    set_key(str(ENV_PATH), key, value, quote_mode="never")
    print(f"Generated {key} and wrote it to {ENV_PATH.name}.")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def _cmd_serve(args: argparse.Namespace) -> int:
    honeypot_proc = subprocess.Popen([sys.executable, "-m", "honeypot.main"])
    api_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "classifier.api.app:create_app",
            "--factory",
            "--host",
            args.api_host,
            "--port",
            str(args.api_port),
        ]
    )
    procs = [honeypot_proc, api_proc]
    print(f"Honeypot listeners: PID {honeypot_proc.pid}")
    print(f"API/dashboard:      PID {api_proc.pid} (http://{args.api_host}:{args.api_port})")
    print("Press Ctrl+C to stop both.")

    def _forward_signal(signum, _frame):
        for proc in procs:
            if proc.poll() is None:
                proc.send_signal(signum)

    signal.signal(signal.SIGINT, _forward_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _forward_signal)

    try:
        while all(proc.poll() is None for proc in procs):
            time.sleep(0.5)
    finally:
        # Either a child exited on its own or we were signaled -- stop both.
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    return max((proc.returncode or 0) for proc in procs)


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


def _cmd_classify(args: argparse.Namespace) -> int:
    from classifier.cli import main as classifier_cli_main

    argv = ["classify-jsonl", args.input_path]
    if args.output_path:
        argv += ["--output", args.output_path]
    return classifier_cli_main(argv)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _cmd_status(args: argparse.Namespace) -> int:
    print("Echidra status")
    print("=" * 40)

    _check_honeypot_listeners()
    _check_api(args.api_host, args.api_port)
    _check_database()
    return 0


def _check_honeypot_listeners() -> None:
    from honeypot.network.config import FTP_PORT, HOST, HTTP_PORT, PORT, TELNET_PORT

    check_host = "127.0.0.1" if HOST == "0.0.0.0" else HOST
    listeners = [
        ("SSH-style shell", PORT),
        ("HTTP", HTTP_PORT),
        ("FTP", FTP_PORT),
        ("Telnet", TELNET_PORT),
    ]
    for name, port in listeners:
        if not port:
            print(f"  {name:<16} disabled (port 0)")
            continue
        state = "listening" if _port_is_open(check_host, port) else "not reachable"
        print(f"  {name:<16} {state} ({check_host}:{port})")


def _port_is_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _check_api(host: str, port: int) -> None:
    url = f"http://{host}:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            ok = response.status == 200
        print(f"  API {url}: {'reachable' if ok else f'unexpected status {response.status}'}")
    except urllib.error.URLError as exc:
        print(f"  API {url}: unreachable ({exc.reason})")
    except OSError as exc:
        print(f"  API {url}: unreachable ({exc})")


def _check_database() -> None:
    from classifier.storage import (
        DatabaseDriverMissingError,
        DatabaseNotConfiguredError,
        PostgresClassifierRepository,
    )

    try:
        repository = PostgresClassifierRepository()
        summary = repository.get_dashboard_report_summary()
    except DatabaseNotConfiguredError:
        print("  Database: not configured (set ECHIDRA_DATABASE_URL in .env)")
        return
    except DatabaseDriverMissingError as exc:
        print(f"  Database: driver missing ({exc})")
        return
    except Exception as exc:
        print(f"  Database: configured but unreachable ({exc})")
        return

    print("  Database: connected")
    print(f"    Sessions classified: {summary.total_runs}")
    print(f"    Elevated-risk runs:  {summary.elevated_runs}")
    print(f"    Distinct personas:   {summary.distinct_personas}")


if __name__ == "__main__":
    raise SystemExit(main())
