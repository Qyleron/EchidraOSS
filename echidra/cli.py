"""Operator-facing `echidra` command: init, start, stop, classify, status.

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
# logs/ is already a writable runtime dir in every deployment path (systemd's
# ReadWritePaths, Compose's echidra_logs volume, and locally) -- reusing it
# avoids needing a new directory just for this.
PID_PATH = REPO_ROOT / "logs" / "echidra.pid"


def main(argv: list[str] | None = None) -> int:
    """Run one `echidra` subcommand and return a process exit code.

    Raises SystemExit for invalid command-line arguments through argparse.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return _cmd_init(args)
    if args.command == "start":
        return _cmd_start(args)
    if args.command == "classify":
        return _cmd_classify(args)
    if args.command == "status":
        return _cmd_status(args)
    if args.command == "stop":
        return _cmd_stop(args)
    if args.command == "help":
        parser.print_help()
        return 0

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

    start_parser = subparsers.add_parser(
        "start",
        help="run the honeypot listeners and the API/dashboard together until Ctrl+C",
    )
    start_parser.add_argument("--api-host", default="0.0.0.0", help="API/dashboard bind host (default: 0.0.0.0)")
    start_parser.add_argument("--api-port", type=int, default=8000, help="API/dashboard bind port (default: 8000)")

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
    classify_parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="skip lines that fail to parse or validate instead of aborting the whole run",
    )

    status_parser = subparsers.add_parser(
        "status",
        help="check whether the honeypot listeners, API, and database are up, and how many sessions are captured",
    )
    status_parser.add_argument("--api-host", default="127.0.0.1", help="API host to check (default: 127.0.0.1)")
    status_parser.add_argument("--api-port", type=int, default=8000, help="API port to check (default: 8000)")

    subparsers.add_parser(
        "stop",
        help="stop a running 'echidra start' from another terminal (reads PIDs from logs/echidra.pid)",
    )

    subparsers.add_parser(
        "help",
        help="show this help message (same as --help)",
    )

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
# start
# ---------------------------------------------------------------------------


def _cmd_start(args: argparse.Namespace) -> int:
    existing_pids = [pid for pid in _read_pid_file() if _pid_is_echidra_process(pid)]
    if existing_pids:
        print(f"A previous 'echidra start' still appears to be running (PID {', '.join(map(str, existing_pids))}).")
        print("Run 'echidra stop' first (or 'sudo echidra stop' if that reports permission denied), "
              "then try again.")
        return 1
    PID_PATH.unlink(missing_ok=True)  # clears a stale pidfile left by a process that's already gone

    procs: list[subprocess.Popen] = []
    try:
        honeypot_proc = subprocess.Popen([sys.executable, "-m", "honeypot.main"])
        procs.append(honeypot_proc)
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
                # Per-request access logs (every dashboard page/asset/css GET)
                # are noise for an operator watching this terminal; attacker
                # activity is what matters, and that's logged separately by
                # the honeypot listeners.
                "--no-access-log",
                # The app registers no startup/shutdown handlers, so the ASGI
                # lifespan handshake is dead weight -- and on this
                # uvicorn/starlette pairing, cancelling it mid-shutdown is
                # what prints the benign-but-noisy "CancelledError ... in
                # lifespan / await receive()" traceback on Ctrl+C. Disabling
                # it removes that code path entirely instead of just making
                # it less likely to trigger.
                "--lifespan",
                "off",
            ]
        )
        procs.append(api_proc)
    except OSError:
        for proc in procs:
            proc.terminate()
        raise
    _write_pid_file(proc.pid for proc in procs)
    print(f"Honeypot listeners: PID {honeypot_proc.pid}")
    print(f"API/dashboard:      PID {api_proc.pid} (http://{args.api_host}:{args.api_port})")
    print("Press Ctrl+C to stop both, or run 'echidra stop' from another terminal.")

    # Ctrl+C sends SIGINT to this whole foreground process group, so both
    # children already receive it directly -- explicitly forwarding SIGINT
    # here too would be a second delivery, which makes uvicorn abort its
    # lifespan mid-shutdown instead of exiting cleanly (a benign but noisy
    # CancelledError traceback). Only SIGTERM needs forwarding, since a
    # `kill <pid>` targeting just this process wouldn't otherwise reach them.
    shutdown_requested = False

    def _forward_signal(signum, _frame):
        nonlocal shutdown_requested
        shutdown_requested = True
        for proc in procs:
            if proc.poll() is None:
                proc.send_signal(signum)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _forward_signal)

    try:
        while not shutdown_requested and all(proc.poll() is None for proc in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping...")
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
        PID_PATH.unlink(missing_ok=True)

    # A negative returncode means the child was killed by a signal (eg. our
    # own SIGINT/SIGTERM forwarding, or the terminate() above) -- that's a
    # clean shutdown, not a failure, so only positive exit codes propagate.
    return max(max(proc.returncode or 0, 0) for proc in procs)


def _write_pid_file(pids) -> None:
    PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    PID_PATH.write_text("\n".join(str(pid) for pid in pids) + "\n", encoding="utf-8")


def _max_pid() -> int:
    # /proc/sys/kernel/pid_max is Linux's own record of this limit; a
    # non-Linux platform (no such file) falls back to the historical Linux
    # default ceiling rather than trusting an unbounded value.
    try:
        with open("/proc/sys/kernel/pid_max", encoding="ascii") as f:
            return int(f.read().strip())
    except OSError:
        return 2**22


def _read_pid_file() -> list[int]:
    if not PID_PATH.exists():
        return []
    max_pid = _max_pid()
    pids = []
    for line in PID_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
        except ValueError:
            continue
        # os.kill() treats pid <= 0 specially (0 = your whole process group,
        # -1 = every process you can signal) -- reject those, and anything
        # above the platform's own PID ceiling, before they ever reach
        # _pid_is_alive/_cmd_stop/_check_start_process.
        if 0 < pid <= max_pid:
            pids.append(pid)
    return pids


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------


def _cmd_stop(args: argparse.Namespace) -> int:
    pids = _read_pid_file()
    if not pids:
        print(f"No PID file at {PID_PATH} -- 'echidra start' doesn't appear to be running.")
        return 0

    signaled = []
    permission_denied = []
    for pid in pids:
        if not _pid_is_echidra_process(pid):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            permission_denied.append(pid)
            continue
        print(f"Sent SIGTERM to PID {pid}.")
        signaled.append(pid)

    deadline = time.monotonic() + 10
    while signaled and time.monotonic() < deadline:
        time.sleep(0.2)
        signaled = [pid for pid in signaled if _pid_is_alive(pid)]

    for pid in signaled:
        print(f"PID {pid} didn't exit within 10s -- sending SIGKILL.")
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.5)
    signaled = [pid for pid in signaled if _pid_is_alive(pid)]

    if permission_denied or signaled:
        for pid in permission_denied:
            print(f"PID {pid}: permission denied sending SIGTERM -- it was likely started "
                  f"as a different user (e.g. via sudo). Try 'sudo echidra stop'.")
        for pid in signaled:
            print(f"PID {pid}: still running after SIGKILL.")
        print("Not fully stopped -- pidfile left in place so a retry can find these PIDs.")
        return 1

    PID_PATH.unlink(missing_ok=True)
    print("Stopped.")
    return 0


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _pid_is_echidra_process(pid: int) -> bool:
    """Return True only if pid is both alive and actually one of ours.

    os.kill(pid, 0) alone can't distinguish a live process from one whose
    PID the OS recycled for an unrelated program after ours already exited
    -- which would otherwise let `echidra stop` send SIGTERM to a stranger
    process, or `echidra start` refuse to start over a merely coincidental
    PID match. /proc/<pid>/cmdline is Linux-only and unreadable for another
    user's process; either case falls back to liveness alone rather than
    refusing to ever recognize our own process.
    """
    if not _pid_is_alive(pid):
        return False
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", "replace")
    except OSError:
        return True
    return "honeypot.main" in cmdline or "classifier.api.app" in cmdline


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------


def _cmd_classify(args: argparse.Namespace) -> int:
    from classifier.cli import main as classifier_cli_main

    argv = ["classify-jsonl", args.input_path]
    if args.output_path:
        argv += ["--output", args.output_path]
    if args.skip_invalid:
        argv.append("--skip-invalid")
    return classifier_cli_main(argv)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _cmd_status(args: argparse.Namespace) -> int:
    print("Echidra status")
    print("=" * 40)

    _check_start_process()
    _check_honeypot_listeners()
    _check_api(args.api_host, args.api_port)
    _check_database()
    return 0


def _check_start_process() -> None:
    pids = [pid for pid in _read_pid_file() if _pid_is_alive(pid)]
    if pids:
        print(f"  echidra start    running (PID {', '.join(map(str, pids))})")
    else:
        print("  echidra start    not running (no active pidfile at "
              f"{PID_PATH}) -- listeners below may still belong to a "
              "process started outside 'echidra start'")


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
        print(f"  Database: configured but unreachable ({type(exc).__name__})")
        return

    print("  Database: connected")
    print(f"    Sessions classified: {summary.total_runs}")
    print(f"    Elevated-risk runs:  {summary.elevated_runs}")
    print(f"    Distinct personas:   {summary.distinct_personas}")


if __name__ == "__main__":
    raise SystemExit(main())
