"""Operator-facing `echidra` command: init, start, stop, classify, status, blocklist, reset-password.

This is a thin wrapper around existing entry points (honeypot.main,
classifier.cli, classifier.storage.cli, uvicorn) -- it exists so a fresh
clone can be set up and run with one memorable command instead of needing
to know four separate module invocations up front.
"""

from __future__ import annotations

import argparse
import csv
import errno
import ipaddress
import os
import re
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
# Checked once at import time so a per-pid /proc/<pid>/cmdline read failure
# can be trusted to mean "not our process" rather than "no /proc support here
# at all" (eg. non-Linux) -- see _pid_is_echidra_process().
_PROC_FS_AVAILABLE = os.path.isdir("/proc")


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
    if args.command == "blocklist":
        return _cmd_blocklist(args)
    if args.command == "reset-password":
        return _cmd_reset_password(args)
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
    start_parser.add_argument(
        "--api-host",
        default="127.0.0.1",
        help="API/dashboard bind host (default: 127.0.0.1 -- the dashboard is for you, not the internet; "
        "reach it remotely over an SSH tunnel)",
    )
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

    blocklist_parser = subparsers.add_parser(
        "blocklist",
        help="export captured attacker IPs for a firewall, fail2ban or Cloudflare (needs the database)",
    )
    blocklist_parser.add_argument(
        "--since",
        default="7d",
        type=_parse_duration,
        help="only IPs seen within this window, eg. 24h, 7d, 30d (default: 7d)",
    )
    blocklist_parser.add_argument(
        "--min-risk",
        choices=_RISK_RANKS,
        default=None,
        help="only IPs with at least one session at this risk level or above (default: any session)",
    )
    blocklist_parser.add_argument(
        "--min-sessions",
        type=int,
        default=1,
        help="only IPs with at least this many sessions in the window (default: 1)",
    )
    blocklist_parser.add_argument(
        "--format",
        choices=("plain", "csv"),
        default="plain",
        help="plain: one IP per line; csv: ip, sessions, first/last seen, max risk (default: plain)",
    )
    blocklist_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="CIDR",
        help="never list addresses in this IP or CIDR range, eg. your own scanner; repeatable",
    )
    blocklist_parser.add_argument(
        "--include-private",
        action="store_true",
        help="also list private, loopback and link-local addresses (left out by default so an "
        "internal decoy can't push your own network into a firewall blocklist)",
    )
    blocklist_parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        default=None,
        help="write to this file instead of stdout",
    )

    reset_parser = subparsers.add_parser(
        "reset-password",
        help="set a new password for a dashboard user (prompts for it), logging out their existing sessions",
    )
    reset_parser.add_argument("email", help="the dashboard user's email address")

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

    busy = _ports_in_use(args.api_host, args.api_port)
    if busy:
        for name, port in busy:
            print(f"Port {port} ({name}) is already in use.")
        units = _active_systemd_units()
        if units:
            print(f"Echidra is already running as a systemd service ({', '.join(units)}). "
                  f"Stop it with: sudo systemctl disable --now {' '.join(units)}")
            return 1
        print("Something else is already listening there -- usually the Docker Compose stack "
              "(check 'docker compose ps', stop it with 'docker compose down') or an Echidra "
              "started some other way. To see what holds a port: "
              f"ss -ltnp | grep ':{busy[0][1]} '")
        return 1

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
    _print_start_summary(args.api_host, args.api_port, honeypot_proc.pid, api_proc.pid)

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


def _print_start_summary(api_host: str, api_port: int, honeypot_pid: int, api_pid: int) -> None:
    """One short block telling the operator what's exposed and where to look."""
    from honeypot.network.config import FTP_PORT, HOST, HTTP_PORT, PORT, TELNET_PORT

    decoys = [
        f"{name} {port}"
        for name, port in (("SSH", PORT), ("HTTP", HTTP_PORT), ("FTP", FTP_PORT), ("Telnet", TELNET_PORT))
        if port
    ]
    print("Echidra is running.")
    print(f"  Decoys:     {', '.join(decoys) or 'none enabled'} (listening on {HOST})")
    print(f"  Dashboard:  http://{api_host}:{api_port}")
    if api_host in ("127.0.0.1", "localhost", "::1"):
        print(f"              on a remote server, open it through an SSH tunnel: "
              f"ssh -L {api_port}:127.0.0.1:{api_port} <user>@<server>")
    print(f"  PIDs:       decoys {honeypot_pid}, dashboard {api_pid}")
    print("  Stop:       Ctrl+C here, or 'echidra stop' from another terminal")


def _ports_in_use(api_host: str, api_port: int) -> list[tuple[str, int]]:
    """Return the (name, port) pairs 'echidra start' would fail to bind.

    Checked up front so a port conflict is one clear message, not a
    traceback per listener after the processes have already started. Only
    "address already in use" counts -- any other bind error (eg. a port
    below 1024 without privileges) is left for the real listener to report.
    """
    from honeypot.network.config import FTP_PORT, HOST, HTTP_PORT, PORT, TELNET_PORT

    wanted = [
        ("SSH-style shell", HOST, PORT),
        ("HTTP", HOST, HTTP_PORT),
        ("FTP", HOST, FTP_PORT),
        ("Telnet", HOST, TELNET_PORT),
        ("API/dashboard", api_host, api_port),
    ]
    busy = []
    for name, host, port in wanted:
        if not port:
            continue
        try:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                # Same as the real listeners (asyncio sets SO_REUSEADDR), so
                # a port only in TIME_WAIT isn't reported as taken.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                busy.append((name, port))
    return busy


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
        _print_systemd_hint()
        return 0

    signaled = []
    permission_denied = []
    found_running = False
    for pid in pids:
        if not _pid_is_echidra_process(pid):
            continue
        found_running = True
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError:
            permission_denied.append(pid)
            continue
        print(f"Sent SIGTERM to PID {pid}.")
        signaled.append(pid)

    # Re-verify ownership, not just liveness, at every step here -- up to 10s
    # (plus the SIGKILL settle time below) is long enough for the OS to have
    # recycled a PID that already exited for an unrelated process, and a
    # liveness-only check would then escalate to SIGKILL against a stranger.
    deadline = time.monotonic() + 10
    while signaled and time.monotonic() < deadline:
        time.sleep(0.2)
        signaled = [pid for pid in signaled if _pid_is_echidra_process(pid)]

    for pid in signaled:
        print(f"PID {pid} didn't exit within 10s -- sending SIGKILL.")
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.5)
    signaled = [pid for pid in signaled if _pid_is_echidra_process(pid)]

    if permission_denied or signaled:
        for pid in permission_denied:
            print(f"PID {pid}: permission denied sending SIGTERM -- it was likely started "
                  f"as a different user (e.g. via sudo). Try 'sudo echidra stop'.")
        for pid in signaled:
            print(f"PID {pid}: still running after SIGKILL.")
        print("Not fully stopped -- pidfile left in place so a retry can find these PIDs.")
        return 1

    PID_PATH.unlink(missing_ok=True)
    if not found_running:
        print(f"Echidra was not running -- removed stale PID file {PID_PATH}.")
        _print_systemd_hint()
        return 0
    print("Stopped.")
    return 0


SYSTEMD_UNITS = ("echidra-api", "echidra-honeypot")


def _active_systemd_units() -> list[str]:
    """Return the deploy/systemd units that are currently active, if any.

    'echidra stop' only knows about processes 'echidra start' launched (its
    PID file); a systemd install holds the same ports but is managed by
    systemctl, so both commands name it instead of failing confusingly.
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", *SYSTEMD_UNITS],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    states = result.stdout.split()
    return [unit for unit, state in zip(SYSTEMD_UNITS, states) if state == "active"]


def _print_systemd_hint() -> None:
    units = _active_systemd_units()
    if units:
        print(f"Echidra is running as a systemd service ({', '.join(units)}) -- "
              f"'echidra stop' doesn't manage that. Stop it with: "
              f"sudo systemctl stop {' '.join(units)}  (add 'disable --now' instead of 'stop' "
              "to keep it off after reboot)")


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
    PID match.

    /proc/<pid>/cmdline is only unreadable here for reasons that both mean
    "not ours": the process already exited (races os.kill(pid, 0) above --
    ProcessLookupError), or it's owned by a different user (our own child
    always runs as us, so we can always read its cmdline). The one case
    that isn't "not ours" is /proc not existing at all (non-Linux) -- that's
    checked once, separately, so a real echidra process isn't misreported
    as foreign just because this host has no /proc.
    """
    if not _pid_is_alive(pid):
        return False
    if not _PROC_FS_AVAILABLE:
        # No way to verify ownership at all here -- this is pure liveness,
        # the same weak guarantee `echidra start`/`stop` had before this
        # check existed. Surfaced once so it isn't mistaken for a real
        # verification on a non-Linux host.
        _warn_proc_fs_unavailable_once()
        return True
    try:
        raw_cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    # /proc/<pid>/cmdline is the process's argv, NUL-separated (with a
    # trailing NUL) -- split it back into real arguments instead of
    # substring-matching the raw bytes, so an unrelated process that merely
    # mentions "honeypot.main" somewhere in one of its own arguments (a file
    # path, a log message passed as an arg, etc.) isn't misidentified as ours.
    argv = raw_cmdline.decode("utf-8", "replace").split("\x00")
    argv = [a for a in argv if a]
    return _argv_matches_echidra_child(argv)


def _argv_matches_echidra_child(argv: list[str]) -> bool:
    """True if argv is shaped like one of the two processes `echidra start`
    launches (see _cmd_start): `<python> -m honeypot.main` or
    `<python> -m uvicorn classifier.api.app:create_app ...`.

    Anchored at argv[1:] (right after the interpreter at argv[0]), not a scan
    over the whole argv -- `-m`/module name only mean "this is a module
    invocation" to the interpreter when they're its own leading flags. A
    process could otherwise pass "-m", "honeypot.main" as plain data further
    down its own unrelated argv (a script's own positional arguments, for
    instance) and be misidentified as ours by a looser scan-anywhere match.
    """
    if len(argv) >= 3 and argv[1] == "-m" and argv[2] == "honeypot.main":
        return True
    if (
        len(argv) >= 4
        and argv[1] == "-m"
        and argv[2] == "uvicorn"
        and "classifier.api.app:create_app" in argv[3:]
    ):
        return True
    return False


_warned_proc_fs_unavailable = False


def _warn_proc_fs_unavailable_once() -> None:
    global _warned_proc_fs_unavailable
    if _warned_proc_fs_unavailable:
        return
    _warned_proc_fs_unavailable = True
    print(
        "Warning: no /proc filesystem on this host -- 'echidra start'/'stop'/'status' "
        "can only check whether a PID is alive, not whether it's actually an Echidra "
        "process. A reused PID could be mistaken for one.",
        file=sys.stderr,
    )


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
    pids = [pid for pid in _read_pid_file() if _pid_is_echidra_process(pid)]
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


# ---------------------------------------------------------------------------
# blocklist
# ---------------------------------------------------------------------------

# Same 0-4 scale as the stored-run risk aggregates in classifier.storage.
_RISK_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RISK_NAMES = {rank: name for name, rank in _RISK_RANKS.items()}
_DURATION_UNITS = {"m": 60, "h": 3_600, "d": 86_400}


def _parse_duration(value: str) -> int:
    match = re.fullmatch(r"(\d+)([mhd])", value.strip().lower())
    if not match or int(match.group(1)) == 0:
        raise argparse.ArgumentTypeError(
            f"invalid duration {value!r}: use a number followed by m, h or d, eg. 24h or 7d"
        )
    return int(match.group(1)) * _DURATION_UNITS[match.group(2)]


def _cmd_blocklist(args: argparse.Namespace) -> int:
    from classifier.blocklist import is_blocklistable
    from classifier.storage import (
        DatabaseDriverMissingError,
        DatabaseNotConfiguredError,
        PostgresClassifierRepository,
    )

    if args.min_sessions < 1:
        print("echidra blocklist: --min-sessions must be at least 1", file=sys.stderr)
        return 2
    try:
        excluded = [ipaddress.ip_network(cidr, strict=False) for cidr in args.exclude]
    except ValueError as exc:
        print(f"echidra blocklist: invalid --exclude: {exc}", file=sys.stderr)
        return 2

    try:
        repository = PostgresClassifierRepository()
        rows = repository.list_attacker_ips(
            since_ts=time.time() - args.since,
            min_risk_rank=_RISK_RANKS.get(args.min_risk, 0),
            min_sessions=args.min_sessions,
        )
    except DatabaseNotConfiguredError:
        print("echidra blocklist: no database configured (set ECHIDRA_DATABASE_URL in .env)", file=sys.stderr)
        return 1
    except DatabaseDriverMissingError as exc:
        print(f"echidra blocklist: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"echidra blocklist: database unreachable ({type(exc).__name__})", file=sys.stderr)
        return 1

    rows = [
        row for row in rows
        if is_blocklistable(row["peer_ip"], excluded, include_private=args.include_private)
    ]

    if args.output_path:
        with open(args.output_path, "w", newline="", encoding="utf-8") as handle:
            _write_blocklist(rows, args.format, handle)
        print(f"Wrote {len(rows)} IPs to {args.output_path}", file=sys.stderr)
    else:
        _write_blocklist(rows, args.format, sys.stdout)
    return 0


def _write_blocklist(rows: list[dict], fmt: str, handle) -> None:
    if fmt == "plain":
        for row in rows:
            handle.write(f"{row['peer_ip']}\n")
        return

    writer = csv.writer(handle)
    writer.writerow(["ip", "sessions", "first_seen_utc", "last_seen_utc", "max_risk"])
    for row in rows:
        writer.writerow([
            row["peer_ip"],
            int(row["session_count"]),
            _utc_iso(row["first_seen"]),
            _utc_iso(row["last_seen"]),
            _RISK_NAMES.get(int(row["max_risk_rank"]), "unclassified"),
        ])


def _utc_iso(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(timestamp)))


# ---------------------------------------------------------------------------
# reset-password
# ---------------------------------------------------------------------------


def _cmd_reset_password(args: argparse.Namespace) -> int:
    import getpass

    from classifier.passwords import hash_password, validate_password_format
    from classifier.storage import (
        DatabaseDriverMissingError,
        DatabaseNotConfiguredError,
        PostgresClassifierRepository,
    )

    email = args.email.strip().lower()  # stored normalized, same as signup
    try:
        password = getpass.getpass("New password: ")
        try:
            validate_password_format(password)
        except ValueError as exc:
            print(f"echidra reset-password: {exc}", file=sys.stderr)
            return 2
        if getpass.getpass("Confirm new password: ") != password:
            print("echidra reset-password: passwords do not match.", file=sys.stderr)
            return 2
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1

    try:
        repository = PostgresClassifierRepository()
        found = repository.reset_dashboard_user_password(email, hash_password(password))
    except DatabaseNotConfiguredError:
        print("echidra reset-password: no database configured (set ECHIDRA_DATABASE_URL in .env)", file=sys.stderr)
        return 1
    except DatabaseDriverMissingError as exc:
        print(f"echidra reset-password: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"echidra reset-password: database unreachable ({type(exc).__name__})", file=sys.stderr)
        return 1

    if not found:
        print(f"echidra reset-password: no dashboard user with email {email}.", file=sys.stderr)
        return 1
    print(f"Password updated for {email}. Existing dashboard sessions were logged out "
          "and any login lockout was cleared.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
