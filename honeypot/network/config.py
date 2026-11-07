import logging
import os
import threading
import time
from pathlib import PurePosixPath

from dotenv import load_dotenv

from honeypot.core.persona import (
    PRESET_PERSONAS,
    FakeFile,
    Persona,
    get_persona,
    validate_persona,
)

logger = logging.getLogger(__name__)


load_dotenv()

"""
Runtime configuration for the honeypot process.

For now, values are simple Python constants so the backend stays easy to run.
Later, organization-specific persona values can come from the HTML/UI and a
database, while the server and shell engine keep using get_active_persona().
"""


def _int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _positive_int_from_env(name: str, default: int) -> int:
    value = _int_from_env(name, default)
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _port_from_env(name: str, default: int) -> int:
    value = _int_from_env(name, default)
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


# Bind to all interfaces by default so the honeypot can accept remote traffic
HOST = os.getenv("ECHIDRA_HOST", "0.0.0.0")

# Non-privileged SSH port
PORT = _port_from_env("ECHIDRA_PORT", 2222)

# Where the persistent SSH host key lives -- generated on first run if missing
SSH_HOST_KEY_PATH = os.getenv("ECHIDRA_SSH_HOST_KEY_PATH", "data/ssh_host_key")

def _optional_port_from_env(name: str, default: int) -> int:
    value = _int_from_env(name, default)
    if value != 0 and not 1 <= value <= 65535:
        raise ValueError(f"{name} must be 0 or between 1 and 65535")
    return value

# Additional protocol listener ports (set to 0 to disable)
HTTP_PORT = _optional_port_from_env("ECHIDRA_HTTP_PORT", 8080)
FTP_PORT = _optional_port_from_env("ECHIDRA_FTP_PORT", 2121)
TELNET_PORT = _optional_port_from_env("ECHIDRA_TELNET_PORT", 2323)

# Maximum number of active client sessions
MAX_CONNECTIONS = _positive_int_from_env("ECHIDRA_MAX_CONNECTIONS", 100)

# Seconds to wait for a client command before closing the session
READ_TIMEOUT = _positive_int_from_env("ECHIDRA_READ_TIMEOUT", 60)

# Append-only structured records consumed by the classifier
SESSION_LOG_PATH = os.getenv("ECHIDRA_SESSION_LOG", "logs/sessions.jsonl")

DEFAULT_PERSONA_ID = "generic_linux"
# get_active_persona() is already called fresh per new connection (every
# protocol handler calls it when a session starts) -- this cache exists only
# to avoid a DB round-trip on every single connection, not because the
# persona is looked up once per process lifetime. A short TTL keeps that
# benefit under a connection burst (eg. a scanner hammering the honeypot)
# while still picking up a dashboard-saved persona_configs change within a
# few seconds, with no restart and no cross-process signaling needed -- the
# API process saving the change and the honeypot process serving connections
# are separate OS processes (see echidra/cli.py's `start`), so an infinite
# cache invalidated only by clear_active_persona_cache() (never actually
# called anywhere) meant the only way to pick up a change was a restart.
_PERSONA_CACHE_TTL_SECONDS = 5.0
_cached_persona: Persona | None = None
_cached_persona_id: str | None = None
_cached_persona_expires_at: float | None = None
# At most one background refresh at a time, however many connections arrive
# while the cache is stale.
_persona_refresh_lock = threading.Lock()
_persona_refresh_running = False


class _PersonaLookupFailed(Exception):
    """The persona_configs lookup itself failed (DB down, hung, erroring),
    as opposed to there being no database or no saved row."""


def get_active_persona() -> Persona:
    """
    Return the persona used for new honeypot sessions.

    Behavior:
    - Read ECHIDRA_PERSONA or use generic_linux.
    - Look up a saved persona_configs row for that ID first, so dashboard
      customizations actually reach the live honeypot.
    - Fall back to a hardcoded preset if no database is configured or no row
      matches — the honeypot must keep working with zero DB setup.
    - If the lookup itself fails (DB down or hung), keep the persona already
      in use, so an outage can't change the decoy's hostname or banners
      under an attacker; the preset is used only if none was loaded yet.
    - Validate the result before any session uses it.
    - Cached for _PERSONA_CACHE_TTL_SECONDS to bound DB load under a
      connection burst. Once the cache is stale, the cached persona is still
      returned at once and the reload runs in a background thread: protocol
      handlers call this on the honeypot's event loop, and a hung DB would
      otherwise stall every decoy for up to the DB connect timeout. Only the
      first load (honeypot/main.py does it before the listeners start) or a
      changed ECHIDRA_PERSONA loads in the caller. Call
      clear_active_persona_cache() to force an immediate reload.
    """
    persona_id = os.getenv("ECHIDRA_PERSONA", DEFAULT_PERSONA_ID)
    cached = _cached_persona
    if cached is not None and _cached_persona_id == persona_id:
        expires_at = _cached_persona_expires_at
        if expires_at is not None and time.monotonic() >= expires_at:
            _start_persona_refresh(persona_id)
        return cached
    return _refresh_active_persona(persona_id)


def _refresh_active_persona(persona_id: str) -> Persona:
    """Load the persona for persona_id and store it in the cache."""
    global _cached_persona, _cached_persona_id, _cached_persona_expires_at

    try:
        persona = _load_persona_from_db(persona_id)
    except _PersonaLookupFailed:
        persona = _cached_persona if _cached_persona_id == persona_id else None
    if persona is None:
        persona = get_persona(persona_id)
        validate_persona(persona)
    _cached_persona = persona
    _cached_persona_id = persona_id
    # Stamped from *after* the load (DB round trip or preset validation)
    # completes, not before it started -- otherwise the cache's effective
    # lifetime is silently shortened by however long that load took, under
    # connection bursts when it matters most.
    _cached_persona_expires_at = time.monotonic() + _PERSONA_CACHE_TTL_SECONDS
    return persona


def _start_persona_refresh(persona_id: str) -> None:
    """Reload the persona in a background thread, unless one already is."""
    global _persona_refresh_running

    with _persona_refresh_lock:
        if _persona_refresh_running:
            return
        _persona_refresh_running = True

    def run() -> None:
        global _persona_refresh_running
        try:
            _refresh_active_persona(persona_id)
        except Exception:
            logger.exception("Background persona refresh failed for %r", persona_id)
        finally:
            with _persona_refresh_lock:
                _persona_refresh_running = False

    threading.Thread(target=run, name="echidra-persona-refresh", daemon=True).start()


def clear_active_persona_cache() -> None:
    """Force get_active_persona() to reload and revalidate config next time."""
    global _cached_persona, _cached_persona_id, _cached_persona_expires_at
    _cached_persona = None
    _cached_persona_id = None
    _cached_persona_expires_at = None


# Login identity for a saved persona that isn't a preset (a preset's id keeps
# the preset's own; see _persona_from_config_record). Everything an operator
# sets in the Personas dashboard tab takes effect on the live honeypot.
_DB_PERSONA_USERNAME = "root"
_DB_PERSONA_HOME_DIR = "/home/admin"


def _load_persona_from_db(persona_id: str) -> Persona | None:
    """Build a live Persona from a saved persona_configs row, if one exists.

    Returns None — meaning "use the hardcoded preset instead" — when no
    database is configured, no row matches this ID, or the row fails
    validation. Raises _PersonaLookupFailed when the lookup itself fails
    (driver missing, DB down or erroring), so the caller can keep the
    persona it already has.
    """
    try:
        from classifier.storage import (
            DatabaseNotConfiguredError,
            PostgresClassifierRepository,
        )

        try:
            repository = PostgresClassifierRepository()
        except DatabaseNotConfiguredError:
            return None  # No ECHIDRA_DATABASE_URL — the common, expected case.
        record = repository.get_persona_config(persona_id)
    except Exception as exc:
        logger.warning(
            "Could not look up persona_configs row for %r; keeping the current persona",
            persona_id,
            exc_info=True,
        )
        raise _PersonaLookupFailed(persona_id) from exc

    if record is None:
        return None

    try:
        persona = _persona_from_config_record(record)
        validate_persona(persona)
    except Exception:
        logger.warning(
            "persona_configs row for %r failed validation; using preset instead",
            persona_id,
            exc_info=True,
        )
        return None
    return persona


_STARTER_BASHRC = (
    "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
    "case $- in\n    *i*) ;;\n      *) return;;\nesac\n"
    "HISTCONTROL=ignoreboth\nHISTSIZE=1000\nHISTFILESIZE=2000\n"
    "alias ll='ls -alF'\nalias la='ls -A'\n"
)
_STARTER_PROFILE = (
    "# ~/.profile: executed by the command interpreter for login shells.\n"
    'if [ -n "$BASH_VERSION" ]; then\n'
    '    if [ -f "$HOME/.bashrc" ]; then\n        . "$HOME/.bashrc"\n    fi\nfi\n'
)


def _starter_files(hostname: str, home_dir: str, users) -> tuple[FakeFile, ...]:
    """A lived-in minimum for a persona that isn't a preset: with no files at
    all, the home directory and /etc look empty, which gives a decoy away."""
    home_user = PurePosixPath(home_dir).name
    others = [user for user in dict.fromkeys([*users, home_user]) if user and user != "root"]
    passwd = "root:x:0:0:root:/root:/bin/bash\n" + "".join(
        f"{user}:x:{1000 + i}:{1000 + i}:{user}:/home/{user}:/bin/bash\n"
        for i, user in enumerate(others)
    )
    return (
        FakeFile(path=f"{home_dir}/.bashrc", content=_STARTER_BASHRC),
        FakeFile(path=f"{home_dir}/.profile", content=_STARTER_PROFILE),
        FakeFile(path=f"{home_dir}/.bash_history", content=""),
        FakeFile(path="/etc/hostname", content=f"{hostname}\n"),
        FakeFile(path="/etc/hosts", content=f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n"),
        FakeFile(path="/etc/passwd", content=passwd),
    )


def _persona_from_config_record(record) -> Persona:
    """Bridge one dashboard-saved PersonaConfigRecord into a live Persona.

    A saved persona with a preset's id starts from that preset's files,
    login identity, SUID binaries, ports and decoy credentials, which the
    dashboard doesn't edit; any other persona starts from a small set of
    starter files. Saved decoy files are added on top, and replace a starting
    file with the same path."""
    hostname = record.hostname or record.id
    preset = PRESET_PERSONAS.get(record.id)
    username = preset.username if preset else _DB_PERSONA_USERNAME
    home_dir = preset.home_dir if preset else _DB_PERSONA_HOME_DIR
    starting_files = (
        preset.fake_filesystem if preset
        else _starter_files(hostname, home_dir, record.fake_users)
    )
    files = {fake_file.path: fake_file for fake_file in starting_files}
    decoy_paths = set()
    for decoy in record.decoy_files:
        # A decoy may replace a starting file, but two decoys with one path
        # is a broken row: fail, so the caller falls back to the preset.
        if decoy.path in decoy_paths:
            raise ValueError(f"Duplicate decoy file path: {decoy.path}")
        decoy_paths.add(decoy.path)
        files[decoy.path] = FakeFile(path=decoy.path, content=decoy.content)

    return Persona(
        persona_id=record.id,
        os_banner=record.os_banner or f"Linux {hostname} 5.15.0-91-generic x86_64",
        ssh_banner=record.ssh_banner or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        hostname=hostname,
        uname_output=(
            f"Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        ),
        username=username,
        home_dir=home_dir,
        fake_filesystem=tuple(files.values()),
        running_processes=tuple(record.running_processes),
        http_server_type=record.http_server_type,
        fake_users=tuple(record.fake_users),
        suid_binaries=preset.suid_binaries if preset else (),
        # The four listeners are controlled once, globally, by ECHIDRA_*_PORT
        # env vars, so a saved persona has no ports of its own to show.
        open_ports_visible=preset.open_ports_visible if preset else (),
        fake_credentials=preset.fake_credentials if preset else (),
    )
