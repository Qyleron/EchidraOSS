import logging
import os
from pathlib import PurePosixPath

from dotenv import load_dotenv

from honeypot.core.persona import FakeFile, Persona, get_persona, validate_persona

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

# Non-privileged SSH-like test port
PORT = _port_from_env("ECHIDRA_PORT", 2222)

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

# Append-only structured records consumed by the future classifier
SESSION_LOG_PATH = os.getenv("ECHIDRA_SESSION_LOG", "logs/sessions.jsonl")

DEFAULT_PERSONA_ID = "generic_linux"
_cached_persona: Persona | None = None
_cached_persona_id: str | None = None


def get_active_persona() -> Persona:
    """
    Return the persona used for new honeypot sessions.

    Behavior:
    - Read ECHIDRA_PERSONA or use generic_linux.
    - Look up a saved persona_configs row for that ID first, so dashboard
      customizations actually reach the live honeypot.
    - Fall back to a hardcoded preset if no database is configured, no row
      matches, or the lookup fails for any reason — the honeypot must keep
      working with zero DB setup.
    - Validate the result before any session uses it.

    Call clear_active_persona_cache() after changing persona config at runtime.
    """
    global _cached_persona, _cached_persona_id

    persona_id = os.getenv("ECHIDRA_PERSONA", DEFAULT_PERSONA_ID)
    if _cached_persona is None or _cached_persona_id != persona_id:
        persona = _load_persona_from_db(persona_id) or get_persona(persona_id)
        validate_persona(persona)
        _cached_persona = persona
        _cached_persona_id = persona_id

    return _cached_persona


def clear_active_persona_cache() -> None:
    """Force get_active_persona() to reload and revalidate config next time."""
    global _cached_persona, _cached_persona_id
    _cached_persona = None
    _cached_persona_id = None


# Fields a saved persona_configs row doesn't capture yet (real login identity,
# SUID binaries, decoy credentials) — these stay fixed until the config
# schema grows to cover them; everything else an operator sets in the
# Personas dashboard tab (banners, hostname, timezone, users, processes,
# decoy files, visible ports) does take effect on the live honeypot.
_DB_PERSONA_USERNAME = "root"
_DB_PERSONA_HOME_DIR = "/home/admin"


def _load_persona_from_db(persona_id: str) -> Persona | None:
    """Build a live Persona from a saved persona_configs row, if one exists.

    Returns None — meaning "use the hardcoded preset instead" — when no
    database is configured, the driver isn't installed, the lookup fails for
    any other reason, or no row matches this ID.
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
    except Exception:
        logger.warning(
            "Could not look up persona_configs row for %r; using preset instead",
            persona_id,
            exc_info=True,
        )
        return None

    if record is None:
        return None
    return _persona_from_config_record(record)


def _persona_from_config_record(record) -> Persona:
    """Bridge one dashboard-saved PersonaConfigRecord into a live Persona."""
    hostname = record.hostname or record.id
    fake_filesystem = tuple(
        FakeFile(path=decoy.path, content=decoy.content)
        for decoy in record.decoy_files
    )
    if not any(
        PurePosixPath(decoy.path).is_relative_to(_DB_PERSONA_HOME_DIR)
        for decoy in fake_filesystem
    ):
        # validate_persona() requires at least one file under home_dir.
        fake_filesystem = fake_filesystem + (
            FakeFile(path=f"{_DB_PERSONA_HOME_DIR}/.bash_history", content=""),
        )

    open_ports_visible = tuple(
        sorted(
            {
                port
                for enabled, port in (
                    (record.ssh_enabled, record.ssh_port),
                    (record.http_enabled, record.http_port),
                    (record.ftp_enabled, record.ftp_port),
                    (record.telnet_enabled, record.telnet_port),
                )
                if enabled and port
            }
        )
    )

    return Persona(
        persona_id=record.id,
        os_banner=record.os_banner or f"Linux {hostname} 5.15.0-91-generic x86_64",
        ssh_banner=record.ssh_banner or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        hostname=hostname,
        uname_output=(
            f"Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        ),
        timezone=record.timezone or "UTC",
        username=_DB_PERSONA_USERNAME,
        home_dir=_DB_PERSONA_HOME_DIR,
        fake_filesystem=fake_filesystem,
        running_processes=tuple(record.running_processes),
        fake_users=tuple(record.fake_users),
        suid_binaries=(),
        open_ports_visible=open_ports_visible,
        fake_credentials=(),
    )
