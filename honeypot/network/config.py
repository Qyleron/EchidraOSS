import os

from dotenv import load_dotenv

from honeypot.core.persona import Persona, get_persona, validate_persona


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


# Bind to all interfaces by default so the honeypot can accept remote traffic
HOST = os.getenv("ECHIDRA_HOST", "0.0.0.0")

# Non-privileged SSH-like test port
PORT = _int_from_env("ECHIDRA_PORT", 2222)

# Maximum number of active client sessions
MAX_CONNECTIONS = _int_from_env("ECHIDRA_MAX_CONNECTIONS", 100)

# Seconds to wait for a client command before closing the session
READ_TIMEOUT = _int_from_env("ECHIDRA_READ_TIMEOUT", 60)

# Append-only structured records consumed by the future classifier
SESSION_LOG_PATH = os.getenv("ECHIDRA_SESSION_LOG", "logs/sessions.jsonl")

DEFAULT_PERSONA_ID = "generic_linux"
_cached_persona: Persona | None = None
_cached_persona_id: str | None = None


def get_active_persona() -> Persona:
    """
    Return the persona used for new honeypot sessions.

    Current behavior:
    - Read ECHIDRA_PERSONA or use generic_linux.
    - Load one of the hardcoded preset personas.
    - Validate it before any session uses it.

    Future UI behavior:
    - Replace this function's inside with database/UI config lookup.
    - Keep returning a valid Persona object to avoid changing ConnectionHandler.
    - Call clear_active_persona_cache() after changing persona config at runtime.
    """
    global _cached_persona, _cached_persona_id

    persona_id = os.getenv("ECHIDRA_PERSONA", DEFAULT_PERSONA_ID)
    if _cached_persona is None or _cached_persona_id != persona_id:
        persona = get_persona(persona_id)
        validate_persona(persona)
        _cached_persona = persona
        _cached_persona_id = persona_id

    return _cached_persona


def clear_active_persona_cache() -> None:
    """Force get_active_persona() to reload and revalidate config next time."""
    global _cached_persona, _cached_persona_id
    _cached_persona = None
    _cached_persona_id = None
