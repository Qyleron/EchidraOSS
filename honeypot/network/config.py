import os

from honeypot.core.persona import Persona, get_persona, validate_persona


"""
Runtime configuration for the honeypot process.

For now, values are simple Python constants so the backend stays easy to run.
Later, organization-specific persona values can come from the HTML/UI and a
database, while the server and shell engine keep using get_active_persona().
"""


# Bind to all interfaces by default so the honeypot can accept remote traffic
HOST = "0.0.0.0"

# Non-privileged SSH-like test port
PORT = 2222

# Maximum number of active client sessions
MAX_CONNECTIONS = 100

# Seconds to wait for a client command before closing the session
READ_TIMEOUT = 60

# --- THE PERSONA ---
# OSS deployments choose one persona at deployment time. Today this is hardcoded
# or set by environment. Later, the HTML/UI can replace get_active_persona()
# with database-backed organization config without changing the shell engine.
PERSONA_ID = os.getenv("ECHIDRA_PERSONA", "generic_linux")
_cached_persona: Persona | None = None


def get_active_persona() -> Persona:
    """
    Return the persona used for new honeypot sessions.

    Current behavior:
    - Read PERSONA_ID from ECHIDRA_PERSONA or use generic_linux.
    - Load one of the hardcoded preset personas.
    - Validate it before any session uses it.

    Future UI behavior:
    - Replace this function's inside with database/UI config lookup.
    - Keep returning a valid Persona object to avoid changing ConnectionHandler.
    - Call clear_active_persona_cache() after changing persona config at runtime.
    """
    global _cached_persona

    if _cached_persona is None:
        persona = get_persona(PERSONA_ID)
        validate_persona(persona)
        _cached_persona = persona

    return _cached_persona


def clear_active_persona_cache() -> None:
    """Force get_active_persona() to reload and revalidate config next time."""
    global _cached_persona
    _cached_persona = None
