import time

from honeypot.core.persona import Persona, get_persona


class SessionState:
    """
    Mutable state for one honeypot client session.

    Tracks identity, timing, command history, current fake directory, and the
    persona-backed virtual filesystem visible to the visitor.
    """

    def __init__(self, peer, persona: Persona | None = None):

        # Identity and timing
        self.peer = peer   
        self.start_time = time.time()  
        self.last_active = self.start_time  
        self.persona = persona or get_persona()

        # Activity tracking
        self.commands = []  
        self.command_count = 0  

        # Fake shell environment
        self.cwd = self.persona.home_dir  
        self.mode = "unknown" 

        # Per-session copy of persona files
        self.files = self.persona.file_map()


    def log_command(self, command: str) -> None:
        """Record a command and refresh session activity metadata."""

        self.commands.append({
            "cmd": command,
            "timestamp": time.time(),
        })

        
        self.command_count += 1
        self.last_active = time.time()


    def prompt(self) -> str:
        """Return the current fake shell prompt."""
        return f"{self.cwd}$ "

    @property
    def persona_id(self) -> str:
        """Expose the active persona ID without storing a duplicate copy."""
        return self.persona.persona_id
