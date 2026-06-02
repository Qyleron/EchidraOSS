import time
import uuid

from honeypot.core.persona import Persona, get_persona


class SessionState:
    """
    Mutable state for one honeypot client session.

    Tracks identity, timing, command history, current fake directory, and the
    persona-backed virtual filesystem visible to the visitor.
    """

    def __init__(self, peer, persona: Persona | None = None):

        # Identity and timing
        self.session_id = str(uuid.uuid4())
        self.peer = peer
        self.start_time = time.time()
        self.last_active = self.start_time
        self.end_time = None
        self.end_reason = None
        self.persona = persona or get_persona()

        # Activity tracking
        self.commands = []  
        self.command_count = 0  
        self.decoy_files_surfaced = []

        # Fake shell environment
        self.cwd = self.persona.home_dir  
        self.mode = "unknown" 

        # Per-session copy of persona files
        self.files = self.persona.file_map()


    def log_command(self, command: str) -> None:
        """Record a command and refresh session activity metadata."""

        timestamp = time.time()
        self.commands.append({
            "cmd": command,
            "timestamp": timestamp,
        })

        self.command_count += 1
        self.last_active = timestamp


    def prompt(self) -> str:
        """Return the current fake shell prompt."""
        return f"{self.cwd}$ "

    def record_decoy_file_surfaced(self, path: str) -> None:
        """Track a decoy file once after its name or content reaches the visitor."""
        if path not in self.decoy_files_surfaced:
            self.decoy_files_surfaced.append(path)

    def finalize(self, reason: str) -> None:
        """Mark the session complete without overwriting its first end reason."""
        if self.end_time is None:
            self.end_time = time.time()
            self.end_reason = reason

    def to_record(self) -> dict:
        """Return a structured record suitable for persistence and analysis."""
        if self.end_time is None or self.end_reason is None:
            raise ValueError("Cannot serialize an active session")

        peer_ip = None
        peer_port = None
        if isinstance(self.peer, tuple):
            if self.peer:
                peer_ip = str(self.peer[0])
            if len(self.peer) > 1:
                peer_port = self.peer[1]
        elif self.peer is not None:
            peer_ip = str(self.peer)

        return {
            "schema_version": 1,
            "session_id": self.session_id,
            "protocol": "tcp_shell",
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "persona_id": self.persona_id,
            "started_at": self.start_time,
            "ended_at": self.end_time,
            "duration_seconds": self.end_time - self.start_time,
            "end_reason": self.end_reason,
            "command_count": self.command_count,
            "commands": list(self.commands),
            "decoy_files_surfaced": list(self.decoy_files_surfaced),
        }

    @property
    def persona_id(self) -> str:
        """Expose the active persona ID without storing a duplicate copy."""
        return self.persona.persona_id
