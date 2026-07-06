"""Lightweight session state for non-shell protocol honeypot handlers."""

from __future__ import annotations

import time
import uuid

from honeypot.core.persona import Persona


class ProtocolSession:
    """
    Minimal session state for HTTP, FTP, and Telnet honeypot handlers.

    Produces a to_record() dict that satisfies SessionRecord.parse_obj()
    so it can be persisted through the same SessionLogger used by the SSH shell.
    """

    def __init__(self, peer: tuple | None, protocol: str, persona: Persona):
        self.session_id = str(uuid.uuid4())
        self.peer = peer
        self.protocol = protocol
        self.persona = persona
        self.start_time = time.time()
        self.end_time: float | None = None
        self.end_reason: str | None = None
        self._commands: list[dict] = []

    def log_command(self, cmd: str) -> None:
        """Record one protocol interaction line with its timestamp."""
        if cmd:
            self._commands.append({"cmd": cmd, "timestamp": time.time()})

    def finalize(self, reason: str) -> None:
        """Mark the session complete. Idempotent."""
        if self.end_time is None:
            self.end_time = time.time()
            self.end_reason = reason

    def to_record(self) -> dict:
        """Return a dict compatible with SessionRecord.parse_obj()."""
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
            "protocol": self.protocol,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "persona_id": self.persona.persona_id,
            "started_at": self.start_time,
            "ended_at": self.end_time,
            "duration_seconds": self.end_time - self.start_time,
            "end_reason": self.end_reason,
            "command_count": len(self._commands),
            "commands": list(self._commands),
            "decoy_files_surfaced": [],
        }
