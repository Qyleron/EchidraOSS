from __future__ import annotations

import shlex
from uuid import UUID

from pydantic import BaseModel, Field

from classifier.schemas.session import SessionRecord


DISCOVERY_COMMANDS = {
    "hostname",
    "id",
    "ls",
    "netstat",
    "ps",
    "pwd",
    "ss",
    "uname",
    "whoami",
}
EXIT_COMMANDS = {"exit", "logout", "quit"}
SENSITIVE_PATH_MARKERS = {
    ".env",
    "auth.log",
    "backup",
    "credential",
    "passwd",
    "shadow",
    "wp-config",
}


class SessionFeatures(BaseModel):
    """Observable session measurements consumed by future classifier rules."""

    session_id: UUID
    protocol: str
    persona_id: str
    end_reason: str
    duration_seconds: float = Field(ge=0)
    command_count: int = Field(ge=0)
    commands_per_minute: float = Field(ge=0)
    unique_command_count: int = Field(ge=0)
    repeated_command_count: int = Field(ge=0)
    discovery_command_count: int = Field(ge=0)
    file_read_count: int = Field(ge=0)
    sensitive_file_read_count: int = Field(ge=0)
    decoy_files_surfaced: list[str]
    decoy_files_surfaced_count: int = Field(ge=0)
    exit_command_present: bool
    inter_command_intervals_seconds: list[float]
    average_inter_command_interval_seconds: float | None
    command_names: list[str]

    class Config:
        extra = "forbid"


def extract_session_features(session: SessionRecord) -> SessionFeatures:
    """Convert one validated session into deterministic behavioral measurements."""
    command_names = []
    discovery_command_count = 0
    file_read_count = 0
    sensitive_file_read_count = 0
    exit_command_present = False

    for event in session.commands:
        command_name, args = _parse_command(event.cmd)
        command_names.append(command_name)

        if command_name in DISCOVERY_COMMANDS:
            discovery_command_count += 1

        if command_name == "cat":
            file_read_count += 1
            if any(_is_sensitive_path(arg) for arg in args):
                sensitive_file_read_count += 1

        if command_name in EXIT_COMMANDS:
            exit_command_present = True

    intervals = [
        current.timestamp - previous.timestamp
        for previous, current in zip(session.commands, session.commands[1:])
    ]
    average_interval = sum(intervals) / len(intervals) if intervals else None
    unique_command_count = len(set(command_names))

    return SessionFeatures(
        session_id=session.session_id,
        protocol=session.protocol,
        persona_id=session.persona_id,
        end_reason=session.end_reason,
        duration_seconds=session.duration_seconds,
        command_count=session.command_count,
        commands_per_minute=_commands_per_minute(
            session.command_count,
            session.duration_seconds,
        ),
        unique_command_count=unique_command_count,
        repeated_command_count=session.command_count - unique_command_count,
        discovery_command_count=discovery_command_count,
        file_read_count=file_read_count,
        sensitive_file_read_count=sensitive_file_read_count,
        decoy_files_surfaced=session.decoy_files_surfaced,
        decoy_files_surfaced_count=len(session.decoy_files_surfaced),
        exit_command_present=exit_command_present,
        inter_command_intervals_seconds=intervals,
        average_inter_command_interval_seconds=average_interval,
        command_names=command_names,
    )


def _parse_command(raw_command: str) -> tuple[str, list[str]]:
    """Return a normalized command name and arguments, even for malformed input."""
    try:
        tokens = shlex.split(raw_command)
    except ValueError:
        tokens = raw_command.split()

    if not tokens:
        return "", []

    return tokens[0].lower(), tokens[1:]


def _is_sensitive_path(path: str) -> bool:
    """Identify reads of paths likely to contain credentials or useful secrets."""
    normalized_path = path.lower()
    return any(marker in normalized_path for marker in SENSITIVE_PATH_MARKERS)


def _commands_per_minute(command_count: int, duration_seconds: float) -> float:
    """Calculate a stable command rate for sessions of any duration."""
    if duration_seconds == 0:
        return 0.0

    return command_count * 60 / duration_seconds
