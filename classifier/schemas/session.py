from pathlib import PurePosixPath
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, IPvAnyAddress, root_validator


class CommandEvent(BaseModel):
    """One non-empty shell command observed during a honeypot session."""

    cmd: str = Field(min_length=1)
    timestamp: float

    class Config:
        extra = "forbid"


class SessionRecord(BaseModel):
    """Canonical v1 record for one completed TCP shell session."""

    schema_version: Literal[1]
    session_id: UUID
    protocol: Literal["tcp_shell"]
    peer_ip: IPvAnyAddress | None
    peer_port: int | None = Field(default=None, ge=1, le=65535)
    persona_id: str = Field(min_length=1)
    started_at: float
    ended_at: float
    duration_seconds: float = Field(ge=0)
    end_reason: Literal["logout", "timeout", "disconnect", "shutdown", "error"]
    command_count: int = Field(ge=0)
    commands: list[CommandEvent]
    decoy_files_surfaced: list[str] = Field(default_factory=list)

    @root_validator
    def validate_session_consistency(cls, values):
        """Reject records whose summary fields disagree with their events."""
        started_at = values.get("started_at")
        ended_at = values.get("ended_at")
        duration_seconds = values.get("duration_seconds")
        commands = values.get("commands")
        command_count = values.get("command_count")
        decoy_files_surfaced = values.get("decoy_files_surfaced")

        if started_at is not None and ended_at is not None:
            if ended_at < started_at:
                raise ValueError("ended_at cannot be earlier than started_at")

            expected_duration = ended_at - started_at
            if (
                duration_seconds is not None
                and abs(duration_seconds - expected_duration) > 1e-6
            ):
                raise ValueError("duration_seconds must match session timestamps")

            if commands is not None:
                for index, command in enumerate(commands):
                    if not started_at <= command.timestamp <= ended_at:
                        raise ValueError(
                            "command timestamps must fall within the session"
                        )
                    if (
                        index > 0
                        and command.timestamp < commands[index - 1].timestamp
                    ):
                        raise ValueError(
                            "commands must be ordered by timestamp"
                        )

        if commands is not None and command_count != len(commands):
            raise ValueError("command_count must match commands")

        if decoy_files_surfaced is not None:
            if len(decoy_files_surfaced) != len(set(decoy_files_surfaced)):
                raise ValueError("decoy_files_surfaced cannot contain duplicates")

            for path in decoy_files_surfaced:
                if not path.startswith("/") or ".." in PurePosixPath(path).parts:
                    raise ValueError(
                        "decoy_files_surfaced must contain safe absolute paths"
                    )

        return values

    class Config:
        extra = "forbid"
