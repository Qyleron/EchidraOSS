import math
from pathlib import PurePosixPath
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator


def _reject_non_finite(value: float | None) -> float | None:
    """NaN/Infinity silently pass Pydantic v1's ge/le Field constraints
    (comparisons against NaN are always False, and +/-inf satisfies most
    bounds), so every timing/coordinate float needs this explicit check --
    a NaN risk_score or an infinite timestamp would otherwise reach scoring
    and JSON-serialize as a token (`NaN`/`Infinity`) that isn't valid JSON
    and that JS's JSON.parse rejects on the dashboard side."""
    if value is not None and not math.isfinite(value):
        raise ValueError("must be a finite number")
    return value


class CommandEvent(BaseModel):
    """One non-empty shell command observed during a honeypot session."""

    cmd: str = Field(min_length=1)
    timestamp: float

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: float | None) -> float | None:
        return _reject_non_finite(value)

    model_config = ConfigDict(extra="forbid")


class SessionRecord(BaseModel):
    """Canonical v1 record for one completed TCP shell session."""

    schema_version: Literal[1]
    session_id: UUID
    protocol: Literal["tcp_shell", "http", "ftp", "telnet"]
    peer_ip: IPvAnyAddress | None
    peer_port: int | None = Field(default=None, ge=1, le=65535)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    persona_id: str = Field(min_length=1)
    started_at: float
    ended_at: float
    duration_seconds: float = Field(ge=0)
    end_reason: Literal["logout", "timeout", "disconnect", "shutdown", "error"]
    command_count: int = Field(ge=0)
    commands: list[CommandEvent]
    decoy_files_surfaced: list[str] = Field(default_factory=list)

    @field_validator("latitude", "longitude", "started_at", "ended_at", "duration_seconds")
    @classmethod
    def _validate_finite(cls, value: float | None) -> float | None:
        return _reject_non_finite(value)

    @model_validator(mode="after")
    def validate_session_consistency(self) -> "SessionRecord":
        """Reject records whose summary fields disagree with their events."""
        started_at = self.started_at
        ended_at = self.ended_at
        duration_seconds = self.duration_seconds
        commands = self.commands
        command_count = self.command_count
        decoy_files_surfaced = self.decoy_files_surfaced
        latitude = self.latitude
        longitude = self.longitude

        if (latitude is None) != (longitude is None):
            raise ValueError("latitude and longitude must be provided together")

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

        return self

    model_config = ConfigDict(extra="forbid")
