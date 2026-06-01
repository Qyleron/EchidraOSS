import uuid

import pytest
from pydantic import ValidationError

from classifier.schemas.session import SessionRecord


def valid_record():
    """Return one minimal canonical session record for validation tests."""
    return {
        "schema_version": 1,
        "session_id": str(uuid.uuid4()),
        "protocol": "tcp_shell",
        "peer_ip": "127.0.0.1",
        "peer_port": 4444,
        "persona_id": "generic_linux",
        "started_at": 100.0,
        "ended_at": 103.0,
        "duration_seconds": 3.0,
        "end_reason": "logout",
        "command_count": 1,
        "commands": [
            {
                "cmd": "whoami",
                "timestamp": 101.0,
            },
        ],
    }


def test_schema_accepts_valid_completed_session():
    """Valid JSONL records should be ready for classifier feature extraction."""
    session = SessionRecord.parse_obj(valid_record())

    assert str(session.peer_ip) == "127.0.0.1"
    assert session.commands[0].cmd == "whoami"


def test_schema_rejects_unknown_end_reason():
    """Only lifecycle reasons emitted by ConnectionHandler should be accepted."""
    record = valid_record()
    record["end_reason"] = "mystery"

    with pytest.raises(ValidationError):
        SessionRecord.parse_obj(record)


def test_schema_rejects_mismatched_command_count():
    """Summary counts must agree with the canonical command event list."""
    record = valid_record()
    record["command_count"] = 2

    with pytest.raises(ValidationError, match="command_count"):
        SessionRecord.parse_obj(record)


def test_schema_rejects_command_outside_session_timestamps():
    """Command events outside the session window indicate corrupt input."""
    record = valid_record()
    record["commands"][0]["timestamp"] = 99.0

    with pytest.raises(ValidationError, match="command timestamps"):
        SessionRecord.parse_obj(record)


def test_schema_rejects_unexpected_fields():
    """Schema changes must be intentional and versioned."""
    record = valid_record()
    record["unexpected"] = True

    with pytest.raises(ValidationError):
        SessionRecord.parse_obj(record)


def test_schema_rejects_commands_out_of_timestamp_order():
    """Feature extraction should receive events in their observed order."""
    record = valid_record()
    record["ended_at"] = 104.0
    record["duration_seconds"] = 4.0
    record["command_count"] = 2
    record["commands"].append({
        "cmd": "ls",
        "timestamp": 100.5,
    })

    with pytest.raises(ValidationError, match="ordered by timestamp"):
        SessionRecord.parse_obj(record)
