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
        "decoy_files_surfaced": [],
    }


def test_schema_accepts_valid_completed_session():
    """Valid JSONL records should be ready for classifier feature extraction."""
    session = SessionRecord.parse_obj(valid_record())

    assert str(session.peer_ip) == "127.0.0.1"
    assert session.commands[0].cmd == "whoami"


def test_schema_defaults_historical_records_to_no_surfaced_decoys():
    """Older JSONL records should remain usable after telemetry expansion."""
    record = valid_record()
    del record["decoy_files_surfaced"]

    session = SessionRecord.parse_obj(record)

    assert session.decoy_files_surfaced == []


def test_schema_accepts_optional_geoip_coordinates():
    record = valid_record()
    record.update({"latitude": 12.9716, "longitude": 77.5946})

    session = SessionRecord.parse_obj(record)

    assert session.latitude == 12.9716
    assert session.longitude == 77.5946


def test_schema_requires_geoip_coordinates_as_a_pair():
    record = valid_record()
    record["latitude"] = 12.9716

    with pytest.raises(ValidationError, match="provided together"):
        SessionRecord.parse_obj(record)


def test_schema_rejects_unknown_end_reason():
    """Only lifecycle reasons the protocol handlers actually emit should be accepted."""
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


def test_schema_rejects_duplicate_surfaced_decoy_files():
    """Persona context should list each exposed decoy at most once."""
    record = valid_record()
    record["decoy_files_surfaced"] = ["/etc/passwd", "/etc/passwd"]

    with pytest.raises(ValidationError, match="duplicates"):
        SessionRecord.parse_obj(record)


def test_schema_rejects_unsafe_surfaced_decoy_paths():
    """Surfaced decoys should remain normalized fake filesystem paths."""
    record = valid_record()
    record["decoy_files_surfaced"] = ["../etc/passwd"]

    with pytest.raises(ValidationError, match="safe absolute paths"):
        SessionRecord.parse_obj(record)


@pytest.mark.parametrize("field", ["started_at", "ended_at"])
@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_schema_rejects_non_finite_timestamps(field, bad_value):
    """started_at/ended_at carry no ge/le Field constraint at all, so nothing
    else would catch a NaN/Infinity value here -- it would reach scoring and
    JSON-serialize as a token the dashboard's JS can't parse."""
    record = valid_record()
    record[field] = bad_value

    with pytest.raises(ValidationError, match="finite"):
        SessionRecord.parse_obj(record)


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_schema_rejects_non_finite_duration_seconds(bad_value):
    """duration_seconds' ge=0 constraint already happens to reject NaN/Infinity
    in this Pydantic version, but the explicit finiteness check is kept as a
    documented, version-independent guarantee rather than relying on that."""
    record = valid_record()
    record["duration_seconds"] = bad_value

    with pytest.raises(ValidationError):
        SessionRecord.parse_obj(record)


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_schema_rejects_non_finite_coordinates(bad_value):
    """latitude/longitude's ge/le bounds already happen to reject NaN/Infinity
    in this Pydantic version; same reasoning as duration_seconds above."""
    record = valid_record()
    record.update({"latitude": bad_value, "longitude": 77.5946})

    with pytest.raises(ValidationError):
        SessionRecord.parse_obj(record)


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_schema_rejects_non_finite_command_timestamp(bad_value):
    record = valid_record()
    record["commands"][0]["timestamp"] = bad_value

    with pytest.raises(ValidationError, match="finite"):
        SessionRecord.parse_obj(record)
