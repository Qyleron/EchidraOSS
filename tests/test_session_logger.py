import json

import pytest

from honeypot.core.session import SessionState
from honeypot.logging.session_logger import SessionLogger


def test_logger_appends_completed_sessions_as_jsonl(tmp_path):
    """Each completed session should become one independently readable line."""
    log_path = tmp_path / "nested" / "sessions.jsonl"
    logger = SessionLogger(str(log_path))

    first = SessionState(("127.0.0.1", 4444))
    first.log_command("whoami")
    first.finalize("logout")

    second = SessionState(("127.0.0.1", 5555))
    second.finalize("disconnect")

    logger.log(first)
    logger.log(second)

    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]

    assert len(records) == 2
    assert [record["end_reason"] for record in records] == [
        "logout",
        "disconnect",
    ]
    assert records[0]["commands"][0]["cmd"] == "whoami"


def test_logger_rejects_active_sessions(tmp_path):
    """Incomplete sessions should never be persisted as finished records."""
    logger = SessionLogger(str(tmp_path / "sessions.jsonl"))

    with pytest.raises(ValueError, match="active session"):
        logger.log(SessionState(("127.0.0.1", 4444)))
