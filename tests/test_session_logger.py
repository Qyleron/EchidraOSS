import errno
import json
import logging
import stat

import pytest

import honeypot.logging.session_logger as session_logger_module
from honeypot.core.session import SessionState
from honeypot.logging.session_logger import SessionLogger, finalize_and_schedule


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


def test_logger_creates_log_file_readable_only_by_owner(tmp_path):
    """Captured FTP/Telnet credentials and HTTP auth headers land in this
    file, so it must not be group/world-readable."""
    log_path = tmp_path / "sessions.jsonl"
    logger = SessionLogger(str(log_path))

    session = SessionState(("127.0.0.1", 4444))
    session.finalize("disconnect")
    logger.log(session)

    mode = stat.S_IMODE(log_path.stat().st_mode)
    assert mode == 0o600


class _FullDiskLogger:
    def log(self, session):
        raise OSError(errno.ENOSPC, "No space left on device")


def test_a_full_disk_still_stores_the_session(monkeypatch):
    """The database may be on another disk, or still have room."""
    scheduled = []
    monkeypatch.setattr(session_logger_module, "schedule_auto_classification", scheduled.append)
    session = SessionState(("127.0.0.1", 4444))
    session.finalize("disconnect")

    finalize_and_schedule(_FullDiskLogger(), session, "SSH", logging.getLogger("test"))

    assert [str(record.session_id) for record in scheduled] == [str(session.session_id)]


def test_a_full_disk_logs_one_traceback_then_a_count(monkeypatch, caplog):
    """A full disk fails every session the same way: one traceback per
    session would bury everything else in the log."""
    monkeypatch.setattr(session_logger_module, "schedule_auto_classification", lambda record: None)
    monkeypatch.setattr(session_logger_module, "_log_failure_count", 0)
    monkeypatch.setattr(session_logger_module, "_log_failure_last_logged", None)
    fake_now = [1_000.0]
    monkeypatch.setattr(session_logger_module.time, "monotonic", lambda: fake_now[0])
    session = SessionState(("127.0.0.1", 4444))
    session.finalize("disconnect")
    logger = logging.getLogger("test")

    with caplog.at_level(logging.ERROR, logger="test"):
        for _ in range(3):
            finalize_and_schedule(_FullDiskLogger(), session, "SSH", logger)
            fake_now[0] += 1
        fake_now[0] += session_logger_module._LOG_FAILURE_INTERVAL_SECONDS
        finalize_and_schedule(_FullDiskLogger(), session, "SSH", logger)

    assert len(caplog.records) == 2
    assert caplog.records[0].exc_info is not None
    assert "Disk space" in caplog.records[0].message
    assert caplog.records[1].exc_info is None
    assert "Failed to log 3 session(s)" in caplog.records[1].message


def test_a_failed_log_of_an_invalid_session_schedules_nothing(monkeypatch):
    scheduled = []
    monkeypatch.setattr(session_logger_module, "schedule_auto_classification", scheduled.append)
    still_active = SessionState(("127.0.0.1", 4444))

    finalize_and_schedule(_FullDiskLogger(), still_active, "SSH", logging.getLogger("test"))

    assert scheduled == []
