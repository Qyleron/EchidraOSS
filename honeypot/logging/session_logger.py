import json
import logging
import os
import time
from pathlib import Path

from classifier.pipeline import schedule_auto_classification
from classifier.schemas.session import SSH_DETAIL_FIELDS, SessionRecord
from honeypot.core.session import SessionState

# On a full disk every session fails to log the same way: a traceback per
# session would bury everything else in the log. Log the first failure with
# its traceback, then one count at most every _LOG_FAILURE_INTERVAL_SECONDS.
_LOG_FAILURE_INTERVAL_SECONDS = 30.0
_log_failure_count = 0
_log_failure_last_logged: float | None = None


class SessionLogger:
    """Persist completed honeypot sessions as append-only JSON Lines records."""

    def __init__(self, path: str):
        self.path = Path(path)

    def log(self, session: SessionState) -> SessionRecord:
        """Append one completed session record to the configured JSONL file.

        Returns the validated SessionRecord that was written, so a caller
        (eg. a protocol handler scheduling auto classification) can reuse it
        without re-deriving the same record from the session a second time.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = SessionRecord.model_validate(session.to_record())
        unset = {name for name in SSH_DETAIL_FIELDS if getattr(record, name) is None}
        line = json.dumps(json.loads(record.model_dump_json(exclude=unset)), sort_keys=True) + "\n"

        # 0o600: this file accumulates captured FTP/Telnet credentials and
        # HTTP Authorization headers, so it must not be world/group-readable.
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        descriptor = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)

        return record


def finalize_and_schedule(
    session_logger: SessionLogger,
    session: SessionState,
    protocol: str,
    logger: logging.Logger,
) -> None:
    """Persist a finalized session and schedule auto-classification.

    Every protocol handler calls this right after session.finalize(): a
    persistence failure is logged and swallowed so it can't crash the
    handler's cleanup path. A failed log write (eg. a full disk) still
    schedules classification, so the session reaches the database when the
    database is on another disk or still has room.
    """
    try:
        record = session_logger.log(session)
    except Exception:
        _report_log_failure(protocol, session, logger)
        try:
            record = SessionRecord.model_validate(session.to_record())
        except Exception:
            # Not a valid record either; there's nothing to classify.
            return
    try:
        schedule_auto_classification(record)
    except Exception:
        logger.exception(
            "Failed to schedule classification for %s session %s",
            protocol,
            session.session_id,
        )


def _report_log_failure(protocol: str, session: SessionState, logger: logging.Logger) -> None:
    """Log a failed session-log write; called from inside the except block."""
    global _log_failure_count, _log_failure_last_logged

    _log_failure_count += 1
    now = time.monotonic()
    if _log_failure_last_logged is None:
        logger.exception(
            "Failed to log %s session %s. If the disk is full, free some space: "
            "see 'Disk space' in docs/DEPLOYMENT.md",
            protocol,
            session.session_id,
        )
    elif now - _log_failure_last_logged >= _LOG_FAILURE_INTERVAL_SECONDS:
        logger.error(
            "Failed to log %d session(s) in the last %.0fs (most recent: %s %s). "
            "If the disk is full, free some space: see 'Disk space' in docs/DEPLOYMENT.md",
            _log_failure_count,
            _LOG_FAILURE_INTERVAL_SECONDS,
            protocol,
            session.session_id,
        )
    else:
        return
    _log_failure_count = 0
    _log_failure_last_logged = now
