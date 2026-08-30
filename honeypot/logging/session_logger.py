import json
import logging
import os
from pathlib import Path

from classifier.pipeline import schedule_auto_classification
from classifier.schemas.session import SessionRecord
from honeypot.core.session import SessionState


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
        line = json.dumps(json.loads(record.model_dump_json()), sort_keys=True) + "\n"

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
    handler's cleanup path, and classification is only scheduled once the
    record has actually made it to storage.
    """
    try:
        record = session_logger.log(session)
    except Exception:
        logger.exception("Failed to log %s session %s", protocol, session.session_id)
    else:
        try:
            schedule_auto_classification(record)
        except Exception:
            logger.exception(
                "Failed to schedule classification for %s session %s",
                protocol,
                session.session_id,
            )
