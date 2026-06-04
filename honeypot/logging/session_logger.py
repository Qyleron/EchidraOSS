import json
import os
from pathlib import Path

from classifier.schemas.session import SessionRecord
from honeypot.core.session import SessionState


class SessionLogger:
    """Persist completed honeypot sessions as append-only JSON Lines records."""

    def __init__(self, path: str):
        self.path = Path(path)

    def log(self, session: SessionState) -> None:
        """Append one completed session record to the configured JSONL file."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = SessionRecord.parse_obj(session.to_record())
        line = json.dumps(json.loads(record.json()), sort_keys=True) + "\n"

        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        descriptor = os.open(self.path, flags, 0o644)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)
