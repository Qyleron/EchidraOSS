import json
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

        with self.path.open("a", encoding="utf-8") as log_file:
            json.dump(json.loads(record.json()), log_file, sort_keys=True)
            log_file.write("\n")
