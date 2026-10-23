"""Store sessions captured while the database was unreachable, once it's back.

Every session is written to the session log first. When saving one to the
database then fails because the database can't be reached,
auto_classify_and_store also adds it to pending-sessions.jsonl, next to the
session log; so does the honeypot, at stop, for sessions still waiting in
the classification queue. The honeypot calls catch_up_pending_sessions every minute: once
the database answers again, it stores those sessions, skipping any already
stored, and sends one summary alert per decoy instead of one late alert per
session.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from classifier.schemas.session import SessionRecord

logger = logging.getLogger(__name__)

PENDING_SESSIONS_FILENAME = "pending-sessions.jsonl"
_BATCH_SIZE = 500

# Classification workers are threads: their appends, and the catch-up taking
# the file over, must not interleave.
_pending_lock = threading.Lock()


def pending_sessions_path() -> Path:
    from honeypot.network.config import SESSION_LOG_PATH

    return Path(SESSION_LOG_PATH).with_name(PENDING_SESSIONS_FILENAME)


def _catching_up_path(path: Path) -> Path:
    # The pending file is renamed to this while it's being stored, so new
    # failures start a fresh pending file instead of racing the reader. If
    # the process stops part-way, the next catch-up resumes from it.
    return path.with_name(path.name + ".catching-up")


def _append_lines(path: Path, lines: list[str]) -> None:
    if not lines:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # 0o600, like the session log: these records can hold captured credentials.
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, "".join(lines).encode("utf-8"))
    finally:
        os.close(descriptor)


def keep_pending_session(session: SessionRecord, path: Path | None = None) -> None:
    """Add a session that couldn't be stored to the pending file."""
    path = path or pending_sessions_path()
    try:
        with _pending_lock:
            _append_lines(path, [session.model_dump_json() + "\n"])
    except OSError:
        logger.exception(
            "Could not keep session %s to store later; it is still in the session log",
            session.session_id,
        )


def keep_pending_sessions(sessions: list[SessionRecord], path: Path | None = None) -> None:
    """Add sessions the honeypot stopped before storing to the pending file,
    in one write."""
    path = path or pending_sessions_path()
    try:
        with _pending_lock:
            _append_lines(path, [session.model_dump_json() + "\n" for session in sessions])
    except OSError:
        logger.exception(
            "Could not keep %d session(s) to store later; they are still in the session log. "
            "To store them: echidra import logs/sessions.jsonl",
            len(sessions),
        )


def _has_content(path: Path) -> bool:
    try:
        return path.stat().st_size > 0
    except FileNotFoundError:
        return False


def count_pending_sessions(path: Path | None = None) -> int:
    """Sessions waiting to be stored, including any part-way through a catch-up."""
    path = path or pending_sessions_path()
    total = 0
    for candidate in (path, _catching_up_path(path)):
        try:
            with candidate.open(encoding="utf-8") as handle:
                total += sum(1 for line in handle if line.strip())
        except FileNotFoundError:
            continue
    return total


def catch_up_pending_sessions(path: Path | None = None) -> int:
    """Store pending sessions if the database is reachable again.

    Returns how many were stored. Does nothing while the database is still
    unreachable, so it's safe to call on a timer.
    """
    from classifier.alerts import send_catch_up_alerts
    from classifier.pipeline import classify_and_store
    from classifier.storage import (
        PostgresClassifierRepository,
        is_database_busy,
        is_database_disk_full,
        is_database_unavailable,
    )

    path = path or pending_sessions_path()
    working = _catching_up_path(path)
    if not (_has_content(path) or _has_content(working)):
        return 0

    try:
        repository = PostgresClassifierRepository()
        repository.ping()
    except Exception:
        return 0  # not configured, or still unreachable: try again next time

    with _pending_lock:
        if not working.exists():
            os.replace(path, working)

    lines = [line for line in working.read_text(encoding="utf-8").splitlines() if line.strip()]
    stored = []
    position = 0
    try:
        while position < len(lines):
            batch = []
            for line in lines[position:position + _BATCH_SIZE]:
                try:
                    batch.append(SessionRecord.model_validate_json(line))
                except ValueError:
                    logger.warning("Skipped a pending session that isn't a valid session record")
            already_stored = repository.stored_session_ids([s.session_id for s in batch])
            for session in batch:
                if session.session_id in already_stored:
                    continue
                try:
                    result = classify_and_store(session, repository)
                except Exception as exc:
                    if is_database_unavailable(exc):
                        raise
                    if is_database_busy(exc):
                        # Not an outage: skip just this one, so it doesn't
                        # hold up the sessions behind it.
                        logger.error(
                            "Could not store pending session %s: the database took too long "
                            "to answer. It is still in the session log; store it with "
                            "'echidra import' (see docs/DEPLOYMENT.md)",
                            session.session_id,
                        )
                        continue
                    logger.exception(
                        "Could not store pending session %s; it is still in the session log",
                        session.session_id,
                    )
                    continue
                if result is not None:
                    run, summary = result
                    stored.append((run, session, summary))
            position += _BATCH_SIZE
    except Exception as exc:
        if is_database_disk_full(exc):
            logger.warning("Database disk full; pending sessions will be retried")
        elif is_database_unavailable(exc):
            logger.warning("Database unreachable again; pending sessions will be retried")
        elif is_database_busy(exc):
            logger.warning("The database took too long to answer; pending sessions will be retried")
        else:
            logger.exception("Catching up pending sessions stopped")
        # Put back everything from the unfinished batch on. Sessions in it that
        # were stored already are skipped next time.
        with _pending_lock:
            _append_lines(path, [line + "\n" for line in lines[position:]])
            working.unlink(missing_ok=True)
    else:
        working.unlink(missing_ok=True)

    if stored:
        logger.info(
            "Stored %d session(s) kept to store later", len(stored)
        )
        send_catch_up_alerts(stored)
        try:
            from classifier.storage.issue_sync import maybe_sync_issues_from_classifier_runs

            maybe_sync_issues_from_classifier_runs()
        except Exception:
            logger.exception("Issue sync after catching up pending sessions failed")
    return len(stored)


@dataclass
class ImportResult:
    stored: int = 0
    already_stored: int = 0
    invalid_lines: int = 0
    failed: int = 0

    @property
    def checked(self) -> int:
        return self.stored + self.already_stored + self.failed


def import_session_log(
    path: Path,
    on_progress: Callable[[ImportResult], None] | None = None,
) -> ImportResult:
    """Store every session in a session log that isn't in the database yet
    (`echidra import`): sessions captured before a database was set up, or
    skipped while the honeypot was overloaded.

    No alerts are sent, since these sessions are usually old. Raises
    DatabaseNotConfiguredError, or psycopg's OperationalError when the
    database can't be reached; running it again skips what's stored.
    """
    from classifier.pipeline import default_rules
    from classifier.storage import PostgresClassifierRepository

    repository = PostgresClassifierRepository()
    repository.ping()
    rules = default_rules()
    result = ImportResult()
    batch: list[SessionRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                batch.append(SessionRecord.model_validate_json(line))
            except ValueError:
                result.invalid_lines += 1
                continue
            if len(batch) == _BATCH_SIZE:
                _import_batch(batch, repository, rules, result)
                batch = []
                if on_progress is not None:
                    on_progress(result)
    if batch:
        _import_batch(batch, repository, rules, result)

    if result.stored:
        try:
            from classifier.storage.issue_sync import maybe_sync_issues_from_classifier_runs

            maybe_sync_issues_from_classifier_runs()
        except Exception:
            logger.exception("Issue sync after importing sessions failed")
    return result


def _import_batch(batch, repository, rules, result: ImportResult) -> None:
    from classifier.pipeline import classify_and_store
    from classifier.storage import is_database_busy, is_database_unavailable

    already_stored = repository.stored_session_ids([s.session_id for s in batch])
    for session in batch:
        if session.session_id in already_stored:
            result.already_stored += 1
            continue
        try:
            stored = classify_and_store(session, repository, rules)
        except Exception as exc:
            if is_database_unavailable(exc):
                raise
            if is_database_busy(exc):
                logger.error(
                    "Could not import session %s: the database took too long to answer",
                    session.session_id,
                )
            else:
                logger.exception("Could not import session %s", session.session_id)
            result.failed += 1
            continue
        if stored is None:
            result.already_stored += 1
        else:
            result.stored += 1
