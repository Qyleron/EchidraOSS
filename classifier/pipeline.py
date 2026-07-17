"""Post-session classification entry points for validated and raw logs."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from classifier.features.session import extract_session_features
from classifier.rules.engine import (
    ClassificationRule,
    RuleSet,
    evaluate_rules,
    load_rules,
)
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import (
    ClassificationSummary,
    summarize_rule_evaluation,
)

logger = logging.getLogger(__name__)

DEFAULT_RULES_PATH = Path(__file__).parent / "rules" / "default_rules.yaml"


def classify_session(
    session: SessionRecord,
    rules: RuleSet | list[ClassificationRule] | None = None,
    *,
    connection_count_from_same_ip: int | None = None,
    active: bool = False,
) -> ClassificationSummary:
    """Classify one validated post-session record into an analyst summary.

    Raises ValueError when a rule references an unknown feature field or uses an
    operator against an incompatible feature value.

    connection_count_from_same_ip is a cross-session feature passed only by the
    store-time path (/classify/session/store) after a DB lookup; the stateless
    /classify/session endpoint always leaves it None.
    """
    active_rules = rules if rules is not None else load_rules(DEFAULT_RULES_PATH)
    features = extract_session_features(
        session,
        connection_count_from_same_ip=connection_count_from_same_ip,
    )
    evaluation = evaluate_rules(features, active_rules)
    summary = summarize_rule_evaluation(evaluation, features)
    if active:
        reason = (
            "live classification from an active session; the result may change "
            "when more activity is observed"
        )
        return summary.copy(
            update={
                "classification_status": "partial",
                "insufficient_data_reason": reason,
            }
        )
    return summary


def classify_session_record(
    record: dict[str, Any],
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Validate and classify one decoded session log record.

    Raises pydantic.ValidationError when the record does not match the canonical
    session schema.
    """
    session = SessionRecord.parse_obj(record)
    return classify_session(session, rules)


def classify_session_jsonl(
    line: str,
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> ClassificationSummary:
    """Classify one JSON Lines record emitted by SessionLogger.

    Raises json.JSONDecodeError for malformed JSON and pydantic.ValidationError
    for decoded records that fail schema validation.
    """
    return classify_session_record(json.loads(line), rules)


def classify_session_jsonl_lines(
    lines: Iterable[str],
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> list[ClassificationSummary]:
    """Classify non-empty JSONL session records from an iterable of lines.

    Raises the same exceptions as classify_session_jsonl for the first invalid
    line encountered.
    """
    return [
        classify_session_jsonl(line, rules)
        for line in lines
        if line.strip()
    ]


def classify_session_jsonl_file(
    path: str | Path,
    rules: RuleSet | list[ClassificationRule] | None = None,
) -> list[ClassificationSummary]:
    """Classify all non-empty session records in a JSONL log file.

    Raises OSError when the file cannot be read, plus the parsing and validation
    exceptions documented by classify_session_jsonl.
    """
    with Path(path).open("r", encoding="utf-8") as log_file:
        return classify_session_jsonl_lines(log_file, rules)


# Classification work runs in a small fixed pool of background workers
# draining a bounded queue, instead of one asyncio.to_thread task per session
# on the interpreter's default executor (whose internal work queue has no
# size limit). That decouples "session finished" -- unbounded, driven by
# attacker traffic -- from "classification capacity" -- bounded, driven by
# DB/alerting latency -- so a connection flood can't grow the backlog
# without limit.
_CLASSIFICATION_WORKER_COUNT = 4
_CLASSIFICATION_QUEUE_MAXSIZE = 500

_classification_queue: "asyncio.Queue[SessionRecord | object] | None" = None
_classification_workers: list[asyncio.Task] = []

# Tells a worker to exit its loop instead of waiting on the next queue item.
# Cancelling a worker's task while it's mid asyncio.to_thread(auto_classify_
# and_store, ...) would not stop the underlying thread -- concurrent.futures
# only honors cancel() before a job starts running, and Python joins any
# still-running threads at interpreter exit regardless. So shutdown must
# make the worker loop *return on its own*, and does so by feeding it this
# sentinel once it's idle, rather than cancelling it.
_WORKER_STOP = object()

# Log threshold (not a hard deadline) for how long stop_classification_workers
# waits for already-queued sessions to finish classifying. Every blocking
# call reachable from auto_classify_and_store now has its own timeout --
# DB connect/statement timeouts (classifier/storage/repository.py) and
# alert-delivery socket timeouts (classifier/alerts.py) -- so the wait below
# is guaranteed to finish rather than hang forever; this constant only
# controls when a "this is taking a while" warning is logged.
_CLASSIFICATION_SHUTDOWN_DRAIN_TIMEOUT = 15.0


async def _classification_worker(queue: "asyncio.Queue[SessionRecord | object]") -> None:
    while True:
        session = await queue.get()
        if session is _WORKER_STOP:
            queue.task_done()
            return
        try:
            await asyncio.to_thread(auto_classify_and_store, session)
        except Exception:
            logger.exception("auto_classify_and_store failed in classification worker")
        finally:
            queue.task_done()


def start_classification_workers(
    worker_count: int = _CLASSIFICATION_WORKER_COUNT,
    queue_maxsize: int = _CLASSIFICATION_QUEUE_MAXSIZE,
) -> None:
    """Start the bounded classification queue and its fixed worker pool.

    Call once from the application's event loop at startup (honeypot/main.py
    does this alongside starting each ProtocolServer) before any session can
    reach schedule_auto_classification.
    """
    global _classification_queue
    _classification_queue = asyncio.Queue(maxsize=queue_maxsize)
    _classification_workers.extend(
        asyncio.create_task(_classification_worker(_classification_queue))
        for _ in range(worker_count)
    )


async def stop_classification_workers(
    drain_timeout: float = _CLASSIFICATION_SHUTDOWN_DRAIN_TIMEOUT,
) -> None:
    """Drain already-queued classification work, then stop workers and drop the queue.

    Waits for the queue to fully empty -- so sessions enqueued right before
    shutdown still get classified and stored instead of silently dropped --
    then feeds each now-idle worker a stop sentinel so its loop returns on
    its own. Workers are never cancelled: cancelling a task awaiting
    asyncio.to_thread does not stop the underlying thread, which would keep
    running against a database/SMTP connection after this function -- and
    the worker pool and queue it clears -- has already returned. drain_timeout
    only bounds how long we wait before logging that the drain is slow; the
    actual wait continues past it, relying on every blocking call inside
    auto_classify_and_store having its own timeout (see module docstring
    above _WORKER_STOP) to guarantee this still finishes.
    """
    global _classification_queue
    queue = _classification_queue
    if queue is None:
        return

    try:
        await asyncio.wait_for(queue.join(), timeout=drain_timeout)
    except asyncio.TimeoutError:
        logger.warning(
            "Classification queue drain still running after %.1fs; "
            "continuing to wait for in-flight work to finish",
            drain_timeout,
        )
        await queue.join()

    for _ in _classification_workers:
        await queue.put(_WORKER_STOP)
    await asyncio.gather(*_classification_workers)
    _classification_workers.clear()
    _classification_queue = None


def auto_classify_and_store(session: SessionRecord) -> None:
    """Classify a just-completed session and persist the result, best-effort.

    Called by every protocol handler right after SessionLogger.log() so a
    completed session gets classified automatically, without an operator
    manually running `echidra classify` or calling the ingest API. Mirrors
    classify_and_store_session_endpoint's DB-optional behavior: the honeypot
    must keep working with zero DB setup, so a missing or misconfigured
    database silently skips classification instead of raising -- the session
    is already durably logged to JSONL by the caller regardless of this
    function's outcome. Every step past that is independently best-effort
    for the same reason: a failure here must never surface to (or block)
    the protocol handler that already finished serving its client.
    """
    from classifier.alerts import _maybe_send_alert
    from classifier.storage import (
        DatabaseDriverMissingError,
        DatabaseNotConfiguredError,
        PostgresClassifierRepository,
    )

    try:
        repository = PostgresClassifierRepository()
    except (DatabaseDriverMissingError, DatabaseNotConfiguredError):
        return
    except Exception:
        logger.exception("Failed to construct repository for auto classification")
        return

    connection_count: int | None = None
    if session.peer_ip:
        try:
            connection_count = repository.count_sessions_from_ip(str(session.peer_ip))
        except Exception:
            logger.exception("count_sessions_from_ip failed during auto classification")

    try:
        summary = classify_session(session, connection_count_from_same_ip=connection_count)
    except Exception:
        logger.exception("classify_session failed during auto classification")
        return

    try:
        run = repository.save_classifier_run(session, summary)
    except Exception:
        logger.exception("save_classifier_run failed during auto classification")
        return

    try:
        _maybe_send_alert(run, session, summary)
    except Exception:
        logger.exception("_maybe_send_alert failed during auto classification")


def schedule_auto_classification(session: SessionRecord) -> None:
    """Enqueue a just-completed session for background classification.

    Runs the (blocking, DB-bound) work in one of a fixed pool of worker
    threads started by start_classification_workers(), so a protocol handler
    calling this right after logging a completed session never waits on a
    database round trip (or an alert email) before it can close the
    connection and move on.

    Overload policy: if the bounded queue is already full -- classification
    can't keep up with session volume, eg. during a connection flood -- the
    session is dropped from auto-classification rather than growing the
    backlog without bound. It's already durably logged to JSONL by the
    caller regardless of this function's outcome.
    """
    if _classification_queue is None:
        logger.warning(
            "Classification workers not started; dropping session %s",
            session.session_id,
        )
        return
    try:
        _classification_queue.put_nowait(session)
    except asyncio.QueueFull:
        logger.warning(
            "Classification queue full; dropping session %s",
            session.session_id,
        )
