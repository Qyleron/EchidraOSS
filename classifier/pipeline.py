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


# Tasks scheduled by schedule_auto_classification(), kept alive until they
# finish -- asyncio only holds a weak reference to a bare create_task()
# result, so an unreferenced task can be garbage-collected mid-execution.
_background_classification_tasks: set[asyncio.Task] = set()


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
    """Fire-and-forget auto_classify_and_store from a sync or async call site.

    Runs the (blocking, DB-bound) work in a thread so it never stalls the
    caller's event loop -- every protocol handler calls this right after
    logging a completed session and must not wait on a database round trip
    (or an alert email) before it can close the connection and move on.
    """
    task = asyncio.create_task(asyncio.to_thread(auto_classify_and_store, session))
    _background_classification_tasks.add(task)
    task.add_done_callback(_background_classification_tasks.discard)
