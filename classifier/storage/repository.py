"""PostgreSQL repository for classifier runs and manual labels."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage.config import get_database_url
from classifier.storage.models import (
    ClassifierRunRecord,
    ManualLabelInput,
    ManualLabelRecord,
)


DELETE_SESSION_EVENTS_SQL = """
DELETE FROM session_events
WHERE session_id = %(session_id)s
"""

INSERT_SESSION_EVENT_SQL = """
INSERT INTO session_events (
    session_id,
    event_index,
    event_type,
    event_value,
    observed_at
) VALUES (
    %(session_id)s,
    %(event_index)s,
    %(event_type)s,
    %(event_value)s,
    %(observed_at)s
)
"""

INSERT_CLASSIFIER_RUN_SQL = """
INSERT INTO classifier_runs (
    id,
    session_id,
    actor_label,
    confidence,
    risk_score,
    risk_level,
    behavior_stage,
    intent
) VALUES (
    %(id)s,
    %(session_id)s,
    %(actor_label)s,
    %(confidence)s,
    %(risk_score)s,
    %(risk_level)s,
    %(behavior_stage)s,
    %(intent)s
)
"""

INSERT_CLASSIFIER_SIGNAL_SQL = """
INSERT INTO classifier_signals (
    classifier_run_id,
    signal_index,
    signal_type,
    signal_key,
    signal_value
) VALUES (
    %(classifier_run_id)s,
    %(signal_index)s,
    %(signal_type)s,
    %(signal_key)s,
    %(signal_value)s
)
"""

UPSERT_SESSION_SQL = """
INSERT INTO sessions (
    id,
    protocol,
    peer_ip,
    peer_port,
    persona_id,
    started_at,
    ended_at,
    end_reason
) VALUES (
    %(id)s,
    %(protocol)s,
    %(peer_ip)s,
    %(peer_port)s,
    %(persona_id)s,
    %(started_at)s,
    %(ended_at)s,
    %(end_reason)s
)
ON CONFLICT (id) DO UPDATE SET
    protocol = EXCLUDED.protocol,
    peer_ip = EXCLUDED.peer_ip,
    peer_port = EXCLUDED.peer_port,
    persona_id = EXCLUDED.persona_id,
    started_at = EXCLUDED.started_at,
    ended_at = EXCLUDED.ended_at,
    end_reason = EXCLUDED.end_reason
"""

INSERT_MANUAL_LABEL_SQL = """
INSERT INTO manual_labels (
    id,
    classifier_run_id,
    session_id,
    actor_label,
    risk_level,
    behavior_stage,
    intent,
    notes,
    labeled_by,
    created_at
) VALUES (
    %(id)s,
    %(classifier_run_id)s,
    %(session_id)s,
    %(actor_label)s,
    %(risk_level)s,
    %(behavior_stage)s,
    %(intent)s,
    %(notes)s,
    %(labeled_by)s,
    %(created_at)s
)
"""


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when storage is requested without ECHIDRA_DATABASE_URL."""


class DatabaseDriverMissingError(RuntimeError):
    """Raised when psycopg is unavailable for PostgreSQL storage."""


class PostgresClassifierRepository:
    """Persist classifier outputs and analyst labels to PostgreSQL."""

    def __init__(self, database_url: str | None = None):
        self.database_url = database_url or get_database_url()
        if self.database_url is None:
            raise DatabaseNotConfiguredError(
                "ECHIDRA_DATABASE_URL must be set to use PostgreSQL storage"
            )

    def save_classifier_run(
        self,
        session: SessionRecord,
        summary: ClassificationSummary,
        run_id: UUID | None = None,
    ) -> ClassifierRunRecord:
        """Persist one classifier run and return the stored record contract."""
        record = ClassifierRunRecord.from_session_summary(
            session=session,
            summary=summary,
            run_id=run_id,
        )
        _execute_statements(self.database_url, classifier_run_statements(record))
        return record

    def save_manual_label(self, label: ManualLabelInput) -> ManualLabelRecord:
        """Persist one manual analyst label and return the stored label."""
        record = ManualLabelRecord(
            id=uuid4(),
            **label.dict(),
        )
        _execute_insert(
            self.database_url,
            INSERT_MANUAL_LABEL_SQL,
            manual_label_insert_params(record),
        )
        return record


def classifier_run_insert_params(record: ClassifierRunRecord) -> dict[str, Any]:
    """Return SQL parameters for the compact classifier_runs row."""
    return {
        "id": record.id,
        "session_id": record.session_id,
        "actor_label": record.actor_label,
        "confidence": record.confidence,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "behavior_stage": record.behavior_stage,
        "intent": record.intent,
    }


def classifier_run_statements(
    record: ClassifierRunRecord,
) -> list[tuple[str, dict[str, Any]]]:
    """Return all SQL writes needed to persist one five-table classifier run."""
    statements = [
        (DELETE_SESSION_EVENTS_SQL, {"session_id": record.session_id}),
        (UPSERT_SESSION_SQL, session_insert_params(record)),
    ]
    statements.extend(
        (INSERT_SESSION_EVENT_SQL, params)
        for params in session_event_insert_params(record)
    )
    statements.append(
        (INSERT_CLASSIFIER_RUN_SQL, classifier_run_insert_params(record))
    )
    statements.extend(
        (INSERT_CLASSIFIER_SIGNAL_SQL, params)
        for params in classifier_signal_insert_params(record)
    )
    return statements


def session_insert_params(record: ClassifierRunRecord) -> dict[str, Any]:
    """Return SQL parameters for upserting the parent session row."""
    session_record = record.session_record
    return {
        "id": record.session_id,
        "protocol": record.protocol,
        "peer_ip": session_record.get("peer_ip"),
        "peer_port": session_record.get("peer_port"),
        "persona_id": record.persona_id,
        "started_at": session_record["started_at"],
        "ended_at": session_record["ended_at"],
        "end_reason": session_record["end_reason"],
    }


def session_event_insert_params(record: ClassifierRunRecord) -> list[dict[str, Any]]:
    """Return command and decoy exposure timeline rows for one session."""
    commands = record.session_record.get("commands", []) or []
    decoy_files = record.session_record.get("decoy_files_surfaced", []) or []

    events = [
        {
            "session_id": record.session_id,
            "event_index": index,
            "event_type": "command",
            "event_value": command["cmd"],
            "observed_at": command["timestamp"],
        }
        for index, command in enumerate(commands)
    ]
    offset = len(events)
    events.extend(
        {
            "session_id": record.session_id,
            "event_index": offset + index,
            "event_type": "decoy_file",
            "event_value": path,
            "observed_at": None,
        }
        for index, path in enumerate(decoy_files)
    )
    return events


def classifier_signal_insert_params(
    record: ClassifierRunRecord,
) -> list[dict[str, Any]]:
    """Return variable-length classifier details as typed signal rows."""
    signals: list[dict[str, Any]] = []

    def add_signal(signal_type: str, signal_key: str, signal_value: str) -> None:
        signals.append(
            {
                "classifier_run_id": record.id,
                "signal_index": len(signals),
                "signal_type": signal_type,
                "signal_key": signal_key,
                "signal_value": signal_value,
            }
        )

    add_signal("version", "classifier", record.classifier_version)
    add_signal("version", "rules", record.rules_version)

    for actor_label, vote_count in record.summary.get("actor_votes", {}).items():
        add_signal("actor_vote", actor_label, str(vote_count))

    for rule_id in record.matched_rule_ids:
        add_signal("matched_rule", "rule_id", rule_id)

    for tag in record.mitre_tags:
        add_signal("mitre_tag", "attack_id", tag)

    for item in record.summary.get("evidence", []):
        add_signal("evidence", item.get("rule_id", ""), item.get("text", ""))

    feature_summary = record.summary.get("feature_summary")
    if feature_summary is not None:
        for key, value in feature_summary.items():
            add_signal("feature", key, str(value))

    for recommendation in record.summary.get("safeguard_recommendations", []):
        add_signal(
            "recommendation",
            recommendation.get("action", "unknown"),
            recommendation.get("priority", "unknown"),
        )

    return signals


def manual_label_insert_params(record: ManualLabelRecord) -> dict[str, Any]:
    """Return SQL parameters for inserting an analyst label row."""
    return {
        "id": record.id,
        "classifier_run_id": record.classifier_run_id,
        "session_id": record.session_id,
        "actor_label": record.actor_label,
        "risk_level": record.risk_level,
        "behavior_stage": record.behavior_stage,
        "intent": record.intent,
        "notes": record.notes,
        "labeled_by": record.labeled_by,
        "created_at": record.created_at,
    }


def _execute_insert(database_url: str, sql: str, params: dict[str, Any]) -> None:
    _execute_statements(database_url, [(sql, params)])


def apply_schema(database_url: str, schema_path: str | Path) -> None:
    """Apply the PostgreSQL schema file to an existing database."""
    schema_sql = Path(schema_path).read_text(encoding="utf-8")
    psycopg = _load_psycopg()
    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(schema_sql)


def _execute_statements(
    database_url: str,
    statements: list[tuple[str, dict[str, Any]]],
) -> None:
    psycopg = _load_psycopg()
    with psycopg.connect(database_url) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                for sql, params in statements:
                    cursor.execute(sql, params)


def _load_psycopg():
    try:
        import psycopg
    except ModuleNotFoundError as exc:
        raise DatabaseDriverMissingError(
            "Install psycopg to use PostgreSQL storage: "
            "python -m pip install 'psycopg[binary]'"
        ) from exc

    return psycopg
