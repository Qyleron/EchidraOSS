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
    DashboardReportSummary,
    DashboardUserRecord,
    ManualLabelInput,
    ManualLabelRecord,
    StoredClassifierRun,
    StoredClassifierSignal,
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

SELECT_CLASSIFIER_RUN_SQL = """
SELECT
    classifier_runs.id,
    classifier_runs.session_id,
    sessions.protocol,
    sessions.peer_ip,
    sessions.peer_port,
    sessions.persona_id,
    sessions.started_at,
    sessions.ended_at,
    sessions.end_reason,
    classifier_runs.actor_label,
    classifier_runs.confidence,
    classifier_runs.risk_score,
    classifier_runs.risk_level,
    classifier_runs.behavior_stage,
    classifier_runs.intent
FROM classifier_runs
JOIN sessions ON sessions.id = classifier_runs.session_id
WHERE classifier_runs.id = %(id)s
"""

SELECT_CLASSIFIER_SIGNALS_SQL = """
SELECT
    signal_index,
    signal_type,
    signal_key,
    signal_value
FROM classifier_signals
WHERE classifier_run_id = %(classifier_run_id)s
ORDER BY signal_index
"""

SELECT_MANUAL_LABEL_SQL = """
SELECT
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
FROM manual_labels
WHERE id = %(id)s
"""

SELECT_CLASSIFIER_RUN_BASE_SQL = """
SELECT
    classifier_runs.id,
    classifier_runs.session_id,
    sessions.protocol,
    sessions.peer_ip,
    sessions.peer_port,
    sessions.persona_id,
    sessions.started_at,
    sessions.ended_at,
    sessions.end_reason,
    classifier_runs.actor_label,
    classifier_runs.confidence,
    classifier_runs.risk_score,
    classifier_runs.risk_level,
    classifier_runs.behavior_stage,
    classifier_runs.intent
FROM classifier_runs
JOIN sessions ON sessions.id = classifier_runs.session_id
"""

SELECT_MANUAL_LABEL_BASE_SQL = """
SELECT
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
FROM manual_labels
"""

INSERT_DASHBOARD_USER_SQL = """
INSERT INTO dashboard_users (
    id,
    email,
    password_hash,
    created_at
) VALUES (
    %(id)s,
    %(email)s,
    %(password_hash)s,
    %(created_at)s
)
"""

SELECT_DASHBOARD_USER_BY_EMAIL_SQL = """
SELECT
    id,
    email,
    password_hash,
    created_at
FROM dashboard_users
WHERE email = %(email)s
"""

SELECT_DASHBOARD_REPORT_OVERVIEW_SQL = """
SELECT
    COUNT(*) AS total_runs,
    COUNT(*) FILTER (
        WHERE classifier_runs.risk_level IN ('high', 'critical')
    ) AS elevated_runs,
    COUNT(DISTINCT sessions.persona_id) AS distinct_personas,
    COALESCE(AVG(classifier_runs.risk_score), 0) AS average_risk_score,
    (SELECT COUNT(*) FROM manual_labels) AS manual_labels
FROM classifier_runs
JOIN sessions ON sessions.id = classifier_runs.session_id
"""

SELECT_DASHBOARD_REPORT_RISK_COUNTS_SQL = """
SELECT risk_level AS key, COUNT(*) AS count
FROM classifier_runs
GROUP BY risk_level
ORDER BY risk_level
"""

SELECT_DASHBOARD_REPORT_ACTOR_COUNTS_SQL = """
SELECT COALESCE(actor_label, 'unknown') AS key, COUNT(*) AS count
FROM classifier_runs
GROUP BY COALESCE(actor_label, 'unknown')
ORDER BY count DESC, key
"""

SELECT_DASHBOARD_REPORT_INTENT_COUNTS_SQL = """
SELECT intent AS key, COUNT(*) AS count
FROM classifier_runs
GROUP BY intent
ORDER BY count DESC, key
"""

# Limit validation constants
MAX_LIMIT = 1000
MAX_MANUAL_LABEL_LIMIT = 1000


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

    def get_classifier_run(self, run_id: UUID) -> StoredClassifierRun | None:
        """Fetch one stored classifier run by ID."""
        row = _fetch_one(
            self.database_url,
            SELECT_CLASSIFIER_RUN_SQL,
            {"id": run_id},
        )
        if row is None:
            return None

        signal_rows = _fetch_all(
            self.database_url,
            SELECT_CLASSIFIER_SIGNALS_SQL,
            {"classifier_run_id": run_id},
        )
        return stored_classifier_run_from_rows(row, signal_rows)

    def get_manual_label(self, label_id: UUID) -> ManualLabelRecord | None:
        """Fetch one manual analyst label by ID."""
        row = _fetch_one(
            self.database_url,
            SELECT_MANUAL_LABEL_SQL,
            {"id": label_id},
        )
        if row is None:
            return None
        return manual_label_from_row(row)

    def list_classifier_runs(
        self,
        *,
        session_id: UUID | None = None,
        risk_level: str | None = None,
        actor_label: str | None = None,
        persona_id: str | None = None,
        limit: int = 100,
    ) -> list[StoredClassifierRun]:
        """Fetch stored classifier runs matching optional exact filters."""
        sql, params = classifier_run_list_query(
            session_id=session_id,
            risk_level=risk_level,
            actor_label=actor_label,
            persona_id=persona_id,
            limit=limit,
        )
        rows = _fetch_all(self.database_url, sql, params)
        if not rows:
            return []
        
        # Fetch all signals at once to avoid N+1 query
        run_ids = [row["id"] for row in rows]
        signal_sql = """
        SELECT
            classifier_run_id,
            signal_index,
            signal_type,
            signal_key,
            signal_value
        FROM classifier_signals
        WHERE classifier_run_id = ANY(%(run_ids)s)
        ORDER BY classifier_run_id, signal_index
        """
        signal_rows = _fetch_all(self.database_url, signal_sql, {"run_ids": run_ids})
        
        # Group signals by classifier_run_id
        signals_by_run_id: dict[UUID, list[dict[str, Any]]] = {}
        for signal_row in signal_rows:
            run_id = signal_row["classifier_run_id"]
            if run_id not in signals_by_run_id:
                signals_by_run_id[run_id] = []
            signals_by_run_id[run_id].append(signal_row)
        
        # Build StoredClassifierRun objects with grouped signals
        return [
            stored_classifier_run_from_rows(
                row,
                signals_by_run_id.get(row["id"], []),
            )
            for row in rows
        ]

    def list_manual_labels(
        self,
        *,
        session_id: UUID | None = None,
        classifier_run_id: UUID | None = None,
        limit: int = 100,
    ) -> list[ManualLabelRecord]:
        """Fetch stored manual labels matching optional exact filters."""
        sql, params = manual_label_list_query(
            session_id=session_id,
            classifier_run_id=classifier_run_id,
            limit=limit,
        )
        return [
            manual_label_from_row(row)
            for row in _fetch_all(self.database_url, sql, params)
        ]

    def create_dashboard_user(
        self,
        *,
        email: str,
        password_hash: str,
    ) -> DashboardUserRecord:
        """Persist one dashboard user for UI authentication."""
        record = DashboardUserRecord(
            id=uuid4(),
            email=email,
            password_hash=password_hash,
        )
        _execute_insert(
            self.database_url,
            INSERT_DASHBOARD_USER_SQL,
            dashboard_user_insert_params(record),
        )
        return record

    def get_dashboard_user_by_email(self, email: str) -> DashboardUserRecord | None:
        """Fetch one dashboard user by normalized email."""
        row = _fetch_one(
            self.database_url,
            SELECT_DASHBOARD_USER_BY_EMAIL_SQL,
            {"email": email},
        )
        if row is None:
            return None
        return dashboard_user_from_row(row)

    def get_dashboard_report_summary(self) -> DashboardReportSummary:
        """Fetch database-wide aggregate values for dashboard reporting."""
        overview = _fetch_one(
            self.database_url,
            SELECT_DASHBOARD_REPORT_OVERVIEW_SQL,
            {},
        )
        if overview is None:
            overview = {
                "total_runs": 0,
                "elevated_runs": 0,
                "distinct_personas": 0,
                "manual_labels": 0,
                "average_risk_score": 0,
            }
        return DashboardReportSummary(
            **overview,
            risk_counts=_count_map(
                _fetch_all(self.database_url, SELECT_DASHBOARD_REPORT_RISK_COUNTS_SQL, {})
            ),
            actor_counts=_count_map(
                _fetch_all(self.database_url, SELECT_DASHBOARD_REPORT_ACTOR_COUNTS_SQL, {})
            ),
            intent_counts=_count_map(
                _fetch_all(self.database_url, SELECT_DASHBOARD_REPORT_INTENT_COUNTS_SQL, {})
            ),
        )


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


def dashboard_user_insert_params(record: DashboardUserRecord) -> dict[str, Any]:
    """Return SQL parameters for inserting a dashboard user row."""
    return {
        "id": record.id,
        "email": record.email,
        "password_hash": record.password_hash,
        "created_at": record.created_at,
    }


def stored_classifier_run_from_rows(
    run_row: dict[str, Any],
    signal_rows: list[dict[str, Any]],
) -> StoredClassifierRun:
    """Build the API read model for one stored classifier run."""
    return StoredClassifierRun(
        **run_row,
        signals=[StoredClassifierSignal(**row) for row in signal_rows],
    )


def manual_label_from_row(row: dict[str, Any]) -> ManualLabelRecord:
    """Build the storage model for one manual label query result."""
    return ManualLabelRecord(**row)


def dashboard_user_from_row(row: dict[str, Any]) -> DashboardUserRecord:
    """Build the storage model for one dashboard user query result."""
    return DashboardUserRecord(**row)


def _count_map(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {str(row["key"]): int(row["count"]) for row in rows}


def classifier_run_list_query(
    *,
    session_id: UUID | None = None,
    risk_level: str | None = None,
    actor_label: str | None = None,
    persona_id: str | None = None,
    limit: int = 100,
) -> tuple[str, dict[str, Any]]:
    """Return SQL and parameters for listing stored classifier runs."""
    # Validate and clamp limit
    if not isinstance(limit, int) or limit < 1:
        raise ValueError(f"limit must be a positive integer, got {limit}")
    limit = min(limit, MAX_LIMIT)
    
    filters: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if session_id is not None:
        filters.append("classifier_runs.session_id = %(session_id)s")
        params["session_id"] = session_id
    if risk_level is not None:
        filters.append("classifier_runs.risk_level = %(risk_level)s")
        params["risk_level"] = risk_level
    if actor_label is not None:
        filters.append("classifier_runs.actor_label = %(actor_label)s")
        params["actor_label"] = actor_label
    if persona_id is not None:
        filters.append("sessions.persona_id = %(persona_id)s")
        params["persona_id"] = persona_id

    return _list_query(
        SELECT_CLASSIFIER_RUN_BASE_SQL,
        filters,
        "sessions.started_at DESC, classifier_runs.id DESC",
        params,
    )


def manual_label_list_query(
    *,
    session_id: UUID | None = None,
    classifier_run_id: UUID | None = None,
    limit: int = 100,
) -> tuple[str, dict[str, Any]]:
    """Return SQL and parameters for listing stored manual labels."""
    # Validate and clamp limit
    if not isinstance(limit, int) or limit < 1:
        raise ValueError(f"limit must be a positive integer, got {limit}")
    limit = min(limit, MAX_MANUAL_LABEL_LIMIT)
    
    filters: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if session_id is not None:
        filters.append("session_id = %(session_id)s")
        params["session_id"] = session_id
    if classifier_run_id is not None:
        filters.append("classifier_run_id = %(classifier_run_id)s")
        params["classifier_run_id"] = classifier_run_id

    return _list_query(
        SELECT_MANUAL_LABEL_BASE_SQL,
        filters,
        "created_at DESC, id DESC",
        params,
    )


def _list_query(
    base_sql: str,
    filters: list[str],
    order_by: str,
    params: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    where_sql = ""
    if filters:
        where_sql = "\nWHERE " + "\n  AND ".join(filters)
    sql = f"{base_sql.rstrip()}{where_sql}\nORDER BY {order_by}\nLIMIT %(limit)s"
    return sql, params


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


def _fetch_one(
    database_url: str,
    sql: str,
    params: dict[str, Any],
) -> dict[str, Any] | None:
    rows = _fetch_all(database_url, sql, params)
    return rows[0] if rows else None


def _fetch_all(
    database_url: str,
    sql: str,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    psycopg = _load_psycopg()
    with psycopg.connect(database_url) as connection:
        with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
            cursor.execute(sql, params)
            return list(cursor.fetchall())


def _load_psycopg():
    try:
        import psycopg
    except ModuleNotFoundError as exc:
        raise DatabaseDriverMissingError(
            "Install psycopg to use PostgreSQL storage: "
            "python -m pip install 'psycopg[binary]'"
        ) from exc

    return psycopg
