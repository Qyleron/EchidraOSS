"""PostgreSQL repository for classifier runs and manual labels."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
try:
    from classifier.rules.issue_playbook import load_mitre_technique_catalog
except Exception:
    load_mitre_technique_catalog = None

from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage.config import get_database_url
from classifier.storage.models import (
    ClassifierRunRecord,
    DashboardReportSummary,
    DashboardUserRecord,
    DecoyFile,
    IssueRecord,
    ManualLabelInput,
    ManualLabelRecord,
    MitreTechnique,
    PersonaAnalytics,
    PersonaConfigInput,
    PersonaConfigRecord,
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
    latitude,
    longitude,
    country,
    persona_id,
    started_at,
    ended_at,
    end_reason
) VALUES (
    %(id)s,
    %(protocol)s,
    %(peer_ip)s,
    %(peer_port)s,
    %(latitude)s,
    %(longitude)s,
    %(country)s,
    %(persona_id)s,
    %(started_at)s,
    %(ended_at)s,
    %(end_reason)s
)
ON CONFLICT (id) DO UPDATE SET
    protocol = EXCLUDED.protocol,
    peer_ip = EXCLUDED.peer_ip,
    peer_port = EXCLUDED.peer_port,
    latitude = EXCLUDED.latitude,
    longitude = EXCLUDED.longitude,
    country = EXCLUDED.country,
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
    sessions.latitude,
    sessions.longitude,
    sessions.country,
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
    sessions.latitude,
    sessions.longitude,
    sessions.country,
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

SELECT_ISSUE_BASE_SQL = """
SELECT
    id,
    title,
    severity,
    evidence,
    recommended_fix,
    impact,
    session_count,
    persona_count,
    status,
    created_at
FROM issues
"""

SELECT_ISSUE_BY_ID_SQL = SELECT_ISSUE_BASE_SQL + "WHERE id = %(id)s"

SELECT_ISSUE_MITRE_TECHNIQUES_SQL = """
SELECT
    issue_id,
    technique_index,
    technique_id,
    technique_name
FROM issue_mitre_techniques
WHERE issue_id = ANY(%(issue_ids)s)
ORDER BY issue_id, technique_index
"""

UPDATE_ISSUE_STATUS_SQL = """
UPDATE issues
SET status = %(status)s
WHERE id = %(id)s
"""

UPSERT_ISSUE_SQL = """
INSERT INTO issues (
    id,
    title,
    severity,
    evidence,
    recommended_fix,
    impact,
    session_count,
    persona_count,
    status,
    created_at
) VALUES (
    %(id)s,
    %(title)s,
    %(severity)s,
    %(evidence)s,
    %(recommended_fix)s,
    %(impact)s,
    %(session_count)s,
    %(persona_count)s,
    %(status)s,
    %(created_at)s
)
ON CONFLICT (id) DO UPDATE SET
    title = EXCLUDED.title,
    severity = EXCLUDED.severity,
    evidence = EXCLUDED.evidence,
    recommended_fix = EXCLUDED.recommended_fix,
    impact = EXCLUDED.impact,
    session_count = EXCLUDED.session_count,
    persona_count = EXCLUDED.persona_count
"""

DELETE_ISSUE_MITRE_TECHNIQUES_SQL = """
DELETE FROM issue_mitre_techniques
WHERE issue_id = %(issue_id)s
"""

INSERT_ISSUE_MITRE_TECHNIQUE_SQL = """
INSERT INTO issue_mitre_techniques (
    issue_id,
    technique_index,
    technique_id,
    technique_name
) VALUES (
    %(issue_id)s,
    %(technique_index)s,
    %(technique_id)s,
    %(technique_name)s
)
"""

SELECT_ACTOR_MITRE_AGGREGATES_SQL = """
SELECT
    classifier_runs.actor_label AS actor_label,
    mitre_signals.signal_value AS mitre_tag,
    COUNT(DISTINCT classifier_runs.session_id) AS session_count,
    COUNT(DISTINCT sessions.persona_id) AS persona_count,
    MAX(
        CASE classifier_runs.risk_level
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
        END
    ) AS max_risk_rank
FROM classifier_runs
JOIN sessions ON sessions.id = classifier_runs.session_id
JOIN classifier_signals AS mitre_signals
    ON mitre_signals.classifier_run_id = classifier_runs.id
    AND mitre_signals.signal_type = 'mitre_tag'
WHERE classifier_runs.actor_label IS NOT NULL
GROUP BY classifier_runs.actor_label, mitre_signals.signal_value
"""

SELECT_REPEAT_CONNECTION_AGGREGATE_SQL = """
WITH offending_ips AS (
    SELECT peer_ip
    FROM sessions
    WHERE peer_ip IS NOT NULL
      AND started_at >= EXTRACT(EPOCH FROM now()) - %(window_seconds)s
    GROUP BY peer_ip
    HAVING COUNT(*) >= %(min_sessions)s
)
SELECT
    COUNT(*) AS session_count,
    COUNT(DISTINCT sessions.persona_id) AS persona_count,
    COUNT(DISTINCT sessions.peer_ip) AS source_ip_count
FROM sessions
JOIN offending_ips ON offending_ips.peer_ip = sessions.peer_ip
WHERE sessions.started_at >= EXTRACT(EPOCH FROM now()) - %(window_seconds)s
"""

INSERT_PERSONA_CONFIG_SQL = """
INSERT INTO persona_configs (
    id, name, os_banner, ssh_banner, hostname, timezone, internal_notes,
    ssh_enabled, ssh_port, http_enabled, http_port, ftp_enabled, ftp_port,
    telnet_enabled, telnet_port,
    fake_users, running_processes, decoy_files,
    alert_routing_level, alert_min_risk_level, contact_email, slack_webhook, interaction_depth,
    created_at, updated_at
) VALUES (
    %(id)s, %(name)s, %(os_banner)s, %(ssh_banner)s, %(hostname)s, %(timezone)s, %(internal_notes)s,
    %(ssh_enabled)s, %(ssh_port)s, %(http_enabled)s, %(http_port)s, %(ftp_enabled)s, %(ftp_port)s,
    %(telnet_enabled)s, %(telnet_port)s,
    %(fake_users)s, %(running_processes)s, %(decoy_files)s::jsonb,
    %(alert_routing_level)s, %(alert_min_risk_level)s, %(contact_email)s, %(slack_webhook)s, %(interaction_depth)s,
    %(created_at)s, %(updated_at)s
)
"""
SELECT_PERSONA_CONFIG_COLS = """
    id, name, os_banner, ssh_banner, hostname, timezone, internal_notes,
    ssh_enabled, ssh_port, http_enabled, http_port, ftp_enabled, ftp_port,
    telnet_enabled, telnet_port,
    fake_users, running_processes, decoy_files,
    alert_routing_level, alert_min_risk_level, contact_email, slack_webhook, interaction_depth,
    created_at, updated_at
"""

UPDATE_PERSONA_CONFIG_SQL = (
    """
UPDATE persona_configs SET
    name = %(name)s,
    os_banner = %(os_banner)s,
    ssh_banner = %(ssh_banner)s,
    hostname = %(hostname)s,
    timezone = %(timezone)s,
    internal_notes = %(internal_notes)s,
    ssh_enabled = %(ssh_enabled)s,
    ssh_port = %(ssh_port)s,
    http_enabled = %(http_enabled)s,
    http_port = %(http_port)s,
    ftp_enabled = %(ftp_enabled)s,
    ftp_port = %(ftp_port)s,
    telnet_enabled = %(telnet_enabled)s,
    telnet_port = %(telnet_port)s,
    fake_users = %(fake_users)s,
    running_processes = %(running_processes)s,
    decoy_files = %(decoy_files)s::jsonb,
    alert_routing_level = %(alert_routing_level)s,
    alert_min_risk_level = %(alert_min_risk_level)s,
    contact_email = %(contact_email)s,
    slack_webhook = %(slack_webhook)s,
    interaction_depth = %(interaction_depth)s,
    updated_at = %(updated_at)s
WHERE id = %(id)s
"""
    + SELECT_PERSONA_CONFIG_COLS
)

SELECT_PERSONA_CONFIG_BASE_SQL = (
    "SELECT " + SELECT_PERSONA_CONFIG_COLS + " FROM persona_configs "
)

SELECT_PERSONA_CONFIG_BY_ID_SQL = (
    SELECT_PERSONA_CONFIG_BASE_SQL + "WHERE id = %(id)s"
)

DELETE_PERSONA_CONFIG_SQL = "DELETE FROM persona_configs WHERE id = %(id)s RETURNING id"

SELECT_PERSONA_SESSION_COUNT_SQL = """
SELECT COUNT(*) AS total
FROM sessions
WHERE persona_id = %(persona_id)s
"""

SELECT_PERSONA_SESSIONS_TREND_SQL = """
SELECT
    to_char(to_timestamp(started_at)::date, 'YYYY-MM-DD') AS date,
    COUNT(*) AS count
FROM sessions
WHERE persona_id = %(persona_id)s
  AND started_at >= EXTRACT(EPOCH FROM now()) - 30 * 86400
GROUP BY date
ORDER BY date
"""

SELECT_PERSONA_INTENT_COUNTS_SQL = """
SELECT cr.intent AS key, COUNT(*) AS count
FROM classifier_runs cr
JOIN sessions s ON s.id = cr.session_id
WHERE s.persona_id = %(persona_id)s
GROUP BY cr.intent
ORDER BY count DESC, key
"""

SELECT_PERSONA_RISK_COUNTS_SQL = """
SELECT cr.risk_level AS key, COUNT(*) AS count
FROM classifier_runs cr
JOIN sessions s ON s.id = cr.session_id
WHERE s.persona_id = %(persona_id)s
GROUP BY cr.risk_level
ORDER BY count DESC
"""

SELECT_PERSONA_TOP_TECHNIQUES_SQL = """
SELECT cs.signal_value AS technique_id, COUNT(*) AS count
FROM classifier_signals cs
JOIN classifier_runs cr ON cr.id = cs.classifier_run_id
JOIN sessions s ON s.id = cr.session_id
WHERE s.persona_id = %(persona_id)s
  AND cs.signal_type = 'mitre_tag'
GROUP BY cs.signal_value
ORDER BY count DESC
LIMIT 10
"""

SELECT_PERSONA_PEAK_HOURS_SQL = """
SELECT
    EXTRACT(HOUR FROM to_timestamp(started_at))::int AS hour,
    COUNT(*) AS count
FROM sessions
WHERE persona_id = %(persona_id)s
GROUP BY hour
ORDER BY hour
"""

SELECT_PERSONA_TOP_COUNTRIES_SQL = """
SELECT country AS key, COUNT(*) AS count
FROM sessions
WHERE persona_id = %(persona_id)s
  AND country IS NOT NULL
GROUP BY country
ORDER BY count DESC
LIMIT 10
"""

SELECT_SESSIONS_FROM_IP_SQL = """
SELECT COUNT(*) AS cnt
FROM sessions
WHERE peer_ip = %(peer_ip)s
  AND started_at >= EXTRACT(EPOCH FROM now()) - %(window_seconds)s
"""

UPSERT_ALERT_CONFIG_SQL = """
INSERT INTO alert_config (
    id, enabled, smtp_host, smtp_port, smtp_username, smtp_password,
    smtp_from_email, smtp_use_tls, global_min_risk_level, updated_at
) VALUES (
    1, %(enabled)s, %(smtp_host)s, %(smtp_port)s, %(smtp_username)s, %(smtp_password)s,
    %(smtp_from_email)s, %(smtp_use_tls)s, %(global_min_risk_level)s, now()
)
ON CONFLICT (id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    smtp_host = EXCLUDED.smtp_host,
    smtp_port = EXCLUDED.smtp_port,
    smtp_username = EXCLUDED.smtp_username,
    smtp_password = COALESCE(EXCLUDED.smtp_password, alert_config.smtp_password),
    smtp_from_email = EXCLUDED.smtp_from_email,
    smtp_use_tls = EXCLUDED.smtp_use_tls,
    global_min_risk_level = EXCLUDED.global_min_risk_level,
    updated_at = now()
"""

SELECT_ALERT_CONFIG_SQL = """
SELECT enabled, smtp_host, smtp_port, smtp_username,
       (smtp_password IS NOT NULL AND smtp_password != '') AS smtp_password_configured,
       smtp_from_email, smtp_use_tls, global_min_risk_level, updated_at
FROM alert_config WHERE id = 1
"""

INSERT_ALERT_EVENT_SQL = """
INSERT INTO alert_events (
    id, run_id, session_id, persona_id, risk_level, actor_label,
    contact_email, sent_at, success, error_message
) VALUES (
    %(id)s, %(run_id)s, %(session_id)s, %(persona_id)s, %(risk_level)s, %(actor_label)s,
    %(contact_email)s, %(sent_at)s, %(success)s, %(error_message)s
)
"""

SELECT_ALERT_EVENTS_SQL = """
SELECT id, run_id, session_id, persona_id, risk_level, actor_label,
       contact_email, sent_at, success, error_message
FROM alert_events
ORDER BY sent_at DESC
LIMIT %(limit)s
"""

# Limit validation constants
MAX_LIMIT = 1000
MAX_MANUAL_LABEL_LIMIT = 1000
MAX_ISSUE_LIMIT = 500


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when storage is requested without ECHIDRA_DATABASE_URL."""


class DatabaseDriverMissingError(RuntimeError):
    """Raised when psycopg is unavailable for PostgreSQL storage."""


def _alert_password_key() -> bytes:
    """Return a stable encryption key from environment or a local fallback."""
    key = os.environ.get("ECHIDRA_ALERT_SECRET")
    if not key:
        key = os.environ.get("ECHIDRA_SECRET_KEY", "echidra-alert-secret-key")
    if not key:
        key = "echidra-alert-secret-key"
    return base64.urlsafe_b64encode(key.encode("utf-8").ljust(32, b"0")[:32])


def _encrypt_alert_password(value: str | None) -> str | None:
    if value is None:
        return None
    if not value:
        return ""
    return Fernet(_alert_password_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def _decrypt_alert_password(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    try:
        return Fernet(_alert_password_key()).decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return None


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
        try:
            psycopg = _load_psycopg()
            with psycopg.connect(self.database_url) as conn:
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                    overview = _fetch_one_with_conn(
                        self.database_url,
                        SELECT_DASHBOARD_REPORT_OVERVIEW_SQL,
                        {},
                        connection=conn,
                        cursor=cur,
                    )
                    if overview is None:
                        overview = {
                            "total_runs": 0,
                            "elevated_runs": 0,
                            "distinct_personas": 0,
                            "manual_labels": 0,
                            "average_risk_score": 0,
                        }

                    risk_counts = _count_map(
                        _fetch_all_with_conn(
                            self.database_url, SELECT_DASHBOARD_REPORT_RISK_COUNTS_SQL, {}, connection=conn, cursor=cur
                        )
                    )
                    actor_counts = _count_map(
                        _fetch_all_with_conn(
                            self.database_url, SELECT_DASHBOARD_REPORT_ACTOR_COUNTS_SQL, {}, connection=conn, cursor=cur
                        )
                    )
                    intent_counts = _count_map(
                        _fetch_all_with_conn(
                            self.database_url, SELECT_DASHBOARD_REPORT_INTENT_COUNTS_SQL, {}, connection=conn, cursor=cur
                        )
                    )
        except DatabaseDriverMissingError:
            # psycopg not available in this environment (tests monkeypatch
            # the fetch helpers). Fall back to the original per-call helpers
            # which tests may have replaced.
            overview = _fetch_one(self.database_url, SELECT_DASHBOARD_REPORT_OVERVIEW_SQL, {})
            if overview is None:
                overview = {
                    "total_runs": 0,
                    "elevated_runs": 0,
                    "distinct_personas": 0,
                    "manual_labels": 0,
                    "average_risk_score": 0,
                }
            risk_counts = _count_map(_fetch_all(self.database_url, SELECT_DASHBOARD_REPORT_RISK_COUNTS_SQL, {}))
            actor_counts = _count_map(_fetch_all(self.database_url, SELECT_DASHBOARD_REPORT_ACTOR_COUNTS_SQL, {}))
            intent_counts = _count_map(_fetch_all(self.database_url, SELECT_DASHBOARD_REPORT_INTENT_COUNTS_SQL, {}))

        return DashboardReportSummary(
            **overview,
            risk_counts=risk_counts,
            actor_counts=actor_counts,
            intent_counts=intent_counts,
        )

    def list_issues(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[IssueRecord]:
        """Fetch stored issues matching an optional status filter."""
        sql, params = issue_list_query(status=status, limit=limit)
        rows = _fetch_all(self.database_url, sql, params)
        if not rows:
            return []

        issue_ids = [row["id"] for row in rows]
        mitre_rows = _fetch_all(
            self.database_url,
            SELECT_ISSUE_MITRE_TECHNIQUES_SQL,
            {"issue_ids": issue_ids},
        )
        mitre_by_issue_id: dict[UUID, list[dict[str, Any]]] = {}
        for mitre_row in mitre_rows:
            mitre_by_issue_id.setdefault(mitre_row["issue_id"], []).append(mitre_row)

        return [
            issue_from_row(row, mitre_by_issue_id.get(row["id"], []))
            for row in rows
        ]

    def update_issue_status(self, issue_id: UUID, status: str) -> IssueRecord | None:
        """Update one issue's triage status and return the stored record."""
        _execute_insert(
            self.database_url,
            UPDATE_ISSUE_STATUS_SQL,
            {"id": issue_id, "status": status},
        )
        row = _fetch_one(self.database_url, SELECT_ISSUE_BY_ID_SQL, {"id": issue_id})
        if row is None:
            return None

        mitre_rows = _fetch_all(
            self.database_url,
            SELECT_ISSUE_MITRE_TECHNIQUES_SQL,
            {"issue_ids": [issue_id]},
        )
        return issue_from_row(row, mitre_rows)

    def create_persona_config(
        self,
        persona_id: str,
        config: PersonaConfigInput,
    ) -> PersonaConfigRecord:
        """Create a new persona config and return the stored record."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        record = PersonaConfigRecord(id=persona_id, created_at=now, updated_at=now, **config.dict())
        _execute_insert(
            self.database_url,
            INSERT_PERSONA_CONFIG_SQL,
            _persona_config_params(record),
        )
        return record

    def get_persona_config(self, persona_id: str) -> PersonaConfigRecord | None:
        """Fetch one persona config by slug ID."""
        row = _fetch_one(
            self.database_url,
            SELECT_PERSONA_CONFIG_BY_ID_SQL,
            {"id": persona_id},
        )
        return _persona_config_from_row(row) if row is not None else None

    def list_persona_configs(self) -> list[PersonaConfigRecord]:
        """Fetch all persisted persona configs ordered by ID."""
        rows = _fetch_all(
            self.database_url,
            SELECT_PERSONA_CONFIG_BASE_SQL + "ORDER BY id",
            {},
        )
        return [_persona_config_from_row(row) for row in rows]

    def update_persona_config(
        self,
        persona_id: str,
        config: PersonaConfigInput,
    ) -> PersonaConfigRecord | None:
        """Update one persona config and return the stored record, or None if not found."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        params: dict[str, Any] = config.dict()
        params.update({"id": persona_id, "updated_at": now})

        # Use UPDATE ... RETURNING to atomically verify the row was updated and
        # to retrieve the stored values (avoids TOCTOU races between a prior
        # existence check and the write).
        row = _fetch_one(self.database_url, UPDATE_PERSONA_CONFIG_SQL, params)
        if row is None:
            return None

        return _persona_config_from_row(row)

    def delete_persona_config(self, persona_id: str) -> bool:
        """Delete one persona config by ID. Returns True if it existed."""
        # Use DELETE ... RETURNING to ensure we only report success when a row
        # was actually removed (prevents TOCTOU where a prior existence check
        # might become stale).
        row = _fetch_one(self.database_url, DELETE_PERSONA_CONFIG_SQL, {"id": persona_id})
        return row is not None

    def get_persona_analytics(self, persona_id: str) -> PersonaAnalytics:
        """Aggregate session + classifier data for one persona ID."""
        params = {"persona_id": persona_id}
        try:
            psycopg = _load_psycopg()
            with psycopg.connect(self.database_url) as conn:
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                    total_row = _fetch_one_with_conn(
                        self.database_url, SELECT_PERSONA_SESSION_COUNT_SQL, params, connection=conn, cursor=cur
                    )
                    sessions_captured = int(total_row["total"]) if total_row else 0

                    trend_rows = _fetch_all_with_conn(
                        self.database_url, SELECT_PERSONA_SESSIONS_TREND_SQL, params, connection=conn, cursor=cur
                    )
                    intent_rows = _fetch_all_with_conn(
                        self.database_url, SELECT_PERSONA_INTENT_COUNTS_SQL, params, connection=conn, cursor=cur
                    )
                    risk_rows = _fetch_all_with_conn(
                        self.database_url, SELECT_PERSONA_RISK_COUNTS_SQL, params, connection=conn, cursor=cur
                    )
                    technique_rows = _fetch_all_with_conn(
                        self.database_url, SELECT_PERSONA_TOP_TECHNIQUES_SQL, params, connection=conn, cursor=cur
                    )
                    hour_rows = _fetch_all_with_conn(
                        self.database_url, SELECT_PERSONA_PEAK_HOURS_SQL, params, connection=conn, cursor=cur
                    )
                    country_rows = _fetch_all_with_conn(
                        self.database_url, SELECT_PERSONA_TOP_COUNTRIES_SQL, params, connection=conn, cursor=cur
                    )
        except DatabaseDriverMissingError:
            total_row = _fetch_one(self.database_url, SELECT_PERSONA_SESSION_COUNT_SQL, params)
            sessions_captured = int(total_row["total"]) if total_row else 0

            trend_rows = _fetch_all(self.database_url, SELECT_PERSONA_SESSIONS_TREND_SQL, params)
            intent_rows = _fetch_all(self.database_url, SELECT_PERSONA_INTENT_COUNTS_SQL, params)
            risk_rows = _fetch_all(self.database_url, SELECT_PERSONA_RISK_COUNTS_SQL, params)
            technique_rows = _fetch_all(self.database_url, SELECT_PERSONA_TOP_TECHNIQUES_SQL, params)
            hour_rows = _fetch_all(self.database_url, SELECT_PERSONA_PEAK_HOURS_SQL, params)
            country_rows = _fetch_all(self.database_url, SELECT_PERSONA_TOP_COUNTRIES_SQL, params)

        # Resolve MITRE technique names using the generated catalog when
        # available; fall back to the technique id when no name is known.
        mitre_catalog: dict[str, str] = {}
        if load_mitre_technique_catalog is not None:
            try:
                mitre_catalog = load_mitre_technique_catalog()
            except Exception:
                mitre_catalog = {}

        top_techniques = [
            {
                "id": row["technique_id"],
                "name": mitre_catalog.get(row["technique_id"], row["technique_id"]),
                "count": int(row["count"]),
            }
            for row in technique_rows
        ]

        return PersonaAnalytics(
            sessions_captured=sessions_captured,
            sessions_trend=[{"date": row["date"], "count": int(row["count"])} for row in trend_rows],
            intent_counts={str(row["key"]): int(row["count"]) for row in intent_rows},
            risk_counts={str(row["key"]): int(row["count"]) for row in risk_rows},
            top_techniques=top_techniques,
            peak_hours=[{"hour": int(row["hour"]), "count": int(row["count"])} for row in hour_rows],
            top_countries=[{"country": str(row["key"]), "count": int(row["count"])} for row in country_rows],
        )

    def aggregate_classifier_runs_by_actor_and_technique(self) -> list[dict[str, Any]]:
        """Aggregate stored classifier runs by (actor_label, MITRE technique)."""
        return _fetch_all(self.database_url, SELECT_ACTOR_MITRE_AGGREGATES_SQL, {})

    def aggregate_repeat_connections_by_peer_ip(
        self,
        *,
        window_seconds: int = 86_400,
        min_sessions: int = 5,
    ) -> dict[str, Any] | None:
        """Aggregate sessions from source IPs that reconnected repeatedly.

        A proxy signal for automated credential/access testing: this honeypot
        has no auth step to literally brute-force, so this counts repeated
        rapid connections from one peer_ip instead. Returns None if no peer_ip
        crossed the threshold within the window.
        """
        row = _fetch_one(
            self.database_url,
            SELECT_REPEAT_CONNECTION_AGGREGATE_SQL,
            {"window_seconds": window_seconds, "min_sessions": min_sessions},
        )
        if row is None or row["session_count"] == 0:
            return None
        return row

    def upsert_issue(self, issue: IssueRecord) -> IssueRecord:
        """Persist one issue and its MITRE techniques, preserving its prior status."""
        _execute_statements(self.database_url, issue_upsert_statements(issue))
        row = _fetch_one(self.database_url, SELECT_ISSUE_BY_ID_SQL, {"id": issue.id})
        mitre_rows = _fetch_all(
            self.database_url,
            SELECT_ISSUE_MITRE_TECHNIQUES_SQL,
            {"issue_ids": [issue.id]},
        )
        return issue_from_row(row, mitre_rows)

    def count_sessions_from_ip(
        self,
        peer_ip: str,
        *,
        window_seconds: int = 86_400,
    ) -> int:
        """Count sessions from a given peer IP in the last window_seconds.

        Used at store-time to populate the cross-session brute_force_bot feature.
        Not called by the stateless /classify/session endpoint by design.
        """
        row = _fetch_one(
            self.database_url,
            SELECT_SESSIONS_FROM_IP_SQL,
            {"peer_ip": peer_ip, "window_seconds": window_seconds},
        )
        return int(row["cnt"]) if row else 0

    def get_alert_config(self) -> "AlertConfigRecord | None":
        """Return the singleton global alert config, or None if never configured."""
        from classifier.storage.models import AlertConfigRecord
        row = _fetch_one(self.database_url, SELECT_ALERT_CONFIG_SQL, {})
        if row is None:
            return None
        return AlertConfigRecord(
            enabled=row["enabled"],
            smtp_host=row["smtp_host"],
            smtp_port=row["smtp_port"],
            smtp_username=row["smtp_username"],
            smtp_password_configured=bool(row["smtp_password_configured"]),
            smtp_from_email=row["smtp_from_email"],
            smtp_use_tls=row["smtp_use_tls"],
            global_min_risk_level=row["global_min_risk_level"],
            updated_at=row["updated_at"],
        )

    def upsert_alert_config(self, config: "AlertConfigInput") -> "AlertConfigRecord":
        """Persist the global alert config (password only updated if non-None)."""
        from classifier.storage.models import AlertConfigInput, AlertConfigRecord
        encrypted_password = _encrypt_alert_password(config.smtp_password)
        _execute_insert(
            self.database_url,
            UPSERT_ALERT_CONFIG_SQL,
            {
                "enabled": config.enabled,
                "smtp_host": config.smtp_host,
                "smtp_port": config.smtp_port,
                "smtp_username": config.smtp_username,
                "smtp_password": encrypted_password,
                "smtp_from_email": config.smtp_from_email,
                "smtp_use_tls": config.smtp_use_tls,
                "global_min_risk_level": config.global_min_risk_level,
            },
        )
        return self.get_alert_config() or AlertConfigRecord(
            enabled=config.enabled,
            smtp_host=config.smtp_host,
            smtp_port=config.smtp_port,
            smtp_username=config.smtp_username,
            smtp_password_configured=config.smtp_password is not None,
            smtp_from_email=config.smtp_from_email,
            smtp_use_tls=config.smtp_use_tls,
            global_min_risk_level=config.global_min_risk_level,
        )

    def insert_alert_event(self, event: "AlertEventRecord") -> "AlertEventRecord":
        """Persist one alert dispatch record."""
        _execute_insert(
            self.database_url,
            INSERT_ALERT_EVENT_SQL,
            {
                "id": event.id,
                "run_id": event.run_id,
                "session_id": event.session_id,
                "persona_id": event.persona_id,
                "risk_level": event.risk_level,
                "actor_label": event.actor_label,
                "contact_email": event.contact_email,
                "sent_at": event.sent_at,
                "success": event.success,
                "error_message": event.error_message,
            },
        )
        return event

    def list_alert_events(self, *, limit: int = 100) -> "list[AlertEventRecord]":
        """Return recent alert dispatch records, newest first."""
        from classifier.storage.models import AlertEventRecord
        rows = _fetch_all(
            self.database_url,
            SELECT_ALERT_EVENTS_SQL,
            {"limit": min(limit, 500)},
        )
        return [
            AlertEventRecord(
                id=row["id"],
                run_id=row["run_id"],
                session_id=row["session_id"],
                persona_id=row["persona_id"],
                risk_level=row["risk_level"],
                actor_label=row["actor_label"],
                contact_email=row["contact_email"],
                sent_at=row["sent_at"],
                success=row["success"],
                error_message=row["error_message"],
            )
            for row in rows
        ]


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
    from classifier.storage.geolocation import resolve_country
    session_record = record.session_record
    peer_ip = session_record.get("peer_ip")
    return {
        "id": record.session_id,
        "protocol": record.protocol,
        "peer_ip": peer_ip,
        "peer_port": session_record.get("peer_port"),
        "latitude": session_record.get("latitude"),
        "longitude": session_record.get("longitude"),
        "country": resolve_country(peer_ip),
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

    for field_name in (
        "deception_action",
        "alert_action",
        "analyst_recommendation",
    ):
        recommendation = record.summary.get(field_name)
        if recommendation is None:
            continue
        add_signal(
            field_name,
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


def issue_from_row(
    row: dict[str, Any],
    mitre_rows: list[dict[str, Any]],
) -> IssueRecord:
    """Build the storage model for one issue query result."""
    return IssueRecord(
        **row,
        mitre=[
            MitreTechnique(id=mitre_row["technique_id"], name=mitre_row["technique_name"])
            for mitre_row in mitre_rows
        ],
    )


def issue_insert_params(issue: IssueRecord) -> dict[str, Any]:
    """Return SQL parameters for upserting the parent issues row."""
    return {
        "id": issue.id,
        "title": issue.title,
        "severity": issue.severity,
        "evidence": issue.evidence,
        "recommended_fix": issue.recommended_fix,
        "impact": issue.impact,
        "session_count": issue.session_count,
        "persona_count": issue.persona_count,
        "status": issue.status,
        "created_at": issue.created_at,
    }


def issue_upsert_statements(issue: IssueRecord) -> list[tuple[str, dict[str, Any]]]:
    """Return all SQL writes needed to upsert one issue and its MITRE techniques."""
    statements = [
        (UPSERT_ISSUE_SQL, issue_insert_params(issue)),
        (DELETE_ISSUE_MITRE_TECHNIQUES_SQL, {"issue_id": issue.id}),
    ]
    statements.extend(
        (
            INSERT_ISSUE_MITRE_TECHNIQUE_SQL,
            {
                "issue_id": issue.id,
                "technique_index": index,
                "technique_id": technique.id,
                "technique_name": technique.name,
            },
        )
        for index, technique in enumerate(issue.mitre)
    )
    return statements


def _persona_config_params(record: PersonaConfigRecord) -> dict[str, Any]:
    """Return SQL parameters for inserting or updating a persona config row."""
    import json
    return {
        "id": record.id,
        "name": record.name,
        "os_banner": record.os_banner,
        "ssh_banner": record.ssh_banner,
        "hostname": record.hostname,
        "timezone": record.timezone,
        "internal_notes": record.internal_notes,
        "ssh_enabled": record.ssh_enabled,
        "ssh_port": record.ssh_port,
        "http_enabled": record.http_enabled,
        "http_port": record.http_port,
        "ftp_enabled": record.ftp_enabled,
        "ftp_port": record.ftp_port,
        "telnet_enabled": record.telnet_enabled,
        "telnet_port": record.telnet_port,
        "fake_users": list(record.fake_users),
        "running_processes": list(record.running_processes),
        "decoy_files": json.dumps([f.dict() for f in record.decoy_files]),
        "alert_routing_level": record.alert_routing_level,
        "alert_min_risk_level": record.alert_min_risk_level,
        "contact_email": record.contact_email,
        "slack_webhook": record.slack_webhook,
        "interaction_depth": record.interaction_depth,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def _persona_config_from_row(row: dict[str, Any]) -> PersonaConfigRecord:
    """Build a PersonaConfigRecord from a DB query result row."""
    raw_decoy = row.get("decoy_files") or []
    decoy_files = [DecoyFile(**f) for f in raw_decoy] if isinstance(raw_decoy, list) else []
    return PersonaConfigRecord(
        id=row["id"],
        name=row["name"],
        os_banner=row["os_banner"],
        ssh_banner=row["ssh_banner"],
        hostname=row["hostname"],
        timezone=row["timezone"],
        internal_notes=row["internal_notes"],
        ssh_enabled=row["ssh_enabled"],
        ssh_port=row["ssh_port"],
        http_enabled=row["http_enabled"],
        http_port=row["http_port"],
        ftp_enabled=row["ftp_enabled"],
        ftp_port=row["ftp_port"],
        telnet_enabled=row["telnet_enabled"],
        telnet_port=row["telnet_port"],
        fake_users=list(row["fake_users"] or []),
        running_processes=list(row["running_processes"] or []),
        decoy_files=decoy_files,
        alert_routing_level=row["alert_routing_level"],
        alert_min_risk_level=row.get("alert_min_risk_level"),
        contact_email=row["contact_email"],
        slack_webhook=row["slack_webhook"],
        interaction_depth=row["interaction_depth"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


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


def issue_list_query(
    *,
    status: str | None = None,
    limit: int = 100,
) -> tuple[str, dict[str, Any]]:
    """Return SQL and parameters for listing stored issues."""
    # Validate and clamp limit
    if not isinstance(limit, int) or limit < 1:
        raise ValueError(f"limit must be a positive integer, got {limit}")
    limit = min(limit, MAX_ISSUE_LIMIT)

    filters: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if status is not None:
        filters.append("status = %(status)s")
        params["status"] = status

    return _list_query(
        SELECT_ISSUE_BASE_SQL,
        filters,
        "session_count DESC, created_at DESC",
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


def seed_demo_issues(database_url: str) -> None:
    """Insert synthetic demo issues and MITRE mappings into a database."""
    _execute_statements(
        database_url,
        [
            (
                """
                INSERT INTO issues (
                    id, title, severity, evidence, recommended_fix, impact,
                    session_count, persona_count, status, created_at
                ) VALUES (
                    %(id)s,
                    %(title)s,
                    %(severity)s,
                    %(evidence)s,
                    %(recommended_fix)s,
                    %(impact)s,
                    %(session_count)s,
                    %(persona_count)s,
                    %(status)s,
                    NOW()
                ) ON CONFLICT (id) DO NOTHING
                """,
                {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "title": "SSH password authentication is being targeted.",
                    "severity": "high",
                    "evidence": "37 brute-force sessions across 4 personas.",
                    "recommended_fix": "Disable password login, enforce SSH keys, add rate limiting, block repeated scanner ASNs.",
                    "impact": "Reduces credential-access exposure.",
                    "session_count": 37,
                    "persona_count": 4,
                    "status": "open",
                },
            ),
            (
                """
                INSERT INTO issues (
                    id, title, severity, evidence, recommended_fix, impact,
                    session_count, persona_count, status, created_at
                ) VALUES (
                    %(id)s,
                    %(title)s,
                    %(severity)s,
                    %(evidence)s,
                    %(recommended_fix)s,
                    %(impact)s,
                    %(session_count)s,
                    %(persona_count)s,
                    %(status)s,
                    NOW()
                ) ON CONFLICT (id) DO NOTHING
                """,
                {
                    "id": "22222222-2222-4222-8222-222222222222",
                    "title": "Attackers fingerprint the system before staging payloads.",
                    "severity": "medium",
                    "evidence": "24 sessions ran whoami, uname -a, and cat /etc/passwd within the first 10 seconds across 3 personas.",
                    "recommended_fix": "Trim shell banner detail, randomize first-command response timing, and alert on rapid fingerprinting sequences.",
                    "impact": "Shortens attacker dwell time before detection.",
                    "session_count": 24,
                    "persona_count": 3,
                    "status": "open",
                },
            ),
            (
                """
                INSERT INTO issues (
                    id, title, severity, evidence, recommended_fix, impact,
                    session_count, persona_count, status, created_at
                ) VALUES (
                    %(id)s,
                    %(title)s,
                    %(severity)s,
                    %(evidence)s,
                    %(recommended_fix)s,
                    %(impact)s,
                    %(session_count)s,
                    %(persona_count)s,
                    %(status)s,
                    NOW()
                ) ON CONFLICT (id) DO NOTHING
                """,
                {
                    "id": "33333333-3333-4333-8333-333333333333",
                    "title": "Attackers plant SSH keys for persistence after login.",
                    "severity": "high",
                    "evidence": "18 sessions appended to ~/.ssh/authorized_keys across 2 personas.",
                    "recommended_fix": "Make ~/.ssh writes visibly detectable, seed decoy keys, and alert immediately on authorized_keys modification.",
                    "impact": "Closes the most common persistence path observed.",
                    "session_count": 18,
                    "persona_count": 2,
                    "status": "open",
                },
            ),
            (
                """
                INSERT INTO issues (
                    id, title, severity, evidence, recommended_fix, impact,
                    session_count, persona_count, status, created_at
                ) VALUES (
                    %(id)s,
                    %(title)s,
                    %(severity)s,
                    %(evidence)s,
                    %(recommended_fix)s,
                    %(impact)s,
                    %(session_count)s,
                    %(persona_count)s,
                    %(status)s,
                    NOW()
                ) ON CONFLICT (id) DO NOTHING
                """,
                {
                    "id": "44444444-4444-4444-8444-444444444444",
                    "title": "The same scanner ASNs revisit after short cooldowns to re-validate access.",
                    "severity": "medium",
                    "evidence": "12 sessions from 3 ASNs returned within 24 hours of a prior scan.",
                    "recommended_fix": "Throttle by ASN with an escalating cooldown and block ranges that repeatedly re-validate without new behavior.",
                    "impact": "Frees analyst attention for genuine attacker sessions.",
                    "session_count": 12,
                    "persona_count": 3,
                    "status": "closed",
                },
            ),
            (
                """
                INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES (
                    %(issue_id)s,
                    %(technique_index)s,
                    %(technique_id)s,
                    %(technique_name)s
                ) ON CONFLICT (issue_id, technique_index) DO NOTHING
                """,
                {
                    "issue_id": "11111111-1111-4111-8111-111111111111",
                    "technique_index": 0,
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                },
            ),
            (
                """
                INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES (
                    %(issue_id)s,
                    %(technique_index)s,
                    %(technique_id)s,
                    %(technique_name)s
                ) ON CONFLICT (issue_id, technique_index) DO NOTHING
                """,
                {
                    "issue_id": "11111111-1111-4111-8111-111111111111",
                    "technique_index": 1,
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                },
            ),
            (
                """
                INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES (
                    %(issue_id)s,
                    %(technique_index)s,
                    %(technique_id)s,
                    %(technique_name)s
                ) ON CONFLICT (issue_id, technique_index) DO NOTHING
                """,
                {
                    "issue_id": "22222222-2222-4222-8222-222222222222",
                    "technique_index": 0,
                    "technique_id": "T1082",
                    "technique_name": "System Information Discovery",
                },
            ),
            (
                """
                INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES (
                    %(issue_id)s,
                    %(technique_index)s,
                    %(technique_id)s,
                    %(technique_name)s
                ) ON CONFLICT (issue_id, technique_index) DO NOTHING
                """,
                {
                    "issue_id": "22222222-2222-4222-8222-222222222222",
                    "technique_index": 1,
                    "technique_id": "T1087",
                    "technique_name": "Account Discovery",
                },
            ),
            (
                """
                INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES (
                    %(issue_id)s,
                    %(technique_index)s,
                    %(technique_id)s,
                    %(technique_name)s
                ) ON CONFLICT (issue_id, technique_index) DO NOTHING
                """,
                {
                    "issue_id": "33333333-3333-4333-8333-333333333333",
                    "technique_index": 0,
                    "technique_id": "T1098.004",
                    "technique_name": "SSH Authorized Keys",
                },
            ),
            (
                """
                INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES (
                    %(issue_id)s,
                    %(technique_index)s,
                    %(technique_id)s,
                    %(technique_name)s
                ) ON CONFLICT (issue_id, technique_index) DO NOTHING
                """,
                {
                    "issue_id": "44444444-4444-4444-8444-444444444444",
                    "technique_index": 0,
                    "technique_id": "T1595",
                    "technique_name": "Active Scanning",
                },
            ),
        ],
    )


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
    return _fetch_one_with_conn(database_url, sql, params)


def _fetch_one_with_conn(
    database_url: str,
    sql: str,
    params: dict[str, Any],
    *,
    connection=None,
    cursor=None,
) -> dict[str, Any] | None:
    rows = _fetch_all_with_conn(database_url, sql, params, connection=connection, cursor=cursor)
    return rows[0] if rows else None


def _fetch_all(
    database_url: str,
    sql: str,
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    return _fetch_all_with_conn(database_url, sql, params)


def _fetch_all_with_conn(
    database_url: str,
    sql: str,
    params: dict[str, Any],
    *,
    connection=None,
    cursor=None,
) -> list[dict[str, Any]]:
    psycopg = _load_psycopg()
    # If a cursor is provided, assume caller controls lifecycle and row factory.
    if cursor is not None:
        cursor.execute(sql, params)
        return list(cursor.fetchall())

    # If a connection is provided, create a short-lived cursor using the
    # connection's row factory so multiple queries can reuse the same
    # TCP connection without reconnecting each time.
    if connection is not None:
        with connection.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    # Fallback: open a fresh connection per call (existing behavior).
    with psycopg.connect(database_url) as conn:
        with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())


def _load_psycopg():
    try:
        import psycopg
    except ModuleNotFoundError as exc:
        raise DatabaseDriverMissingError(
            "Install psycopg to use PostgreSQL storage: "
            "python -m pip install 'psycopg[binary]'"
        ) from exc

    return psycopg
