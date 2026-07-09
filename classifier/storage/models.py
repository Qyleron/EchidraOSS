"""Storage contracts for classifier runs and manual analyst labels."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator

from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _model_dict(model: BaseModel) -> dict[str, Any]:
    return json.loads(model.json())


class ClassifierRunRecord(BaseModel):
    """One persisted classifier run with searchable summary columns."""

    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    protocol: str
    persona_id: str
    actor_label: str | None
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    behavior_stage: str
    intent: str
    classification_status: str
    insufficient_data_reason: str | None
    classifier_version: str
    rules_version: str
    matched_rule_ids: list[str]
    mitre_tags: list[str]
    session_record: dict[str, Any]
    summary: dict[str, Any]
    created_at: datetime = Field(default_factory=_utc_now)

    @classmethod
    def from_session_summary(
        cls,
        session: SessionRecord,
        summary: ClassificationSummary,
        run_id: UUID | None = None,
    ) -> "ClassifierRunRecord":
        """Build the database record for one validated classification result."""
        return cls(
            id=run_id or uuid4(),
            session_id=session.session_id,
            protocol=session.protocol,
            persona_id=session.persona_id,
            actor_label=summary.actor_label,
            confidence=summary.confidence,
            risk_score=summary.risk_score,
            risk_level=summary.risk_level,
            behavior_stage=summary.behavior_stage,
            intent=summary.intent,
            classification_status=summary.classification_status,
            insufficient_data_reason=summary.insufficient_data_reason,
            classifier_version=summary.classifier_version,
            rules_version=summary.rules_version,
            matched_rule_ids=list(summary.matched_rule_ids),
            mitre_tags=list(summary.mitre_tags),
            session_record=_model_dict(session),
            summary=_model_dict(summary),
        )

    class Config:
        extra = "forbid"


class ManualLabelInput(BaseModel):
    """Analyst-supplied label data for a session or classifier run."""

    session_id: UUID
    classifier_run_id: UUID | None = None
    actor_label: str | None = None
    risk_level: str | None = None
    behavior_stage: str | None = None
    intent: str | None = None
    notes: str | None = None
    labeled_by: str | None = None

    class Config:
        extra = "forbid"


class ManualLabelRecord(ManualLabelInput):
    """One persisted manual analyst label."""

    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=_utc_now)


class DashboardUserRecord(BaseModel):
    """One dashboard user allowed to access persisted classifier data."""

    id: UUID = Field(default_factory=uuid4)
    email: str
    password_hash: str
    created_at: datetime = Field(default_factory=_utc_now)

    class Config:
        extra = "forbid"


class StoredClassifierSignal(BaseModel):
    """One persisted classifier signal attached to a stored run."""

    signal_index: int = Field(ge=0)
    signal_type: str
    signal_key: str
    signal_value: str

    class Config:
        extra = "forbid"


class StoredSessionEvent(BaseModel):
    """One persisted command or decoy-file-access event for a session."""

    event_index: int = Field(ge=0)
    event_type: str
    event_value: str
    observed_at: float | None = None

    class Config:
        extra = "forbid"


class StoredClassifierRun(BaseModel):
    """Readable storage view for one classifier run and its parent session."""

    id: UUID
    session_id: UUID
    protocol: str
    peer_ip: str | None = None
    peer_port: int | None = None
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    country: str | None = None
    persona_id: str
    started_at: float
    ended_at: float
    end_reason: str
    actor_label: str | None = None
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    behavior_stage: str
    intent: str
    classification_status: str = "complete"
    insufficient_data_reason: str | None = None
    signals: list[StoredClassifierSignal] = Field(default_factory=list)

    class Config:
        extra = "forbid"


class DashboardReportSummary(BaseModel):
    """Database-wide aggregate values for the analyst dashboard."""

    total_runs: int = Field(ge=0)
    elevated_runs: int = Field(ge=0)
    distinct_personas: int = Field(ge=0)
    manual_labels: int = Field(ge=0)
    average_risk_score: float = Field(ge=0, le=100)
    risk_counts: dict[str, int] = Field(default_factory=dict)
    actor_counts: dict[str, int] = Field(default_factory=dict)
    intent_counts: dict[str, int] = Field(default_factory=dict)

    class Config:
        extra = "forbid"


class ClassifyAndStoreResponse(BaseModel):
    """API response for classify-and-store requests."""

    run_id: UUID
    summary: ClassificationSummary

    class Config:
        extra = "forbid"


ISSUE_SEVERITIES = {"high", "medium", "low"}
ISSUE_STATUSES = {"open", "closed"}


class MitreTechnique(BaseModel):
    """One MITRE ATT&CK technique referenced by a detected issue."""

    id: str
    name: str

    class Config:
        extra = "forbid"


class IssueRecord(BaseModel):
    """One persisted issue detected from recurring attacker behavior."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    severity: str
    evidence: str
    recommended_fix: str
    impact: str
    session_count: int = Field(ge=0)
    persona_count: int = Field(ge=0)
    status: str = "open"
    mitre: list[MitreTechnique] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utc_now)

    @validator("severity")
    def validate_severity(cls, value: str) -> str:
        if value not in ISSUE_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(ISSUE_SEVERITIES)}")
        return value

    @validator("status")
    def validate_status(cls, value: str) -> str:
        if value not in ISSUE_STATUSES:
            raise ValueError(f"status must be one of {sorted(ISSUE_STATUSES)}")
        return value

    class Config:
        extra = "forbid"


class IssueStatusUpdate(BaseModel):
    """Analyst-submitted status change for one issue."""

    status: str

    @validator("status")
    def validate_status(cls, value: str) -> str:
        if value not in ISSUE_STATUSES:
            raise ValueError(f"status must be one of {sorted(ISSUE_STATUSES)}")
        return value

    class Config:
        extra = "forbid"


PERSONA_ALERT_ROUTING_LEVELS = {"none", "email", "slack", "both"}
PERSONA_INTERACTION_DEPTHS = {"minimal", "standard", "deep"}
RISK_LEVELS_ORDERED = ("critical", "high", "medium", "low")


class DecoyFile(BaseModel):
    """One fake file path and content stored in a persona config."""

    path: str
    content: str

    class Config:
        extra = "forbid"


class PersonaConfigInput(BaseModel):
    """Analyst-submitted configuration for one honeypot persona."""

    name: str
    os_banner: str = ""
    ssh_banner: str = ""
    hostname: str = ""
    timezone: str = "UTC"
    internal_notes: str = ""
    ssh_enabled: bool = False
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    http_enabled: bool = False
    http_port: int | None = Field(default=None, ge=1, le=65535)
    ftp_enabled: bool = False
    ftp_port: int | None = Field(default=None, ge=1, le=65535)
    telnet_enabled: bool = False
    telnet_port: int | None = Field(default=None, ge=1, le=65535)
    fake_users: list[str] = Field(default_factory=list)
    running_processes: list[str] = Field(default_factory=list)
    decoy_files: list[DecoyFile] = Field(default_factory=list)
    alert_routing_level: str = "none"
    alert_min_risk_level: str | None = None
    contact_email: str | None = None
    slack_webhook: str | None = None
    interaction_depth: str = "minimal"
    @validator("alert_routing_level")
    def validate_routing(cls, value: str) -> str:
        if value not in PERSONA_ALERT_ROUTING_LEVELS:
            raise ValueError(
                f"alert_routing_level must be one of {sorted(PERSONA_ALERT_ROUTING_LEVELS)}"
            )
        return value

    @validator("alert_min_risk_level")
    def validate_alert_min_risk_level(cls, value: str | None) -> str | None:
        if value is not None and value not in RISK_LEVELS_ORDERED:
            raise ValueError(
                f"alert_min_risk_level must be one of {list(RISK_LEVELS_ORDERED)} or null"
            )
        return value

    @validator("interaction_depth")
    def validate_depth(cls, value: str) -> str:
        if value not in PERSONA_INTERACTION_DEPTHS:
            raise ValueError(
                f"interaction_depth must be one of {sorted(PERSONA_INTERACTION_DEPTHS)}"
            )
        return value

    class Config:
        extra = "forbid"


class PersonaConfigRecord(PersonaConfigInput):
    """One persisted persona configuration row."""

    id: str
    created_at: datetime = Field(default_factory=_utc_now)
    updated_at: datetime = Field(default_factory=_utc_now)


class PersonaAnalytics(BaseModel):
    """Aggregated session analytics for one persona ID."""

    sessions_captured: int = Field(ge=0)
    sessions_trend: list[dict[str, Any]] = Field(default_factory=list)
    intent_counts: dict[str, int] = Field(default_factory=dict)
    risk_counts: dict[str, int] = Field(default_factory=dict)
    top_techniques: list[dict[str, Any]] = Field(default_factory=list)
    peak_hours: list[dict[str, Any]] = Field(default_factory=list)
    top_countries: list[dict[str, Any]] = Field(default_factory=list)

    class Config:
        extra = "forbid"


class AnalyticsSummary(BaseModel):
    """Aggregated session/classifier analytics across all personas for one
    date range, backing the Analytics dashboard page."""

    intent_counts: dict[str, int] = Field(default_factory=dict)
    attacks_by_hour: dict[str, int] = Field(default_factory=dict)
    risk_trend: list[dict[str, Any]] = Field(default_factory=list)
    top_commands: list[dict[str, Any]] = Field(default_factory=list)
    top_personas: list[dict[str, Any]] = Field(default_factory=list)
    top_countries: list[dict[str, Any]] = Field(default_factory=list)

    class Config:
        extra = "forbid"


class AlertConfigInput(BaseModel):
    """Analyst-submitted global SMTP alert configuration."""

    enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_use_tls: bool = True
    global_min_risk_level: str = "high"

    @validator("global_min_risk_level")
    def validate_global_min_risk_level(cls, value: str) -> str:
        if value not in RISK_LEVELS_ORDERED:
            raise ValueError(
                f"global_min_risk_level must be one of {list(RISK_LEVELS_ORDERED)}"
            )
        return value

    class Config:
        extra = "forbid"


class AlertConfigRecord(BaseModel):
    """Persisted global SMTP alert configuration (password never returned)."""

    enabled: bool
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password_configured: bool
    smtp_from_email: str | None
    smtp_use_tls: bool
    global_min_risk_level: str
    updated_at: datetime = Field(default_factory=_utc_now)

    class Config:
        extra = "forbid"


class AlertEventRecord(BaseModel):
    """One persisted record of an attempted alert dispatch (email or Slack)."""

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID | None = None
    session_id: UUID | None = None
    persona_id: str
    risk_level: str
    actor_label: str | None = None
    channel: str = "email"
    contact_email: str | None = None
    sent_at: datetime = Field(default_factory=_utc_now)
    success: bool
    error_message: str | None = None

    class Config:
        extra = "forbid"
