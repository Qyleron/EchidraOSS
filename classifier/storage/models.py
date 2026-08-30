"""Storage contracts for classifier runs and manual analyst labels."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _model_dict(model: BaseModel) -> dict[str, Any]:
    return json.loads(model.model_dump_json())


# Mirrors classifier.scoring.session.ClassificationStatus (a Literal there,
# enforced by pydantic on ClassificationSummary already) -- classification_status
# is a plain str on the storage models below since ClassifierRunRecord and
# StoredClassifierRun are also built from raw DB rows / direct construction,
# not only from an already-validated ClassificationSummary.
CLASSIFICATION_STATUSES = {"complete", "partial", "insufficient_data"}
CLASSIFICATION_STATUS_LABELS = {
    "complete": "Complete",
    "partial": "Partial",
    "insufficient_data": "Insufficient data",
}


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

    @field_validator("classification_status")
    @classmethod
    def validate_classification_status(cls, value: str) -> str:
        if value not in CLASSIFICATION_STATUSES:
            raise ValueError(
                "Classification status must be one of "
                f"{_option_labels(CLASSIFICATION_STATUSES, CLASSIFICATION_STATUS_LABELS)}"
            )
        return value

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

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


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
    session_version: int = 1

    model_config = ConfigDict(extra="forbid")


class StoredClassifierSignal(BaseModel):
    """One persisted classifier signal attached to a stored run."""

    signal_index: int = Field(ge=0)
    signal_type: str
    signal_key: str
    signal_value: str

    model_config = ConfigDict(extra="forbid")


class StoredSessionEvent(BaseModel):
    """One persisted command or decoy-file-access event for a session."""

    event_index: int = Field(ge=0)
    event_type: str
    event_value: str
    observed_at: float | None = None

    model_config = ConfigDict(extra="forbid")


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

    @field_validator("classification_status")
    @classmethod
    def validate_classification_status(cls, value: str) -> str:
        if value not in CLASSIFICATION_STATUSES:
            raise ValueError(
                "Classification status must be one of "
                f"{_option_labels(CLASSIFICATION_STATUSES, CLASSIFICATION_STATUS_LABELS)}"
            )
        return value

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


class ClassifyAndStoreResponse(BaseModel):
    """API response for classify-and-store requests."""

    run_id: UUID
    summary: ClassificationSummary

    model_config = ConfigDict(extra="forbid")


ISSUE_SEVERITIES = {"high", "medium", "low"}
ISSUE_SEVERITY_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
ISSUE_STATUSES = {"open", "closed"}
ISSUE_STATUS_LABELS = {
    "open": "Open",
    "closed": "Closed",
}


class MitreTechnique(BaseModel):
    """One MITRE ATT&CK technique referenced by a detected issue."""

    id: str
    name: str

    model_config = ConfigDict(extra="forbid")


class LinkedIssueSummary(BaseModel):
    """One issue a given session was aggregated into -- the reverse of
    IssueRecord.session_ids, used for the Sessions-side "linked issue" badge
    without pulling in an issue's full evidence/fix/impact text."""

    id: UUID
    title: str
    severity: str
    status: str

    model_config = ConfigDict(extra="forbid")


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
    actor_label: str | None = None
    mitre: list[MitreTechnique] = Field(default_factory=list)
    # The exact sessions aggregated into this issue (see issue_sessions in
    # schema.sql) -- lets the dashboard link straight to one specific
    # session instead of only a bare session_count.
    session_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utc_now)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in ISSUE_SEVERITIES:
            raise ValueError(
                f"Severity must be one of {_option_labels(ISSUE_SEVERITIES, ISSUE_SEVERITY_LABELS)}"
            )
        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in ISSUE_STATUSES:
            raise ValueError(
                f"Status must be one of {_option_labels(ISSUE_STATUSES, ISSUE_STATUS_LABELS)}"
            )
        return value

    model_config = ConfigDict(extra="forbid")


class IssueStatusUpdate(BaseModel):
    """Analyst-submitted status change for one issue."""

    status: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in ISSUE_STATUSES:
            raise ValueError(
                f"Status must be one of {_option_labels(ISSUE_STATUSES, ISSUE_STATUS_LABELS)}"
            )
        return value

    model_config = ConfigDict(extra="forbid")


PERSONA_ALERT_ROUTING_LEVELS = {"none", "email", "slack", "both"}
PERSONA_ALERT_ROUTING_LABELS = {
    "none": "None",
    "email": "Email",
    "slack": "Slack",
    "both": "Both",
}
# The fake web server the HTTP listener presents for this persona -- an
# explicit operator choice, decoupled from running_processes (which stays
# free text purely for the fake `ps` output over the SSH shell, and is
# never read by the HTTP handler). "none" means the HTTP listener rejects
# every request for this persona instead of risking a page that
# contradicts what running_processes/hostname claim about it. Single
# source of truth with honeypot/network/http_handler.py's _server_kind().
PERSONA_HTTP_SERVER_TYPES = {"nginx", "apache", "busybox", "none"}
PERSONA_HTTP_SERVER_TYPE_LABELS = {
    "nginx": "Nginx",
    "apache": "Apache",
    "busybox": "BusyBox",
    "none": "None",
}
RISK_LEVELS_ORDERED = ("critical", "high", "medium", "low")
RISK_LEVEL_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# Same pattern as classifier/api/app.py's _EMAIL_RE -- duplicated rather than
# imported since models.py sits below app.py in the dependency direction.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def _option_labels(values: set[str] | tuple[str, ...], labels: dict[str, str]) -> str:
    """Render values as a comma-separated label list for a validation message.

    A set has no meaningful order, so those are alphabetized by label for a
    deterministic, readable message. A tuple/list (eg. RISK_LEVELS_ORDERED)
    is deliberately pre-ordered by the caller (severity rank, not alphabetical)
    -- alphabetizing it too would silently scramble that order.
    """
    ordered = sorted(values, key=lambda value: labels[value]) if isinstance(values, set) else values
    return ", ".join(labels[value] for value in ordered)


class DecoyFile(BaseModel):
    """One fake file path and content stored in a persona config."""

    path: str = Field(min_length=1, max_length=256)
    content: str = Field(max_length=65_536)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or ".." in PurePosixPath(value).parts:
            raise ValueError("Decoy file path must be a safe absolute path")
        return value

    model_config = ConfigDict(extra="forbid")


class PersonaConfigInput(BaseModel):
    """Analyst-submitted configuration for one honeypot persona."""

    name: str = Field(min_length=1, max_length=100)
    os_banner: str = Field(default="", max_length=256)
    ssh_banner: str = Field(default="", max_length=256)
    hostname: str = Field(default="", max_length=253)
    internal_notes: str = Field(default="", max_length=4_000)
    fake_users: list[str] = Field(default_factory=list, max_length=100)
    running_processes: list[str] = Field(default_factory=list, max_length=100)
    http_server_type: str = "nginx"
    decoy_files: list[DecoyFile] = Field(default_factory=list, max_length=50)
    alert_routing_level: str = "none"
    alert_min_risk_level: str | None = None
    contact_email: str | None = Field(default=None, max_length=254)
    slack_webhook: str | None = Field(default=None, max_length=512)

    @field_validator("fake_users", "running_processes")
    @classmethod
    def validate_list_item_length(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.strip():
                raise ValueError("Entries cannot be blank")
            if len(item) > 128:
                raise ValueError("Entries must be 128 characters or fewer")
        return value

    @field_validator("decoy_files")
    @classmethod
    def validate_decoy_files_unique(cls, value: list[DecoyFile]) -> list[DecoyFile]:
        paths = [f.path for f in value]
        if len(paths) != len(set(paths)):
            raise ValueError("Decoy files cannot contain duplicate paths")
        return value

    @field_validator("http_server_type")
    @classmethod
    def validate_http_server_type(cls, value: str) -> str:
        if value not in PERSONA_HTTP_SERVER_TYPES:
            raise ValueError(
                "HTTP server type must be one of "
                f"{_option_labels(PERSONA_HTTP_SERVER_TYPES, PERSONA_HTTP_SERVER_TYPE_LABELS)}"
            )
        return value

    @field_validator("alert_routing_level")
    @classmethod
    def validate_routing(cls, value: str) -> str:
        if value not in PERSONA_ALERT_ROUTING_LEVELS:
            raise ValueError(
                "Alert routing level must be one of "
                f"{_option_labels(PERSONA_ALERT_ROUTING_LEVELS, PERSONA_ALERT_ROUTING_LABELS)}"
            )
        return value

    @field_validator("alert_min_risk_level")
    @classmethod
    def validate_alert_min_risk_level(cls, value: str | None) -> str | None:
        if value is not None and value not in RISK_LEVELS_ORDERED:
            raise ValueError(
                "Alert minimum risk level must be one of "
                f"{_option_labels(RISK_LEVELS_ORDERED, RISK_LEVEL_LABELS)} or empty"
            )
        return value

    @field_validator("contact_email")
    @classmethod
    def validate_contact_email(cls, value: str | None) -> str | None:
        if value is not None and not _EMAIL_RE.match(value):
            raise ValueError("Contact email must be a valid email address")
        return value

    @field_validator("slack_webhook")
    @classmethod
    def validate_slack_webhook(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("https://hooks.slack.com/"):
            raise ValueError("Slack webhook must be an https://hooks.slack.com/ URL")
        return value

    @model_validator(mode="after")
    def validate_cross_field_requirements(self) -> "PersonaConfigInput":
        if self.alert_routing_level in ("email", "both") and not self.contact_email:
            raise ValueError("Contact email is required when alert routing includes email")
        if self.alert_routing_level in ("slack", "both") and not self.slack_webhook:
            raise ValueError("Slack webhook is required when alert routing includes Slack")

        return self

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")


class AnalyticsSummary(BaseModel):
    """Aggregated session/classifier analytics across all personas for one
    date range, backing the Analytics dashboard page."""

    intent_counts: dict[str, int] = Field(default_factory=dict)
    attacks_by_hour: dict[str, int] = Field(default_factory=dict)
    risk_trend: list[dict[str, Any]] = Field(default_factory=list)
    # "day" (range <= 31 days), "week" (<= 180 days), or "month" (beyond
    # that) -- tells the frontend how to label risk_trend's date buckets,
    # which stop being one-per-calendar-day once the range widens.
    risk_trend_bucket: str = "day"
    top_commands: list[dict[str, Any]] = Field(default_factory=list)
    top_personas: list[dict[str, Any]] = Field(default_factory=list)
    top_countries: list[dict[str, Any]] = Field(default_factory=list)
    protocol_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    avg_dwell_seconds: float | None = None

    model_config = ConfigDict(extra="forbid")


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
    excluded_ips: str | None = Field(default=None, max_length=4_000)

    @field_validator("global_min_risk_level")
    @classmethod
    def validate_global_min_risk_level(cls, value: str) -> str:
        if value not in RISK_LEVELS_ORDERED:
            raise ValueError(
                "Global minimum risk level must be one of "
                f"{_option_labels(RISK_LEVELS_ORDERED, RISK_LEVEL_LABELS)}"
            )
        return value

    model_config = ConfigDict(extra="forbid")


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
    excluded_ips: str | None = None
    updated_at: datetime = Field(default_factory=_utc_now)

    model_config = ConfigDict(extra="forbid")


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

    model_config = ConfigDict(extra="forbid")
