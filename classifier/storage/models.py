"""Storage contracts for classifier runs and manual analyst labels."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

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


class ClassifyAndStoreResponse(BaseModel):
    """API response for classify-and-store requests."""

    run_id: UUID
    summary: ClassificationSummary

    class Config:
        extra = "forbid"
