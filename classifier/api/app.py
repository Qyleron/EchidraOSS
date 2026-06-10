"""HTTP API for post-session Echidra classification."""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage import (
    ClassifyAndStoreResponse,
    DatabaseDriverMissingError,
    DatabaseNotConfiguredError,
    ManualLabelRecord,
    PostgresClassifierRepository,
    StoredClassifierRun,
)


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create the FastAPI application for classifier consumers."""
    api = FastAPI(
        title="Echidra Classifier API",
        version="1.0.0",
        description="Post-session behavioral classification for Echidra logs.",
    )

    @api.get("/health", tags=["service"])
    def health() -> dict[str, str]:
        """Report whether the classifier API process is serving requests."""
        return {"status": "ok"}

    @api.post(
        "/classify/session",
        response_model=ClassificationSummary,
        tags=["classifier"],
    )
    def classify_session_endpoint(session: SessionRecord) -> ClassificationSummary:
        """Classify one completed session record."""
        return _classify_or_http_error(session)

    @api.post(
        "/classify/session/store",
        response_model=ClassifyAndStoreResponse,
        tags=["classifier"],
    )
    def classify_and_store_session_endpoint(
        session: SessionRecord,
    ) -> ClassifyAndStoreResponse:
        """Classify one session and persist the classifier run."""
        summary = _classify_or_http_error(session)
        try:
            repository = PostgresClassifierRepository()
            run = repository.save_classifier_run(session, summary)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in classify_and_store_session_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

        return ClassifyAndStoreResponse(run_id=run.id, summary=summary)

    @api.get(
        "/classifier/runs",
        response_model=list[StoredClassifierRun],
        tags=["storage"],
    )
    def list_classifier_runs_endpoint(
        session_id: UUID | None = None,
        risk_level: str | None = None,
        actor_label: str | None = None,
        persona_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[StoredClassifierRun]:
        """Return stored classifier runs matching optional exact filters."""
        try:
            repository = PostgresClassifierRepository()
            return repository.list_classifier_runs(
                session_id=session_id,
                risk_level=risk_level,
                actor_label=actor_label,
                persona_id=persona_id,
                limit=limit,
            )
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in list_classifier_runs_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

    @api.get(
        "/classifier/runs/{run_id}",
        response_model=StoredClassifierRun,
        tags=["storage"],
    )
    def get_classifier_run_endpoint(run_id: UUID) -> StoredClassifierRun:
        """Return one stored classifier run by ID."""
        try:
            repository = PostgresClassifierRepository()
            run = repository.get_classifier_run(run_id)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in get_classifier_run_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

        if run is None:
            raise HTTPException(status_code=404, detail="classifier run not found")
        return run

    @api.get(
        "/manual-labels",
        response_model=list[ManualLabelRecord],
        tags=["storage"],
    )
    def list_manual_labels_endpoint(
        session_id: UUID | None = None,
        classifier_run_id: UUID | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[ManualLabelRecord]:
        """Return stored manual labels matching optional exact filters."""
        try:
            repository = PostgresClassifierRepository()
            return repository.list_manual_labels(
                session_id=session_id,
                classifier_run_id=classifier_run_id,
                limit=limit,
            )
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in list_manual_labels_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

    @api.get(
        "/manual-labels/{label_id}",
        response_model=ManualLabelRecord,
        tags=["storage"],
    )
    def get_manual_label_endpoint(label_id: UUID) -> ManualLabelRecord:
        """Return one stored manual analyst label by ID."""
        try:
            repository = PostgresClassifierRepository()
            label = repository.get_manual_label(label_id)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in get_manual_label_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

        if label is None:
            raise HTTPException(status_code=404, detail="manual label not found")
        return label

    return api


def _classify_or_http_error(session: SessionRecord) -> ClassificationSummary:
    """Run classification and map pipeline failures to HTTP errors."""
    try:
        return classify_session(session)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc) or "validation error",
        )
    except Exception as exc:
        logger.exception("Unhandled exception in classify_session_endpoint: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="internal server error",
        )


app = create_app()
