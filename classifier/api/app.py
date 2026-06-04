"""HTTP API for post-session Echidra classification."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary


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
        try:
            return classify_session(session)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc) or "validation error",
            )
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="internal server error",
            )

    return api


app = create_app()
