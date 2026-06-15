"""HTTP API for post-session Echidra classification."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, validator

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage import (
    ClassifyAndStoreResponse,
    DashboardUserRecord,
    DatabaseDriverMissingError,
    DatabaseNotConfiguredError,
    ManualLabelRecord,
    PostgresClassifierRepository,
    StoredClassifierRun,
)


logger = logging.getLogger(__name__)
DASHBOARD_INDEX_PATH = Path(__file__).resolve().parents[2] / "dashboard/public/index.html"
AUTH_INDEX_PATH = Path(__file__).resolve().parents[2] / "dashboard/public/auth.html"
ASSETS_PATH = Path(__file__).resolve().parents[2] / "assets"
DASHBOARD_SESSION_SECRET_ENV = "ECHIDRA_SESSION_SECRET"
DASHBOARD_COOKIE_SECURE_ENV = "ECHIDRA_COOKIE_SECURE"
DASHBOARD_AUTH_COOKIE = "echidra_dashboard_auth"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 8
PASSWORD_HASH_ITERATIONS = 390_000
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128
_DEFAULT_SESSION_SECRET = secrets.token_urlsafe(32)
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


class DashboardSignupInput(BaseModel):
    """Browser-submitted dashboard signup credentials."""

    email: str
    password: str

    @validator("email")
    def validate_email(cls, value: str) -> str:
        return _validate_email_format(value)

    @validator("password")
    def validate_password(cls, value: str) -> str:
        _validate_password_format(value)
        return value

    class Config:
        extra = "forbid"


class DashboardLoginInput(BaseModel):
    """Browser-submitted dashboard login credentials."""

    email: str
    password: str

    @validator("email")
    def validate_email(cls, value: str) -> str:
        return _validate_email_format(value)

    @validator("password")
    def validate_password(cls, value: str) -> str:
        _validate_password_format(value)
        return value

    class Config:
        extra = "forbid"


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

    @api.get("/assets/{filename}", response_class=FileResponse, tags=["dashboard"])
    def dashboard_asset(filename: str) -> FileResponse:
        """Serve whitelisted dashboard image assets."""
        if filename not in {"Qyleron_Banner.png", "qyleron_logo.png"}:
            raise HTTPException(status_code=404, detail="asset not found")
        path = ASSETS_PATH / filename
        if not path.exists():
            raise HTTPException(status_code=404, detail="asset not found")
        return FileResponse(path)

    @api.get("/auth", response_class=FileResponse, tags=["dashboard"])
    def auth_page() -> FileResponse:
        """Serve the dashboard access page."""
        if not AUTH_INDEX_PATH.exists():
            raise HTTPException(status_code=404, detail="auth page not found")
        return FileResponse(AUTH_INDEX_PATH, media_type="text/html")

    @api.post("/auth/signup", tags=["dashboard"])
    def signup_dashboard_user(
        payload: DashboardSignupInput,
        response: Response,
    ) -> dict[str, str | bool]:
        """Create a dashboard user and set the auth cookie."""
        try:
            repository = PostgresClassifierRepository()
            existing_user = repository.get_dashboard_user_by_email(payload.email)
            if existing_user is not None:
                raise HTTPException(status_code=409, detail="email already registered")
            user = repository.create_dashboard_user(
                email=payload.email,
                password_hash=_hash_password(payload.password),
            )
        except HTTPException:
            raise
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in signup_dashboard_user: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        _set_dashboard_session_cookie(response, user)
        return {"authenticated": True, "email": user.email}

    @api.post("/auth/login", tags=["dashboard"])
    def login_dashboard_user(
        payload: DashboardLoginInput,
        response: Response,
    ) -> dict[str, str | bool]:
        """Verify dashboard credentials and set the auth cookie."""
        try:
            repository = PostgresClassifierRepository()
            user = repository.get_dashboard_user_by_email(payload.email)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in login_dashboard_user: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if user is None or not _verify_password(payload.password, user.password_hash):
            raise HTTPException(status_code=401, detail="invalid email or password")

        _set_dashboard_session_cookie(response, user)
        return {"authenticated": True, "email": user.email}

    @api.post("/auth/logout", tags=["dashboard"])
    def logout_dashboard(response: Response) -> dict[str, bool]:
        """Clear the dashboard auth cookie."""
        response.delete_cookie(DASHBOARD_AUTH_COOKIE)
        return {"authenticated": False}

    @api.get("/dashboard", response_class=FileResponse, tags=["dashboard"])
    def dashboard(request: Request) -> Response:
        """Serve the local analyst dashboard shell."""
        if not _dashboard_request_is_authenticated(request):
            return RedirectResponse("/auth", status_code=303)
        if not DASHBOARD_INDEX_PATH.exists():
            raise HTTPException(status_code=404, detail="dashboard not found")
        return FileResponse(DASHBOARD_INDEX_PATH, media_type="text/html")

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
        request: Request,
        session_id: UUID | None = None,
        risk_level: str | None = None,
        actor_label: str | None = None,
        persona_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[StoredClassifierRun]:
        """Return stored classifier runs matching optional exact filters."""
        _require_dashboard_auth(request)
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
    def get_classifier_run_endpoint(
        run_id: UUID,
        request: Request,
    ) -> StoredClassifierRun:
        """Return one stored classifier run by ID."""
        _require_dashboard_auth(request)
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
        request: Request,
        session_id: UUID | None = None,
        classifier_run_id: UUID | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[ManualLabelRecord]:
        """Return stored manual labels matching optional exact filters."""
        _require_dashboard_auth(request)
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
    def get_manual_label_endpoint(
        label_id: UUID,
        request: Request,
    ) -> ManualLabelRecord:
        """Return one stored manual analyst label by ID."""
        _require_dashboard_auth(request)
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


def _dashboard_request_is_authenticated(request: Request) -> bool:
    cookie_value = request.cookies.get(DASHBOARD_AUTH_COOKIE)
    if cookie_value is None:
        return False
    return _verify_dashboard_session_cookie(cookie_value)


def _require_dashboard_auth(request: Request) -> None:
    if not _dashboard_request_is_authenticated(request):
        raise HTTPException(status_code=401, detail="dashboard auth required")


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _validate_email_format(value: str) -> str:
    normalized = _normalize_email(value)
    if (
        len(normalized) > MAX_EMAIL_LENGTH
        or not _EMAIL_RE.fullmatch(normalized)
        or normalized.startswith(".")
        or ".." in normalized
    ):
        raise ValueError("valid email address required")
    local_part, domain = normalized.rsplit("@", 1)
    if (
        len(local_part) > 64
        or local_part.endswith(".")
        or any(label.startswith("-") or label.endswith("-") for label in domain.split("."))
    ):
        raise ValueError("valid email address required")
    return normalized


def _validate_password_format(value: str) -> None:
    if len(value) < 8:
        raise ValueError("password must be at least 8 characters")
    if len(value) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    if any(character.isspace() for character in value):
        raise ValueError("password must not contain whitespace")
    if not re.search(r"[A-Za-z]", value):
        raise ValueError("password must contain a letter")
    if not re.search(r"\d", value):
        raise ValueError("password must contain a number")


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt}${digest}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, digest = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        ).hex()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(candidate, digest)


def _dashboard_session_secret() -> str:
    return os.getenv(DASHBOARD_SESSION_SECRET_ENV) or _DEFAULT_SESSION_SECRET


def _set_dashboard_session_cookie(
    response: Response,
    user: DashboardUserRecord,
) -> None:
    response.set_cookie(
        DASHBOARD_AUTH_COOKIE,
        _dashboard_session_cookie_value(user),
        httponly=True,
        samesite="lax",
        secure=_dashboard_cookie_secure(),
        max_age=SESSION_MAX_AGE_SECONDS,
    )


def _dashboard_session_cookie_value(user: DashboardUserRecord) -> str:
    payload = f"{user.id}:{user.email}:{int(time.time())}"
    signature = hmac.new(
        _dashboard_session_secret().encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}:{signature}"


def _verify_dashboard_session_cookie(value: str) -> bool:
    try:
        payload, signature = value.rsplit(":", 1)
        UUID(payload.split(":", 1)[0])
        issued_at = int(payload.rsplit(":", 1)[1])
    except (TypeError, ValueError, IndexError):
        return False
    expected_signature = hmac.new(
        _dashboard_session_secret().encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    age = int(time.time()) - issued_at
    return (
        0 <= age <= SESSION_MAX_AGE_SECONDS
        and hmac.compare_digest(signature, expected_signature)
    )


def _dashboard_cookie_secure() -> bool:
    return os.getenv(DASHBOARD_COOKIE_SECURE_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


app = create_app()
