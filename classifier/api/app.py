"""HTTP API for post-session Echidra classification."""

from __future__ import annotations

import email.mime.multipart
import email.mime.text
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import ssl
import time
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, validator

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.alerts import _maybe_send_alert
from classifier.storage import (
    AlertConfigInput,
    AlertConfigRecord,
    AlertEventRecord,
    ClassifierRunRecord,
    ClassifyAndStoreResponse,
    DashboardReportSummary,
    DashboardUserRecord,
    DatabaseDriverMissingError,
    DatabaseNotConfiguredError,
    IssueRecord,
    IssueStatusUpdate,
    ManualLabelRecord,
    PersonaAnalytics,
    PersonaConfigInput,
    PersonaConfigRecord,
    PostgresClassifierRepository,
    StoredClassifierRun,
)
from honeypot.core.persona import PRESET_PERSONAS, Persona


logger = logging.getLogger(__name__)
DASHBOARD_PUBLIC_PATH = Path(__file__).resolve().parents[2] / "dashboard/public"
DASHBOARD_INDEX_PATH = DASHBOARD_PUBLIC_PATH / "index.html"
AUTH_INDEX_PATH = DASHBOARD_PUBLIC_PATH / "auth.html"
DASHBOARD_CSS_PATH = DASHBOARD_PUBLIC_PATH / "dashboard.css"
ASSETS_PATH = Path(__file__).resolve().parents[2] / "assets"
DASHBOARD_PAGE_FILES = {
    "sessions": DASHBOARD_PUBLIC_PATH / "sessions.html",
    "analytics": DASHBOARD_PUBLIC_PATH / "analytics.html",
    "intelligence": DASHBOARD_PUBLIC_PATH / "intelligence.html",
    "personas": DASHBOARD_PUBLIC_PATH / "personas.html",
    "alerts": DASHBOARD_PUBLIC_PATH / "alerts.html",
}
DASHBOARD_SESSION_SECRET_ENV = "ECHIDRA_SESSION_SECRET"
DASHBOARD_COOKIE_SECURE_ENV = "ECHIDRA_COOKIE_SECURE"
DASHBOARD_AUTH_COOKIE = "echidra_dashboard_auth"
INGEST_API_KEY_ENV = "ECHIDRA_INGEST_API_KEY"
INGEST_API_KEY_HEADER = "x-api-key"
ALLOW_SIGNUPS_ENV = "ECHIDRA_ALLOW_SIGNUPS"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7
PASSWORD_HASH_ITERATIONS = 390_000
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128
_FALLBACK_SESSION_SECRET_PATH = (
    Path(__file__).resolve().parents[2] / "logs" / ".dashboard_session_secret"
)
_fallback_session_secret: str | None = None
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


class DashboardPersonaFile(BaseModel):
    """One fake persona file exposed to the dashboard."""

    path: str
    content: str

    class Config:
        extra = "forbid"


class DashboardPersonaCredential(BaseModel):
    """One decoy credential exposed to the dashboard."""

    username: str
    password: str

    class Config:
        extra = "forbid"


class DashboardPersonaPreset(BaseModel):
    """One available honeypot persona preset for dashboard configuration."""

    persona_id: str
    os_banner: str
    ssh_banner: str
    hostname: str
    uname_output: str
    timezone: str
    username: str
    home_dir: str
    running_processes: list[str]
    fake_users: list[str]
    suid_binaries: list[str]
    open_ports_visible: list[int]
    fake_filesystem: list[DashboardPersonaFile]
    fake_credentials: list[DashboardPersonaCredential]

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
        """Create a dashboard user and set the auth cookie.

        Self-hosted single-operator deployments should not stay open to
        public registration forever: signup is only allowed until the first
        account exists, unless ECHIDRA_ALLOW_SIGNUPS explicitly opts back in
        for deployments that want more than one dashboard user.
        """
        try:
            repository = PostgresClassifierRepository()
            if not _signup_allowed(repository.count_dashboard_users()):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "signup is disabled — a dashboard account already exists. "
                        f"Set {ALLOW_SIGNUPS_ENV}=true to allow additional accounts."
                    ),
                )
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

    @api.get("/dashboard.css", response_class=FileResponse, tags=["dashboard"])
    def dashboard_css() -> FileResponse:
        """Serve the shared dashboard stylesheet."""
        if not DASHBOARD_CSS_PATH.exists():
            raise HTTPException(status_code=404, detail="dashboard stylesheet not found")
        return FileResponse(DASHBOARD_CSS_PATH, media_type="text/css")

    @api.get("/dashboard/{page_name}", response_class=FileResponse, tags=["dashboard"])
    def dashboard_page(page_name: str, request: Request) -> Response:
        """Serve whitelisted dashboard pages behind the same auth guard."""
        if not _dashboard_request_is_authenticated(request):
            return RedirectResponse("/auth", status_code=303)
        page_path = DASHBOARD_PAGE_FILES.get(page_name)
        if page_path is None or not page_path.exists():
            raise HTTPException(status_code=404, detail="dashboard page not found")
        return FileResponse(page_path, media_type="text/html")

    @api.get(
        "/personas",
        response_model=list[DashboardPersonaPreset],
        tags=["dashboard"],
    )
    def dashboard_personas_endpoint(request: Request) -> list[DashboardPersonaPreset]:
        """Return available persona presets for dashboard configuration."""
        _require_dashboard_auth(request)
        return [
            _dashboard_persona_from_preset(persona)
            for persona in sorted(
                PRESET_PERSONAS.values(),
                key=lambda item: item.persona_id,
            )
        ]

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
        request: Request,
    ) -> ClassifyAndStoreResponse:
        """Classify one session and persist the classifier run.

        Unlike /classify/session, this endpoint has DB access at call time.
        It queries the session count for the peer IP before classifying so
        that the cross-session brute_force_bot YAML rule can match — the
        stateless endpoint cannot do this and always leaves that feature None.

        Requires ECHIDRA_INGEST_API_KEY (X-Api-Key header) since it writes to
        the database and can trigger alert emails — unlike /classify/session,
        which is read-only and side-effect-free.
        """
        _require_ingest_api_key(request)

        # Look up cross-session connection count before classification so the
        # repeat_connections_same_ip rule can fire on this session.
        connection_count: int | None = None
        if session.peer_ip:
            try:
                _repo = PostgresClassifierRepository()
                connection_count = _repo.count_sessions_from_ip(session.peer_ip)
            except (DatabaseDriverMissingError, DatabaseNotConfiguredError):
                pass  # classify without brute_force_bot detection if DB unavailable

        summary = _classify_or_http_error(
            session, connection_count_from_same_ip=connection_count
        )
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

        # Fire email alert asynchronously-ish — errors here never fail the run.
        _maybe_send_alert(run, session, summary)

        return ClassifyAndStoreResponse(run_id=run.id, summary=summary)

    @api.get(
        "/reports/summary",
        response_model=DashboardReportSummary,
        tags=["reports"],
    )
    def dashboard_report_summary_endpoint(request: Request) -> DashboardReportSummary:
        """Return database-wide aggregate values for the dashboard."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.get_dashboard_report_summary()
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in dashboard_report_summary_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

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

    @api.get(
        "/issues",
        response_model=list[IssueRecord],
        tags=["intelligence"],
    )
    def list_issues_endpoint(
        request: Request,
        status: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[IssueRecord]:
        """Return stored issues matching an optional status filter."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.list_issues(status=status, limit=limit)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in list_issues_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    @api.patch(
        "/issues/{issue_id}/status",
        response_model=IssueRecord,
        tags=["intelligence"],
    )
    def update_issue_status_endpoint(
        issue_id: UUID,
        payload: IssueStatusUpdate,
        request: Request,
    ) -> IssueRecord:
        """Update one issue's open/closed triage status."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            issue = repository.update_issue_status(issue_id, payload.status)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in update_issue_status_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if issue is None:
            raise HTTPException(status_code=404, detail="issue not found")
        return issue

    @api.get(
        "/persona-configs",
        response_model=list[PersonaConfigRecord],
        tags=["personas"],
    )
    def list_persona_configs_endpoint(request: Request) -> list[PersonaConfigRecord]:
        """Return all saved persona configurations."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.list_persona_configs()
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in list_persona_configs_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    @api.post(
        "/persona-configs",
        response_model=PersonaConfigRecord,
        status_code=201,
        tags=["personas"],
    )
    def create_persona_config_endpoint(
        persona_id: str,
        payload: PersonaConfigInput,
        request: Request,
    ) -> PersonaConfigRecord:
        """Create a new persona configuration. Returns 409 if the slug already exists."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            if repository.get_persona_config(persona_id) is not None:
                raise HTTPException(status_code=409, detail="persona config already exists")
            return repository.create_persona_config(persona_id, payload)
        except HTTPException:
            raise
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in create_persona_config_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    @api.get(
        "/persona-configs/{persona_id}",
        response_model=PersonaConfigRecord,
        tags=["personas"],
    )
    def get_persona_config_endpoint(
        persona_id: str,
        request: Request,
    ) -> PersonaConfigRecord:
        """Return one persona configuration by slug ID."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            config = repository.get_persona_config(persona_id)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in get_persona_config_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if config is None:
            raise HTTPException(status_code=404, detail="persona config not found")
        return config

    @api.put(
        "/persona-configs/{persona_id}",
        response_model=PersonaConfigRecord,
        tags=["personas"],
    )
    def update_persona_config_endpoint(
        persona_id: str,
        payload: PersonaConfigInput,
        request: Request,
    ) -> PersonaConfigRecord:
        """Update one persona configuration by slug ID."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            config = repository.update_persona_config(persona_id, payload)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in update_persona_config_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if config is None:
            raise HTTPException(status_code=404, detail="persona config not found")
        return config

    @api.delete(
        "/persona-configs/{persona_id}",
        status_code=204,
        response_model=None,
        tags=["personas"],
    )
    def delete_persona_config_endpoint(
        persona_id: str,
        request: Request,
    ) -> None:
        """Delete one persona configuration by slug ID."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            deleted = repository.delete_persona_config(persona_id)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in delete_persona_config_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if not deleted:
            raise HTTPException(status_code=404, detail="persona config not found")

    @api.get(
        "/persona-configs/{persona_id}/analytics",
        response_model=PersonaAnalytics,
        tags=["personas"],
    )
    def get_persona_analytics_endpoint(
        persona_id: str,
        request: Request,
    ) -> PersonaAnalytics:
        """Return aggregated session analytics for one persona ID."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.get_persona_analytics(persona_id)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in get_persona_analytics_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    @api.get(
        "/alerts/config",
        response_model=AlertConfigRecord,
        tags=["alerts"],
    )
    def get_alert_config_endpoint(request: Request) -> AlertConfigRecord:
        """Return the current global SMTP alert configuration."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            config = repository.get_alert_config()
            return config or AlertConfigRecord(
                enabled=False,
                smtp_host=None,
                smtp_port=587,
                smtp_username=None,
                smtp_password_configured=False,
                smtp_from_email=None,
                smtp_use_tls=True,
                global_min_risk_level="high",
            )
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in get_alert_config_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    @api.put(
        "/alerts/config",
        response_model=AlertConfigRecord,
        tags=["alerts"],
    )
    def update_alert_config_endpoint(
        payload: AlertConfigInput,
        request: Request,
    ) -> AlertConfigRecord:
        """Persist the global SMTP alert configuration."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.upsert_alert_config(payload)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in update_alert_config_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    @api.post(
        "/alerts/test",
        tags=["alerts"],
    )
    def send_test_alert_endpoint(request: Request) -> dict[str, str]:
        """Send a test email using the current alert config."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            config = repository.get_alert_config()
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in send_test_alert_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if config is None or not config.enabled:
            raise HTTPException(status_code=400, detail="alerts not enabled")
        if not config.smtp_host or not config.smtp_from_email:
            raise HTTPException(status_code=400, detail="smtp_host and smtp_from_email are required")

        err = _dispatch_test_email(config)
        if err:
            raise HTTPException(status_code=502, detail=f"SMTP error: {err}")
        return {"status": "sent"}

    @api.get(
        "/alerts/events",
        response_model=list[AlertEventRecord],
        tags=["alerts"],
    )
    def list_alert_events_endpoint(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[AlertEventRecord]:
        """Return recent alert dispatch records, newest first."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.list_alert_events(limit=limit)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in list_alert_events_endpoint: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

    return api


def _classify_or_http_error(
    session: SessionRecord,
    *,
    connection_count_from_same_ip: int | None = None,
) -> ClassificationSummary:
    """Run classification and map pipeline failures to HTTP errors."""
    try:
        return classify_session(
            session,
            connection_count_from_same_ip=connection_count_from_same_ip,
        )
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


_RISK_LEVEL_ORDER = ("critical", "high", "medium", "low", "none")


def _risk_meets_threshold(risk_level: str, min_risk_level: str) -> bool:
    """Return True when risk_level is at or above min_risk_level in severity."""
    try:
        return _RISK_LEVEL_ORDER.index(risk_level) <= _RISK_LEVEL_ORDER.index(min_risk_level)
    except ValueError:
        return False


def _dispatch_test_email(config: AlertConfigRecord) -> str | None:
    """Send a test email using the current alert config. Returns error or None."""
    recipient = config.smtp_from_email or ""
    if not recipient:
        return "smtp_from_email must be set to receive the test email"
    subject = "[Echidra] SMTP alert test"
    body = "This is a test alert from your Echidra OSS honeypot. SMTP is configured correctly."
    return _smtp_send(config, recipient, subject, body)


def _smtp_send(
    config: AlertConfigRecord,
    recipient: str,
    subject: str,
    body: str,
) -> str | None:
    """Low-level SMTP send. Returns error string on failure, None on success."""
    if not config.smtp_host:
        return "smtp_host not configured"
    msg = email.mime.multipart.MIMEMultipart()
    msg["From"] = config.smtp_from_email or config.smtp_host
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(email.mime.text.MIMEText(body, "plain"))
    try:
        context = ssl.create_default_context() if config.smtp_use_tls else None
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as server:
            if config.smtp_use_tls:
                server.starttls(context=context)
            if config.smtp_username:
                # Password is stored in DB but not in AlertConfigRecord (redacted).
                # Re-fetch the raw password for sending only.
                from classifier.storage.config import get_database_url
                try:
                    import psycopg
                    db_url = get_database_url()
                    if db_url:
                        with psycopg.connect(db_url) as conn:
                            row = conn.execute(
                                "SELECT smtp_password FROM alert_config WHERE id = 1"
                            ).fetchone()
                            raw_password = row[0] if row else None
                    else:
                        raw_password = None
                except Exception:
                    raw_password = None
                if raw_password:
                    server.login(config.smtp_username, raw_password)
            server.sendmail(msg["From"], [recipient], msg.as_string())
        return None
    except Exception as exc:
        return str(exc)


def _dashboard_persona_from_preset(persona: Persona) -> DashboardPersonaPreset:
    return DashboardPersonaPreset(
        persona_id=persona.persona_id,
        os_banner=persona.os_banner,
        ssh_banner=persona.ssh_banner,
        hostname=persona.hostname,
        uname_output=persona.uname_output,
        timezone=persona.timezone,
        username=persona.username,
        home_dir=persona.home_dir,
        running_processes=list(persona.running_processes),
        fake_users=list(persona.fake_users),
        suid_binaries=list(persona.suid_binaries),
        open_ports_visible=list(persona.open_ports_visible),
        fake_filesystem=[
            DashboardPersonaFile(path=fake_file.path, content=fake_file.content)
            for fake_file in persona.fake_filesystem
        ],
        fake_credentials=[
            DashboardPersonaCredential(
                username=credential.username,
                password=credential.password,
            )
            for credential in persona.fake_credentials
        ],
    )


def _dashboard_request_is_authenticated(request: Request) -> bool:
    cookie_value = request.cookies.get(DASHBOARD_AUTH_COOKIE)
    if cookie_value is None:
        return False
    return _verify_dashboard_session_cookie(cookie_value)


def _require_dashboard_auth(request: Request) -> None:
    if not _dashboard_request_is_authenticated(request):
        raise HTTPException(status_code=401, detail="dashboard auth required")


def _signup_allowed(existing_user_count: int) -> bool:
    if os.getenv(ALLOW_SIGNUPS_ENV, "").strip().lower() in ("1", "true", "yes"):
        return True
    return existing_user_count == 0


def _require_ingest_api_key(request: Request) -> None:
    """Gate write/alert-triggering ingestion behind a configured shared secret.

    Fails closed: if the operator hasn't set ECHIDRA_INGEST_API_KEY, this
    endpoint refuses all requests rather than silently accepting writes from
    anyone who can reach the port.
    """
    configured_key = os.getenv(INGEST_API_KEY_ENV, "")
    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail=f"{INGEST_API_KEY_ENV} is not configured on this server",
        )
    provided_key = request.headers.get(INGEST_API_KEY_HEADER, "")
    if not provided_key or not hmac.compare_digest(provided_key, configured_key):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


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
    configured = os.getenv(DASHBOARD_SESSION_SECRET_ENV)
    if configured:
        return configured
    global _fallback_session_secret
    if _fallback_session_secret is None:
        _fallback_session_secret = _load_or_create_fallback_session_secret()
    return _fallback_session_secret


def _load_or_create_fallback_session_secret() -> str:
    """Fall back secret used when ECHIDRA_SESSION_SECRET is unset.

    Persisted to disk so dashboard logins survive process restarts (eg.
    --reload, crashes, redeploys) instead of invalidating every cookie the
    moment a fresh random secret is generated in memory.
    """
    try:
        existing = _FALLBACK_SESSION_SECRET_PATH.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except OSError:
        pass

    secret = secrets.token_urlsafe(32)
    try:
        _FALLBACK_SESSION_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
        _FALLBACK_SESSION_SECRET_PATH.write_text(secret, encoding="utf-8")
        _FALLBACK_SESSION_SECRET_PATH.chmod(0o600)
    except OSError:
        logger.warning(
            "Could not persist fallback dashboard session secret to %s; "
            "logins will not survive a process restart. Set %s to fix this "
            "permanently.",
            _FALLBACK_SESSION_SECRET_PATH,
            DASHBOARD_SESSION_SECRET_ENV,
        )
    return secret


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
