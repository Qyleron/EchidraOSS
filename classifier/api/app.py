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
from fastapi import Path as PathParam
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, validator

from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.alerts import _maybe_send_alert, _smtp_send
from classifier.storage import (
    AlertConfigInput,
    AlertConfigRecord,
    AlertEventRecord,
    AnalyticsSummary,
    ClassifierRunRecord,
    ClassifyAndStoreResponse,
    DashboardEmailAlreadyRegisteredError,
    DashboardReportSummary,
    DashboardSignupNotAllowedError,
    DashboardUserRecord,
    DatabaseDriverMissingError,
    DatabaseNotConfiguredError,
    IssueRecord,
    IssueStatusUpdate,
    ManualLabelRecord,
    PersonaAnalytics,
    PersonaConfigAlreadyExistsError,
    PersonaConfigInput,
    PersonaConfigRecord,
    PostgresClassifierRepository,
    StoredClassifierRun,
    StoredSessionEvent,
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
# Applied to every authenticated dashboard page response. Without this, a
# browser may serve a logged-out user their last-viewed dashboard straight
# from the back-forward cache on Back/Forward navigation -- a real network
# request (and this route's own auth check) never happens, so a revoked
# session would otherwise appear to still be logged in.
_DASHBOARD_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, must-revalidate",
    "Pragma": "no-cache",
}
# Every dashboard JSON/API route (reports, classifier runs, issues, alerts,
# personas, sessions, manual labels, persona configs, ...) reads the same
# echidra_dashboard_auth cookie as /dashboard itself, so it's exposed to the
# same risk _DASHBOARD_NO_STORE_HEADERS was introduced for: a cached response
# body could otherwise be replayed for a since-logged-out or different
# session sharing the same URL. Rather than hand-adding headers= to each of
# the 20+ individual endpoints (and needing to remember it for every new one
# added later), _apply_dashboard_no_store_headers below defaults to
# protecting every response and this is the explicit allowlist of routes
# that are intentionally public/non-session and should stay normally
# cacheable -- the ingest endpoints (authenticated separately, by API key,
# not cookie), health/docs, and static assets.
_NO_STORE_EXEMPT_PATHS = {
    "/health",
    "/",
    "/classify/session",
    "/openapi.json",
    "/docs",
    "/redoc",
}
_NO_STORE_EXEMPT_PREFIXES = ("/assets/",)
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
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60

# Persona IDs are slugs used as a Postgres primary key, a URL path segment,
# and the ECHIDRA_PERSONA env var value the honeypot looks up by -- lowercase
# snake_case, matching every built-in preset (see honeypot/core/persona.py),
# keeps them predictable across all three and rules out an empty string.
_PERSONA_ID_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
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
    decoy_credential_count: int

    class Config:
        extra = "forbid"


def create_app() -> FastAPI:
    """Create the FastAPI application for classifier consumers."""
    api = FastAPI(
        title="Echidra Classifier API",
        version="1.0.0",
        description="Post-session behavioral classification for Echidra logs.",
    )

    @api.middleware("http")
    async def _apply_dashboard_no_store_headers(request: Request, call_next):
        """Default every response to no-store except the explicit public allowlist.

        See _NO_STORE_EXEMPT_PATHS for why this defaults to protecting rather
        than an allowlist of routes to protect: a route that forgets to opt in
        is a silent gap, a route that forgets to opt out fails safe. Uses
        setdefault so it never overwrites the header on /dashboard, /auth, and
        /dashboard.css, which already set it explicitly for reasons (bfcache,
        stale-CSS-after-deploy) that predate and go beyond this middleware.
        """
        response = await call_next(request)
        path = request.url.path
        if path not in _NO_STORE_EXEMPT_PATHS and not path.startswith(_NO_STORE_EXEMPT_PREFIXES):
            for key, value in _DASHBOARD_NO_STORE_HEADERS.items():
                response.headers.setdefault(key, value)
        return response

    @api.get("/health", tags=["service"])
    def health() -> dict[str, str]:
        """Report whether the classifier API process is serving requests."""
        return {"status": "ok"}

    @api.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        """Send visitors at the bare host straight to the dashboard."""
        return RedirectResponse("/dashboard", status_code=307)

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
        return FileResponse(
            AUTH_INDEX_PATH,
            media_type="text/html",
            headers=_DASHBOARD_NO_STORE_HEADERS,
        )

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
            user = repository.create_dashboard_user_if_eligible(
                email=payload.email,
                password_hash=_hash_password(payload.password),
                allow_multiple=_dashboard_allow_multiple_signups(),
            )
        except DashboardSignupNotAllowedError:
            # Deliberately generic: this endpoint is reachable by anyone who
            # can reach the honeypot's dashboard port, including attackers
            # probing it, so the response must not name the exact env var
            # that reopens signups. An operator who needs that already has
            # it documented in README.md/docs/DEPLOYMENT.md.
            raise HTTPException(
                status_code=403,
                detail="signup is currently unavailable.",
            )
        except DashboardEmailAlreadyRegisteredError:
            raise HTTPException(status_code=409, detail="email already registered")
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
        request: Request,
        response: Response,
    ) -> dict[str, str | bool]:
        """Verify dashboard credentials and set the auth cookie."""
        rate_limit_key = _login_rate_limit_key(request, payload.email)
        try:
            repository = PostgresClassifierRepository()
            _check_login_rate_limit(rate_limit_key, repository)
            user = repository.get_dashboard_user_by_email(payload.email)
        except HTTPException:
            raise
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in login_dashboard_user: %s", exc)
            raise HTTPException(status_code=500, detail="internal server error")

        if user is None or not _verify_password(payload.password, user.password_hash):
            _record_login_failure(rate_limit_key, repository)
            raise HTTPException(status_code=401, detail="invalid email or password")

        _clear_login_failures(rate_limit_key, repository)
        _set_dashboard_session_cookie(response, user)
        return {"authenticated": True, "email": user.email}

    @api.post("/auth/logout", tags=["dashboard"])
    def logout_dashboard(request: Request, response: Response) -> dict[str, bool]:
        """Revoke the current session and clear the dashboard auth cookie.

        Rotates the user's session_version so this (and every other
        outstanding) copy of the cookie is rejected by verification from
        this point on -- clearing the browser cookie alone would leave a
        captured/copied cookie valid until it expires on its own.
        """
        cookie_value = request.cookies.get(DASHBOARD_AUTH_COOKIE)
        user_id = _dashboard_session_cookie_user_id(cookie_value) if cookie_value else None
        if user_id is not None:
            try:
                repository = PostgresClassifierRepository()
                repository.rotate_dashboard_user_session(user_id)
            except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
                logger.warning("Could not rotate session_version during logout: %s", exc)
                raise HTTPException(status_code=503, detail="could not revoke dashboard session")
            except Exception:
                logger.exception("Could not rotate session_version during logout")
                raise HTTPException(status_code=503, detail="could not revoke dashboard session")
        response.delete_cookie(DASHBOARD_AUTH_COOKIE)
        return {"authenticated": False}

    @api.get("/dashboard", response_class=FileResponse, tags=["dashboard"])
    def dashboard(request: Request) -> Response:
        """Serve the local analyst dashboard shell."""
        if not _dashboard_request_is_authenticated(request):
            return RedirectResponse("/auth", status_code=303)
        if not DASHBOARD_INDEX_PATH.exists():
            raise HTTPException(status_code=404, detail="dashboard not found")
        return FileResponse(
            DASHBOARD_INDEX_PATH,
            media_type="text/html",
            headers=_DASHBOARD_NO_STORE_HEADERS,
        )

    @api.get("/dashboard.css", response_class=FileResponse, tags=["dashboard"])
    def dashboard_css() -> FileResponse:
        """Serve the shared dashboard stylesheet.

        no-store here isn't the bfcache/auth concern _DASHBOARD_NO_STORE_HEADERS
        was introduced for (this route needs no auth) -- it's so a browser
        never keeps serving a stylesheet cached from before a deploy/restart
        changed it, which silently breaks any page relying on a class added
        since (eg. .password-toggle-btn's positioning).
        """
        if not DASHBOARD_CSS_PATH.exists():
            raise HTTPException(status_code=404, detail="dashboard stylesheet not found")
        return FileResponse(
            DASHBOARD_CSS_PATH,
            media_type="text/css",
            headers=_DASHBOARD_NO_STORE_HEADERS,
        )

    @api.get("/dashboard/{page_name}", response_class=FileResponse, tags=["dashboard"])
    def dashboard_page(page_name: str, request: Request) -> Response:
        """Serve whitelisted dashboard pages behind the same auth guard."""
        if not _dashboard_request_is_authenticated(request):
            return RedirectResponse("/auth", status_code=303)
        page_path = DASHBOARD_PAGE_FILES.get(page_name)
        if page_path is None or not page_path.exists():
            raise HTTPException(status_code=404, detail="dashboard page not found")
        return FileResponse(
            page_path,
            media_type="text/html",
            headers=_DASHBOARD_NO_STORE_HEADERS,
        )

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
            except Exception:
                logger.exception("count_sessions_from_ip failed; classifying without it")

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
        try:
            _maybe_send_alert(run, session, summary)
        except Exception as exc:
            logger.exception(
                "Alert dispatch failed for classifier run %s: %s",
                run.id,
                exc,
            )

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
        "/analytics/summary",
        response_model=AnalyticsSummary,
        tags=["reports"],
    )
    def analytics_summary_endpoint(
        request: Request,
        from_ts: float = Query(..., description="Range start, Unix seconds"),
        to_ts: float = Query(..., description="Range end, Unix seconds"),
    ) -> AnalyticsSummary:
        """Return aggregated session/classifier analytics for one date range."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.get_analytics_summary(from_ts, to_ts)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in analytics_summary_endpoint: %s",
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
        from_ts: float | None = None,
        to_ts: float | None = None,
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
                from_ts=from_ts,
                to_ts=to_ts,
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
        "/sessions/{session_id}/events",
        response_model=list[StoredSessionEvent],
        tags=["storage"],
    )
    def list_session_events_endpoint(
        session_id: UUID,
        request: Request,
    ) -> list[StoredSessionEvent]:
        """Return one session's command/decoy-access timeline, in order."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.list_session_events(session_id)
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception(
                "Unhandled exception in list_session_events_endpoint: %s",
                exc,
            )
            raise HTTPException(status_code=500, detail="internal server error")

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
        "/persona-configs/{persona_id}",
        response_model=PersonaConfigRecord,
        status_code=201,
        tags=["personas"],
    )
    def create_persona_config_endpoint(
        request: Request,
        payload: PersonaConfigInput,
        persona_id: str = PathParam(..., pattern=_PERSONA_ID_PATTERN),
    ) -> PersonaConfigRecord:
        """Create a new persona configuration. Returns 409 if the slug already exists."""
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return repository.create_persona_config(persona_id, payload)
        except PersonaConfigAlreadyExistsError:
            raise HTTPException(status_code=409, detail="persona config already exists")
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
        request: Request,
        persona_id: str = PathParam(..., pattern=_PERSONA_ID_PATTERN),
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
        request: Request,
        payload: PersonaConfigInput,
        persona_id: str = PathParam(..., pattern=_PERSONA_ID_PATTERN),
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
        request: Request,
        persona_id: str = PathParam(..., pattern=_PERSONA_ID_PATTERN),
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
        request: Request,
        persona_id: str = PathParam(..., pattern=_PERSONA_ID_PATTERN),
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

    @api.get(
        "/alerts/events/count",
        tags=["alerts"],
    )
    def count_alert_events_endpoint(request: Request) -> dict[str, int]:
        """Return the total number of alert dispatch records ever stored.

        list_alert_events_endpoint is capped at 500, so the dashboard's
        "Total Alerts" tile needs this separate authoritative count.
        """
        _require_dashboard_auth(request)
        try:
            repository = PostgresClassifierRepository()
            return {"total": repository.count_alert_events()}
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            logger.exception("Unhandled exception in count_alert_events_endpoint: %s", exc)
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
        # Never return decoy credential values over the API — a count is
        # enough for the dashboard to show, and can't leak into logs/errors.
        decoy_credential_count=len(persona.fake_credentials),
    )


def _dashboard_request_is_authenticated(request: Request) -> bool:
    cookie_value = request.cookies.get(DASHBOARD_AUTH_COOKIE)
    if cookie_value is None:
        return False
    return _verify_dashboard_session_cookie(cookie_value)


def _require_dashboard_auth(request: Request) -> None:
    if not _dashboard_request_is_authenticated(request):
        raise HTTPException(status_code=401, detail="dashboard auth required")


def _dashboard_allow_multiple_signups() -> bool:
    return os.getenv(ALLOW_SIGNUPS_ENV, "").strip().lower() in ("1", "true", "yes")


def _login_rate_limit_key(request: Request, email: str) -> str:
    client = getattr(request, "client", None)
    host = client.host if client else "unknown"
    return f"{host}:{_normalize_email(email)}"


def _check_login_rate_limit(key: str, repository: PostgresClassifierRepository) -> None:
    """Reject a login attempt if this (client, account) pair failed too often recently.

    Backed by the database (shared across every API worker process) rather
    than a process-local dict, which would let an attacker bypass the limit
    by simply spreading requests across workers. Checked before the PBKDF2
    verify so a lockout skips the expensive hash, not just delays the 401.
    """
    recent = repository.count_recent_login_failures(key, LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    if recent >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too many login attempts — try again later")


def _record_login_failure(key: str, repository: PostgresClassifierRepository) -> None:
    try:
        repository.record_login_failure(key, window_seconds=LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    except Exception:
        logger.exception("Could not record login failure for rate limiting")


def _clear_login_failures(key: str, repository: PostgresClassifierRepository) -> None:
    try:
        repository.clear_login_failures(key)
    except Exception:
        logger.exception("Could not clear login failure history after successful login")


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


def _read_fallback_session_secret() -> str | None:
    try:
        existing = _FALLBACK_SESSION_SECRET_PATH.read_text(encoding="utf-8").strip()
        return existing or None
    except OSError:
        return None


def _load_or_create_fallback_session_secret() -> str:
    """Fall back secret used when ECHIDRA_SESSION_SECRET is unset.

    Persisted to disk so dashboard logins survive process restarts (eg.
    --reload, crashes, redeploys) instead of invalidating every cookie the
    moment a fresh random secret is generated in memory.

    Creation is atomic (O_CREAT | O_EXCL) so that if multiple worker
    processes start at once and race to create this file, only the first
    one's secret is ever persisted -- every loser re-reads that file instead
    of quietly signing/verifying cookies with its own, different candidate
    secret, which previously desynced sessions across workers.
    """
    existing = _read_fallback_session_secret()
    if existing:
        return existing

    candidate = secrets.token_urlsafe(32)
    try:
        _FALLBACK_SESSION_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            _FALLBACK_SESSION_SECRET_PATH,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            os.write(fd, candidate.encode("utf-8"))
        finally:
            os.close(fd)
        return candidate
    except FileExistsError:
        # Another process won the race and created the file first between
        # our read above and our create attempt -- use its secret so every
        # worker shares one value.
        return _read_fallback_session_secret() or candidate
    except OSError:
        logger.warning(
            "Could not persist fallback dashboard session secret to %s; "
            "logins will not survive a process restart. Set %s to fix this "
            "permanently.",
            _FALLBACK_SESSION_SECRET_PATH,
            DASHBOARD_SESSION_SECRET_ENV,
        )
    return candidate


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


def _dashboard_session_cookie_signature(
    user_id: UUID, session_version: int, issued_at: int
) -> str:
    payload = f"{user_id}:{session_version}:{issued_at}"
    return hmac.new(
        _dashboard_session_secret().encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _dashboard_session_cookie_value(user: DashboardUserRecord) -> str:
    issued_at = int(time.time())
    signature = _dashboard_session_cookie_signature(user.id, user.session_version, issued_at)
    return f"{user.id}:{user.session_version}:{issued_at}:{signature}"


def _parse_dashboard_session_cookie(
    value: str,
) -> tuple[UUID, int, int, str] | None:
    """Split a cookie into (user_id, session_version, issued_at, signature).

    Structural parsing only -- callers must still check the signature before
    trusting any of the parsed fields.
    """
    try:
        payload, signature = value.rsplit(":", 1)
        user_id_str, version_str, issued_at_str = payload.split(":", 2)
        return UUID(user_id_str), int(version_str), int(issued_at_str), signature
    except (TypeError, ValueError):
        return None


def _dashboard_session_cookie_user_id(value: str) -> UUID | None:
    """Return the user id embedded in a cookie once its signature checks out.

    Ignores age and session_version so a stale-but-genuine cookie can still
    be used to log out. Rejecting on a bad signature first stops an attacker
    from forging an arbitrary user id to force-invalidate someone else's
    session via /auth/logout, which takes no other auth.
    """
    parsed = _parse_dashboard_session_cookie(value)
    if parsed is None:
        return None
    user_id, session_version, issued_at, signature = parsed
    expected = _dashboard_session_cookie_signature(user_id, session_version, issued_at)
    if not hmac.compare_digest(signature, expected):
        return None
    return user_id


def _verify_dashboard_session_cookie(value: str) -> bool:
    parsed = _parse_dashboard_session_cookie(value)
    if parsed is None:
        return False
    user_id, session_version, issued_at, signature = parsed
    expected_signature = _dashboard_session_cookie_signature(user_id, session_version, issued_at)
    age = int(time.time()) - issued_at
    if not (
        0 <= age <= SESSION_MAX_AGE_SECONDS
        and hmac.compare_digest(signature, expected_signature)
    ):
        return False

    # Revocation check: logout (and, in future, password change or account
    # deletion) bumps session_version in the database, which invalidates
    # every cookie issued before that point even though its signature and
    # age are still otherwise valid.
    try:
        repository = PostgresClassifierRepository()
        current_version = repository.get_dashboard_user_session_version(user_id)
    except (DatabaseDriverMissingError, DatabaseNotConfiguredError):
        logger.warning("Dashboard DB not configured; rejecting session cookie")
        return False
    except Exception:
        logger.exception("Could not verify dashboard session revocation status")
        return False
    return current_version is not None and current_version == session_version


def _dashboard_cookie_secure() -> bool:
    return os.getenv(DASHBOARD_COOKIE_SECURE_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


app = create_app()
