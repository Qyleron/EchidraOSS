import email.mime.multipart
import email.mime.text
import json
import logging
import smtplib
import ssl
import urllib.request

from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage import (
    AlertConfigRecord,
    AlertEventRecord,
    ClassifierRunRecord,
    DatabaseDriverMissingError,
    DatabaseNotConfiguredError,
    PostgresClassifierRepository,
)
from classifier.storage.config import get_database_url

logger = logging.getLogger(__name__)

_SMTP_IMPLICIT_TLS_PORT = 465

_RISK_LEVEL_ORDER = ("critical", "high", "medium", "low", "none")


def _risk_meets_threshold(risk_level: str, min_risk_level: str) -> bool:
    try:
        return _RISK_LEVEL_ORDER.index(risk_level) <= _RISK_LEVEL_ORDER.index(min_risk_level)
    except ValueError:
        return False


def _is_excluded_ip(excluded_ips: str | None, peer_ip) -> bool:
    """True if peer_ip matches an operator-configured excluded-IP entry.

    Exists because rules like repeat_connections_same_ip key off connection
    frequency from an IP, not that connection's own content -- an operator's
    own dev/test traffic against a stable IP (eg. 127.0.0.1) will eventually
    self-trigger a brute_force_bot/T1110 alert with no actual credential
    activity behind it. This lets an operator silence known-noisy sources
    without touching the scoring rules themselves.
    """
    if not excluded_ips or not peer_ip:
        return False
    peer_ip_str = str(peer_ip).strip()
    entries = {line.strip() for line in excluded_ips.replace(",", "\n").splitlines()}
    return peer_ip_str in entries


def _maybe_send_alert(
    run: ClassifierRunRecord | None,
    session: SessionRecord | dict,
    summary: ClassificationSummary,
) -> None:
    """Fire an alert (email and/or Slack) if the run meets the configured threshold."""
    if summary.alert_action is None:
        return
    try:
        if isinstance(session, dict):
            session = SessionRecord.parse_obj(session)
        repository = PostgresClassifierRepository()
        config = repository.get_alert_config()
        if config is None or not config.enabled:
            logger.info(
                "Alert skipped for session %s: global alert config is missing or disabled",
                session.session_id,
            )
            return

        if _is_excluded_ip(config.excluded_ips, session.peer_ip):
            logger.info(
                "Alert skipped for session %s: peer_ip %s is on the excluded_ips list",
                session.session_id,
                session.peer_ip,
            )
            return

        persona_config = repository.get_persona_config(session.persona_id)
        if persona_config is None or persona_config.alert_routing_level == "none":
            logger.info(
                "Alert skipped for session %s: no persona_configs row for %r "
                "(or its alert_routing_level is 'none')",
                session.session_id,
                session.persona_id,
            )
            return

        # The persona's own alert_min_risk_level, when set, is authoritative --
        # it can loosen the bar below the global default (eg. an operator wants
        # every hit on a decoy persona flagged) as well as tighten it. Only
        # fall back to the global default when the persona hasn't set one.
        effective_threshold = persona_config.alert_min_risk_level or config.global_min_risk_level
        if not _risk_meets_threshold(summary.risk_level, effective_threshold):
            logger.info(
                "Alert skipped for session %s: risk_level %r below effective threshold %r",
                session.session_id,
                summary.risk_level,
                effective_threshold,
            )
            return

        # "both" fires each configured channel independently -- a persona
        # missing one destination (e.g. routing is "both" but no Slack
        # webhook is set yet) still gets the channel it does have configured,
        # rather than silently getting nothing.
        if persona_config.alert_routing_level in ("email", "both") and persona_config.contact_email:
            err = _dispatch_alert_email(config, persona_config.contact_email, run, session, summary)
            repository.insert_alert_event(
                _build_alert_event(
                    run, session, summary,
                    channel="email",
                    contact_email=persona_config.contact_email,
                    error=err,
                )
            )

        if persona_config.alert_routing_level in ("slack", "both") and persona_config.slack_webhook:
            err = _dispatch_alert_slack(persona_config.slack_webhook, run, session, summary)
            repository.insert_alert_event(
                _build_alert_event(
                    run, session, summary,
                    channel="slack",
                    contact_email=None,
                    error=err,
                )
            )
    except Exception:
        logger.exception("Alert dispatch failed — classifier run was saved normally")


def _build_alert_event(
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
    *,
    channel: str,
    contact_email: str | None,
    error: str | None,
) -> AlertEventRecord:
    return AlertEventRecord(
        run_id=run.id if run is not None else None,
        session_id=session.session_id,
        persona_id=session.persona_id,
        risk_level=summary.risk_level,
        actor_label=summary.actor_label,
        channel=channel,
        contact_email=contact_email,
        success=error is None,
        error_message=error,
    )


def _alert_mitre_str(summary: ClassificationSummary) -> str:
    return ", ".join(summary.mitre_tags) if summary.mitre_tags else "none"


def _alert_evidence_lines(summary: ClassificationSummary, *, bullet: str) -> str:
    lines = "\n".join(f"{bullet}{e.text}" for e in summary.evidence)
    return lines or f"{bullet}(none)"


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _alert_html_field_rows(fields: list[tuple[str, str]]) -> str:
    return "\n".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#555;"><b>{_html_escape(label)}</b></td>'
        f'<td style="padding:4px 0;">{_html_escape(value)}</td></tr>'
        for label, value in fields
    )


def _alert_html_evidence(summary: ClassificationSummary) -> str:
    items = [e.text for e in summary.evidence] or ["(none)"]
    return "".join(f"<li>{_html_escape(item)}</li>" for item in items)


def _dispatch_alert_email(
    config: AlertConfigRecord,
    recipient: str,
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
) -> str | None:
    from classifier.storage.geolocation import resolve_country

    subject = f"[Echidra Alert] {summary.risk_level.upper()} risk session on {session.persona_id}"
    fields = [
        ("Risk Level", summary.risk_level.upper()),
        ("Risk Score", f"{summary.risk_score}/100"),
        ("Actor", summary.actor_label or "unknown"),
        ("Behavior", summary.behavior_stage),
        ("Intent", summary.intent),
        ("Persona", session.persona_id),
        ("Peer IP", str(session.peer_ip) if session.peer_ip else "unknown"),
        ("Country", resolve_country(str(session.peer_ip)) or "unknown"),
        ("Session ID", str(session.session_id)),
        ("MITRE", _alert_mitre_str(summary)),
    ]
    body = (
        f"ECHIDRA HONEYPOT ALERT\n"
        f"{'=' * 40}\n\n"
        + "\n".join(f"{label}: {value}" for label, value in fields)
        + f"\n\nEvidence:\n{_alert_evidence_lines(summary, bullet='  - ')}\n"
    )
    html_body = (
        '<div style="font-family:sans-serif;font-size:14px;color:#111;">'
        f'<h2 style="margin:0 0 12px;">Echidra Honeypot Alert</h2>'
        f'<table cellspacing="0" cellpadding="0">{_alert_html_field_rows(fields)}</table>'
        '<p style="margin:16px 0 4px;"><b>Evidence</b></p>'
        f'<ul style="margin:4px 0;padding-left:20px;">{_alert_html_evidence(summary)}</ul>'
        "</div>"
    )
    return _smtp_send(config, recipient, subject, body, html_body)


def _dispatch_alert_slack(
    webhook_url: str,
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
) -> str | None:
    from classifier.storage.geolocation import resolve_country

    text = (
        f"*[Echidra Alert] {summary.risk_level.upper()} risk session on {session.persona_id}*\n"
        f"Risk Score: {summary.risk_score}/100\n"
        f"Actor: {summary.actor_label or 'unknown'}\n"
        f"Behavior: {summary.behavior_stage}\n"
        f"Intent: {summary.intent}\n"
        f"Peer IP: {session.peer_ip or 'unknown'}\n"
        f"Country: {resolve_country(str(session.peer_ip)) or 'unknown'}\n"
        f"Session ID: {session.session_id}\n"
        f"MITRE: {_alert_mitre_str(summary)}\n"
        f"Evidence:\n{_alert_evidence_lines(summary, bullet='- ')}"
    )
    return _slack_post(webhook_url, text)


def _slack_post(webhook_url: str, text: str) -> str | None:
    # Anchored to the real Slack webhook host, not just the https:// scheme --
    # this is the one place both the real alert dispatch path and the
    # dashboard's test-send endpoint funnel through, so it's the spot to stop
    # an authenticated-but-untrusted caller from pointing the server at an
    # arbitrary internal URL (cloud metadata service, internal admin panel,
    # etc.) via SSRF. PersonaConfigInput.slack_webhook already enforces this
    # at save time (classifier/storage/models.py); this is defense in depth
    # for that path and the actual enforcement point for the test endpoint,
    # which takes a webhook URL directly rather than a saved config.
    if not webhook_url.startswith("https://hooks.slack.com/"):
        return "slack_webhook must be an https://hooks.slack.com/ URL"
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status >= 300:
                return f"slack webhook returned HTTP {response.status}"
        return None
    except Exception as exc:
        return str(exc)


def _smtp_send(
    config: AlertConfigRecord,
    recipient: str,
    subject: str,
    body: str,
    html_body: str | None = None,
) -> str | None:
    """Low-level SMTP send. Returns error string on failure, None on success.

    Shared by real alert dispatch (this module) and the dashboard's "Send
    Test Email" button (classifier/api/app.py imports this function) so the
    two paths can't drift out of sync again.

    html_body, when given, is attached alongside the plain-text body as a
    multipart/alternative part -- most mail clients prefer and render that
    one, falling back to the plain-text part only if they can't do HTML.
    """
    if not config.smtp_host:
        return "smtp_host not configured"
    msg = email.mime.multipart.MIMEMultipart("alternative" if html_body else "mixed")
    msg["From"] = config.smtp_from_email or config.smtp_host
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(email.mime.text.MIMEText(body, "plain"))
    if html_body:
        msg.attach(email.mime.text.MIMEText(html_body, "html"))

    raw_password = None
    if config.smtp_username:
        # AlertConfigRecord deliberately never carries the password (it's
        # redacted to smtp_password_configured) — fetch and decrypt it
        # through the repository for sending only.
        try:
            repository = PostgresClassifierRepository()
            raw_password = repository.get_alert_smtp_password()
        except (DatabaseDriverMissingError, DatabaseNotConfiguredError) as exc:
            return f"could not load SMTP credentials: {exc}"
        except Exception:
            # Unlike the two errors above (curated, safe operator-facing
            # text), an arbitrary exception here could be a raw psycopg
            # error containing connection/internal details -- log it for
            # the operator instead of embedding it in a message that
            # reaches the dashboard (test-email response, alert_events log).
            logger.exception("Could not load SMTP credentials for alert dispatch")
            return "could not load SMTP credentials"
        if not raw_password:
            return "smtp_username is set but no SMTP password is configured"
    # Port 465 servers expect TLS from the first byte of the connection
    # (implicit TLS) -- STARTTLS on a plaintext SMTP connection is a
    # different, incompatible protocol and would fail against them.
    use_implicit_tls = config.smtp_use_tls and config.smtp_port == _SMTP_IMPLICIT_TLS_PORT

    try:
        context = ssl.create_default_context() if config.smtp_use_tls else None
        if use_implicit_tls:
            server_cm = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=10, context=context)
        else:
            server_cm = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10)
        with server_cm as server:
            if config.smtp_use_tls and not use_implicit_tls:
                server.starttls(context=context)
            if raw_password:
                server.login(config.smtp_username, raw_password)
            server.sendmail(msg["From"], [recipient], msg.as_string())
        return None
    except Exception as exc:
        return str(exc)
