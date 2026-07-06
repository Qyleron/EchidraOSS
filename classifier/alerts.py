import email.mime.multipart
import email.mime.text
import logging
import smtplib
import ssl

from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary
from classifier.storage import (
    AlertConfigRecord,
    AlertEventRecord,
    ClassifierRunRecord,
    PostgresClassifierRepository,
)
from classifier.storage.config import get_database_url

logger = logging.getLogger(__name__)

_RISK_LEVEL_ORDER = ("critical", "high", "medium", "low", "none")


def _risk_meets_threshold(risk_level: str, min_risk_level: str) -> bool:
    try:
        return _RISK_LEVEL_ORDER.index(risk_level) <= _RISK_LEVEL_ORDER.index(min_risk_level)
    except ValueError:
        return False


def _maybe_send_alert(
    run: ClassifierRunRecord | None,
    session: SessionRecord | dict,
    summary: ClassificationSummary,
) -> None:
    """Fire an email alert if the run meets the configured threshold."""
    if summary.alert_action is None:
        return
    if isinstance(session, dict):
        session = SessionRecord.parse_obj(session)
    try:
        repository = PostgresClassifierRepository()
        config = repository.get_alert_config()
        if config is None or not config.enabled:
            return

        if not _risk_meets_threshold(summary.risk_level, config.global_min_risk_level):
            return

        persona_config = repository.get_persona_config(session.persona_id)
        if persona_config is None or persona_config.alert_routing_level not in ("email", "both"):
            return
        if not persona_config.contact_email:
            return

        effective_threshold = persona_config.alert_min_risk_level or config.global_min_risk_level
        if not _risk_meets_threshold(summary.risk_level, effective_threshold):
            return

        err = _dispatch_alert_email(config, persona_config.contact_email, run, session, summary)
        repository.insert_alert_event(
            AlertEventRecord(
                run_id=run.id if run is not None else None,
                session_id=session.session_id,
                persona_id=session.persona_id,
                risk_level=summary.risk_level,
                actor_label=summary.actor_label,
                contact_email=persona_config.contact_email,
                success=err is None,
                error_message=err,
            )
        )
    except Exception:
        logger.exception("Alert dispatch failed — classifier run was saved normally")


def _dispatch_alert_email(
    config: AlertConfigRecord,
    recipient: str,
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
) -> str | None:
    subject = f"[Echidra Alert] {summary.risk_level.upper()} risk session on {session.persona_id}"
    mitre_str = ", ".join(summary.mitre_tags) if summary.mitre_tags else "none"
    evidence_lines = "\n".join(f"  - {e.text}" for e in summary.evidence) or "  (none)"
    body = (
        f"ECHIDRA HONEYPOT ALERT\n"
        f"{'=' * 40}\n\n"
        f"Risk Level:    {summary.risk_level.upper()}\n"
        f"Risk Score:    {summary.risk_score}/100\n"
        f"Actor:         {summary.actor_label or 'unknown'}\n"
        f"Behavior:      {summary.behavior_stage}\n"
        f"Intent:        {summary.intent}\n"
        f"Persona:       {session.persona_id}\n"
        f"Peer IP:       {session.peer_ip or 'unknown'}\n"
        f"Session ID:    {session.session_id}\n"
        f"Run ID:        {run.id if run is not None else 'live-session'}\n\n"
        f"MITRE: {mitre_str}\n\n"
        f"Evidence:\n{evidence_lines}\n"
    )
    return _smtp_send(config, recipient, subject, body)


def _smtp_send(
    config: AlertConfigRecord,
    recipient: str,
    subject: str,
    body: str,
) -> str | None:
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
                raw_password = None
                if hasattr(config, "smtp_password"):
                    raw_password = config.smtp_password
                if raw_password:
                    server.login(config.smtp_username, raw_password)
            server.sendmail(msg["From"], [recipient], msg.as_string())
        return None
    except Exception as exc:
        return str(exc)
