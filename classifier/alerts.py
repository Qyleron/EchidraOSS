import email.mime.multipart
import email.mime.text
import html
import json
import logging
import os
import smtplib
import ssl
import urllib.parse
import urllib.request
from functools import lru_cache
from pathlib import Path

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
            session = SessionRecord.model_validate(session)
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


_PROTOCOL_NAMES = {"tcp_shell": "SSH", "http": "HTTP", "ftp": "FTP", "telnet": "Telnet"}


def _humanize(value: str | None) -> str:
    """credential_access -> Credential access."""
    if not value:
        return "Unknown"
    text = value.replace("_", " ")
    return text[:1].upper() + text[1:]


@lru_cache(maxsize=1)
def _issue_playbook():
    from classifier.rules.issue_playbook import load_issue_playbook

    return load_issue_playbook(Path(__file__).resolve().parent / "rules" / "issue_playbook.yaml")


def _actor_display(actor_label: str | None) -> str:
    """Singular, readable actor name: brute_force_bot -> Brute-force bot."""
    if not actor_label:
        return "Unclassified actor"
    try:
        plural = _issue_playbook().actor_label_names.get(actor_label)
    except Exception:
        plural = None
    # Playbook names are plural ("Brute-force bots", "Script kiddies").
    return plural[:-1] if plural and plural.endswith("s") else _humanize(actor_label)


def _technique_display(tag: str) -> str:
    from classifier.rules.issue_playbook import load_mitre_technique_catalog

    name = load_mitre_technique_catalog().get(tag)
    return f"{tag} {name}" if name else tag


def _recommended_fix(summary: ClassificationSummary) -> str | None:
    """The same fix text the Intelligence page shows for this actor/technique."""
    try:
        from classifier.rules.mitre_playbook import get_playbook_entry

        for tag in summary.mitre_tags:
            fix = _issue_playbook().fix_for(summary.actor_label or "", tag)
            if fix:
                return fix.recommended_fix
        if summary.mitre_tags:
            return get_playbook_entry(summary.mitre_tags[0]).recommended_fix
    except Exception:
        logger.exception("Could not look up a recommended fix for an alert")
    if summary.analyst_recommendation is not None:
        return summary.analyst_recommendation.rationale
    return None


_DEFAULT_DASHBOARD_URL = "http://127.0.0.1:8000"


def _session_link(session_id) -> str:
    """Direct link that opens this session in the dashboard's Sessions page.

    The server can't know the address the operator reaches the dashboard
    at, so this defaults to the loopback URL -- which also works through the
    `ssh -L 8000:127.0.0.1:8000` tunnel `echidra start` suggests -- and
    ECHIDRA_DASHBOARD_URL overrides it for any other setup.
    """
    base = os.getenv("ECHIDRA_DASHBOARD_URL", "").strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = _DEFAULT_DASHBOARD_URL
    return f"{base}/dashboard/sessions?session={urllib.parse.quote(str(session_id))}"


def _alert_content(session: SessionRecord, summary: ClassificationSummary) -> dict:
    """Everything an alert says, shared by the email and Slack versions."""
    from classifier.storage.geolocation import resolve_country

    risk = _humanize(summary.risk_level)
    actor = _actor_display(summary.actor_label)
    ip = str(session.peer_ip) if session.peer_ip else None
    country = resolve_country(ip) if ip else None
    tags = summary.mitre_tags

    what = actor[:1].lower() + actor[1:] if summary.actor_label else "session"
    subject = f"[Echidra] {risk}-risk {what}"
    if ip:
        subject += f" from {ip}"
    subject += f" on {session.persona_id}"
    if tags:
        subject += f" ({', '.join(tags[:2])})"

    source = ip or "Unknown"
    if ip and country:
        source += f" ({country})"
    fields = [
        ("Actor", actor),
        ("Risk", f"{risk} ({summary.risk_score}/100)"),
        ("Behavior", _humanize(summary.behavior_stage)),
        ("Intent", _humanize(summary.intent)),
        ("Source IP", source),
        ("Decoy", f"{session.persona_id} ({_PROTOCOL_NAMES.get(session.protocol, session.protocol)})"),
        ("Techniques", ", ".join(_technique_display(tag) for tag in tags) or "None mapped"),
        ("Session", str(session.session_id)),
        ("Open", _session_link(session.session_id)),
    ]
    return {
        "subject": subject,
        "heading": f"Echidra alert: {risk.lower()}-risk session",
        "fix": _recommended_fix(summary),
        "fields": fields,
        "evidence": [item.text for item in summary.evidence],
    }


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _alert_html_field_rows(fields: list[tuple[str, str]]) -> str:
    def cell(label: str, value: str) -> str:
        if label == "Open":
            # Built by _session_link, never from attacker input.
            href = html.escape(value, quote=True)
            return f'<a href="{href}">Open this session in the dashboard</a>'
        return _html_escape(value)

    return "\n".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#555;"><b>{_html_escape(label)}</b></td>'
        f'<td style="padding:4px 0;">{cell(label, value)}</td></tr>'
        for label, value in fields
    )


def _dispatch_alert_email(
    config: AlertConfigRecord,
    recipient: str,
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
) -> str | None:
    content = _alert_content(session, summary)
    evidence = content["evidence"] or ["None recorded."]
    body = (
        f"{content['heading']}\n\n"
        + (f"What to do: {content['fix']}\n\n" if content["fix"] else "")
        + "\n".join(f"{label + ':':<12}{value}" for label, value in content["fields"])
        + "\n\nEvidence:\n"
        + "\n".join(f"  - {item}" for item in evidence)
        + "\n"
    )
    fix_html = (
        '<p style="margin:0 0 16px;padding:10px 12px;background:#f4f6f8;border-left:3px solid #111;">'
        f"<b>What to do:</b> {_html_escape(content['fix'])}</p>"
        if content["fix"]
        else ""
    )
    html_body = (
        '<div style="font-family:sans-serif;font-size:14px;color:#111;">'
        f'<h2 style="margin:0 0 12px;">{_html_escape(content["heading"])}</h2>'
        f"{fix_html}"
        f'<table cellspacing="0" cellpadding="0">{_alert_html_field_rows(content["fields"])}</table>'
        '<p style="margin:16px 0 4px;"><b>Evidence</b></p>'
        '<ul style="margin:4px 0;padding-left:20px;">'
        + "".join(f"<li>{_html_escape(item)}</li>" for item in evidence)
        + "</ul></div>"
    )
    return _smtp_send(config, recipient, content["subject"], body, html_body)


def _dispatch_alert_slack(
    webhook_url: str,
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
) -> str | None:
    content = _alert_content(session, summary)
    evidence = content["evidence"] or ["None recorded."]
    text = (
        f"*{content['subject']}*\n"
        + (f"*What to do:* {content['fix']}\n" if content["fix"] else "")
        + "\n".join(
            f"<{value}|Open this session in the dashboard>" if label == "Open" else f"{label}: {value}"
            for label, value in content["fields"]
        )
        + "\nEvidence:\n"
        + "\n".join(f"- {item}" for item in evidence)
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
    parsed = urllib.parse.urlsplit(webhook_url)
    if parsed.scheme != "https" or parsed.hostname != "hooks.slack.com":
        return "Slack webhook URLs must start with https://hooks.slack.com/."
    # Rebuild the request URL from a hardcoded scheme/host rather than reusing
    # webhook_url directly, so the value reaching Request() is provably not
    # attacker-controlled (the hostname check above guards a derived value,
    # which static SSRF analysis can't always credit as sanitizing the
    # original string).
    safe_url = urllib.parse.urlunsplit(("https", "hooks.slack.com", parsed.path, parsed.query, ""))
    request = urllib.request.Request(
        safe_url,
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status >= 300:
                return f"Slack returned HTTP {response.status}. Check the webhook URL."
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
        return "SMTP host isn't set."
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
            return f"Couldn't load SMTP credentials: {exc}"
        except Exception:
            # Unlike the two errors above (curated, safe operator-facing
            # text), an arbitrary exception here could be a raw psycopg
            # error containing connection/internal details -- log it for
            # the operator instead of embedding it in a message that
            # reaches the dashboard (test-email response, alert_events log).
            logger.exception("Could not load SMTP credentials for alert dispatch")
            return "Couldn't load SMTP credentials."
        if not raw_password:
            return "An SMTP username is set but no SMTP password is saved."
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
