import email.mime.multipart
import email.mime.text
import html
import json
import logging
import os
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
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


_REPEAT_WINDOW_ENV = "ECHIDRA_ALERT_REPEAT_MINUTES"
_DEFAULT_REPEAT_MINUTES = 60.0
_RISK_RANKS = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MAX_TRACKED_SESSIONS = 10_000
_PRUNE_INTERVAL_SECONDS = 60.0

# Monotonic clock for the repeat window; module-level so tests can replace it.
_clock = time.monotonic


@dataclass
class _AlertGroup:
    """Alerts for one (persona, source address, lead technique) in the current window."""

    opened_at: float
    rank: int
    held: int = 0
    last_held_at: datetime | None = None
    latest: tuple | None = None
    timer: threading.Timer | None = None


_grouping_lock = threading.Lock()
_alert_groups: dict[tuple[str, str, str], _AlertGroup] = {}
_alerted_session_ranks: OrderedDict = OrderedDict()
_last_pruned_at: float | None = None


def _repeat_window_seconds() -> float:
    raw = os.getenv(_REPEAT_WINDOW_ENV, "").strip()
    if not raw:
        return _DEFAULT_REPEAT_MINUTES * 60
    try:
        minutes = float(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a number of minutes; using %d",
            _REPEAT_WINDOW_ENV,
            raw,
            _DEFAULT_REPEAT_MINUTES,
        )
        return _DEFAULT_REPEAT_MINUTES * 60
    return max(minutes, 0.0) * 60


def _group_key(session: SessionRecord, summary: ClassificationSummary) -> tuple[str, str, str]:
    technique = summary.mitre_tags[0] if summary.mitre_tags else (summary.actor_label or "")
    return (session.persona_id, str(session.peer_ip or ""), technique)


def _start_follow_up_timer(delay: float, key: tuple[str, str, str]) -> threading.Timer:
    timer = threading.Timer(max(delay, 0.0), _send_follow_up, args=(key,))
    timer.daemon = True
    timer.start()
    return timer


def _alert_decision(
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
) -> int | None:
    """Return how many held-back sessions this alert should count, or None to not send it.

    A session alerts once per level: the end-of-session classification of an
    SSH session the live classifier already alerted on is dropped unless its
    level rose. Across sessions, the first alert for a persona, source
    address and lead technique goes out at once; repeats within the window
    are held and counted, and one follow-up with the count goes out when the
    window ends. A higher level than the one already alerted, or a critical
    session, always goes out at once.
    """
    global _last_pruned_at
    rank = _RISK_RANKS.get(summary.risk_level, 0)
    with _grouping_lock:
        previous_rank = _alerted_session_ranks.get(session.session_id)
        if previous_rank is not None and rank <= previous_rank:
            return None
        _alerted_session_ranks[session.session_id] = rank
        _alerted_session_ranks.move_to_end(session.session_id)
        while len(_alerted_session_ranks) > _MAX_TRACKED_SESSIONS:
            _alerted_session_ranks.popitem(last=False)

        window = _repeat_window_seconds()
        if window <= 0:
            return 0

        now = _clock()
        if _last_pruned_at is None or now - _last_pruned_at >= _PRUNE_INTERVAL_SECONDS:
            _last_pruned_at = now
            for stale_key in [
                key
                for key, group in _alert_groups.items()
                if group.timer is None and now - group.opened_at >= window
            ]:
                del _alert_groups[stale_key]

        key = _group_key(session, summary)
        group = _alert_groups.get(key)
        if (
            group is None
            or now - group.opened_at >= window
            or rank > group.rank
            or summary.risk_level == "critical"
        ):
            repeats = 0
            if group is not None:
                repeats = group.held
                if group.timer is not None:
                    group.timer.cancel()
            _alert_groups[key] = _AlertGroup(opened_at=now, rank=rank)
            return repeats

        group.held += 1
        group.last_held_at = datetime.now(timezone.utc)
        group.latest = (run, session, summary)
        if group.timer is None:
            group.timer = _start_follow_up_timer(group.opened_at + window - now, key)
        return None


def _send_follow_up(key: tuple[str, str, str]) -> None:
    """Send the count of sessions held back in a window that just ended."""
    try:
        with _grouping_lock:
            group = _alert_groups.get(key)
            if group is None or not group.held or group.latest is None:
                return
            repeats, last_held_at = group.held, group.last_held_at
            run, session, summary = group.latest
            # The follow-up opens a new window, so a source that keeps going
            # produces at most one message per window.
            _alert_groups[key] = _AlertGroup(opened_at=_clock(), rank=group.rank)

        targets = _alert_targets(session, summary)
        if targets is None:
            return
        repository, config, persona_config = targets
        _dispatch_alerts(
            repository, config, persona_config, run, session, summary,
            repeats=repeats, last_held_at=last_held_at, follow_up=True,
        )
    except Exception:
        logger.exception("Follow-up alert dispatch failed")


def reset_alert_grouping() -> None:
    """Forget all alert grouping state and cancel pending follow-ups (for tests)."""
    global _last_pruned_at
    with _grouping_lock:
        for group in _alert_groups.values():
            if group.timer is not None:
                group.timer.cancel()
        _alert_groups.clear()
        _alerted_session_ranks.clear()
        _last_pruned_at = None


def _alert_targets(session: SessionRecord, summary: ClassificationSummary):
    """Return (repository, config, persona_config) when this session should alert, else None."""
    repository = PostgresClassifierRepository()
    config = repository.get_alert_config()
    if config is None or not config.enabled:
        logger.info(
            "Alert skipped for session %s: global alert config is missing or disabled",
            session.session_id,
        )
        return None

    if _is_excluded_ip(config.excluded_ips, session.peer_ip):
        logger.info(
            "Alert skipped for session %s: peer_ip %s is on the excluded_ips list",
            session.session_id,
            session.peer_ip,
        )
        return None

    persona_config = repository.get_persona_config(session.persona_id)
    if persona_config is None or persona_config.alert_routing_level == "none":
        logger.info(
            "Alert skipped for session %s: no persona_configs row for %r "
            "(or its alert_routing_level is 'none')",
            session.session_id,
            session.persona_id,
        )
        return None

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
        return None
    return repository, config, persona_config


def _maybe_send_alert(
    run: ClassifierRunRecord | None,
    session: SessionRecord | dict,
    summary: ClassificationSummary,
) -> None:
    """Fire an alert (email and/or Slack) if the run meets the configured threshold.

    Repeats are grouped by _alert_decision. Only email and Slack are held
    back; every session is still stored and classified as usual.
    """
    if summary.alert_action is None:
        return
    try:
        if isinstance(session, dict):
            session = SessionRecord.model_validate(session)
        targets = _alert_targets(session, summary)
        if targets is None:
            return
        repository, config, persona_config = targets

        repeats = _alert_decision(run, session, summary)
        if repeats is None:
            logger.info(
                "Alert held for session %s: already alerted for this session or "
                "for this source and technique in the current window",
                session.session_id,
            )
            return
        _dispatch_alerts(repository, config, persona_config, run, session, summary, repeats=repeats)
    except Exception:
        logger.exception("Alert dispatch failed — classifier run was saved normally")


def _dispatch_alerts(
    repository,
    config: AlertConfigRecord,
    persona_config,
    run: ClassifierRunRecord | None,
    session: SessionRecord,
    summary: ClassificationSummary,
    *,
    repeats: int = 0,
    last_held_at: datetime | None = None,
    follow_up: bool = False,
) -> None:
    grouping = {"repeats": repeats, "last_held_at": last_held_at, "follow_up": follow_up}

    # "both" fires each configured channel independently -- a persona
    # missing one destination (e.g. routing is "both" but no Slack
    # webhook is set yet) still gets the channel it does have configured,
    # rather than silently getting nothing.
    if persona_config.alert_routing_level in ("email", "both") and persona_config.contact_email:
        err = _dispatch_alert_email(
            config, persona_config.contact_email, run, session, summary, **grouping
        )
        _record_alert_event(
            repository,
            _build_alert_event(
                run, session, summary,
                channel="email",
                contact_email=persona_config.contact_email,
                error=err,
            ),
        )

    if persona_config.alert_routing_level in ("slack", "both") and persona_config.slack_webhook:
        err = _dispatch_alert_slack(persona_config.slack_webhook, run, session, summary, **grouping)
        _record_alert_event(
            repository,
            _build_alert_event(
                run, session, summary,
                channel="slack",
                contact_email=None,
                error=err,
            ),
        )


def _record_alert_event(repository, event: AlertEventRecord) -> None:
    # The alert has already gone out; failing to record it must not stop
    # the next channel from being sent.
    try:
        repository.insert_alert_event(event)
    except Exception:
        logger.exception(
            "Could not record the %s alert for session %s", event.channel, event.session_id
        )


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
    return f"{_dashboard_base_url()}/dashboard/sessions?session={urllib.parse.quote(str(session_id))}"


def _dashboard_base_url() -> str:
    base = os.getenv("ECHIDRA_DASHBOARD_URL", "").strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = _DEFAULT_DASHBOARD_URL
    return base


def _alert_content(
    session: SessionRecord,
    summary: ClassificationSummary,
    *,
    repeats: int = 0,
    last_held_at: datetime | None = None,
    follow_up: bool = False,
) -> dict:
    """Everything an alert says, shared by the email and Slack versions.

    repeats is the number of sessions like this one held back since the
    last alert; follow_up marks the message sent when a window ends, which
    describes the newest of those sessions.
    """
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
    heading = f"Echidra alert: {risk.lower()}-risk session"
    if repeats:
        more = f"{repeats} more session{'s' if repeats != 1 else ''} like this"
        repeat_text = f"{more} from this source since the last alert"
        if last_held_at is not None:
            repeat_text += f", the last at {last_held_at:%H:%M} UTC"
        fields.insert(5, ("Repeats", repeat_text))
        if follow_up:
            subject = f"[Echidra] {more}: {subject.removeprefix('[Echidra] ')}"
            heading = f"Echidra alert: {more}"
    return {
        "subject": subject,
        "heading": heading,
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


# Fields whose value is a dashboard link, with the text it's shown as.
_LINK_FIELD_TEXT = {
    "Open": "Open this session in the dashboard",
    "Review": "Open the Sessions page",
}


def _alert_html_field_rows(fields: list[tuple[str, str]]) -> str:
    def cell(label: str, value: str) -> str:
        if label in _LINK_FIELD_TEXT:
            # Built from the dashboard URL, never from attacker input.
            href = html.escape(value, quote=True)
            return f'<a href="{href}">{_LINK_FIELD_TEXT[label]}</a>'
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
    **grouping,
) -> str | None:
    content = _alert_content(session, summary, **grouping)
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
    **grouping,
) -> str | None:
    content = _alert_content(session, summary, **grouping)
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


def send_catch_up_alerts(stored: list[tuple]) -> None:
    """One alert per decoy for sessions stored late, after a database outage
    or a stop (classifier/catch_up.py), instead of one late alert per session.

    stored holds (run, session, summary) tuples. Only sessions that would
    have alerted on their own count, with each decoy's usual routing and
    risk threshold.
    """
    by_persona: dict[str, list[tuple]] = {}
    targets_by_persona = {}
    for run, session, summary in stored:
        if summary.alert_action is None:
            continue
        try:
            targets = _alert_targets(session, summary)
        except Exception:
            logger.exception("Could not check the alert settings for session %s", session.session_id)
            continue
        if targets is None:
            continue
        by_persona.setdefault(session.persona_id, []).append((run, session, summary))
        targets_by_persona[session.persona_id] = targets

    for persona_id, items in by_persona.items():
        repository, config, persona_config = targets_by_persona[persona_id]
        try:
            _dispatch_catch_up_alert(repository, config, persona_config, items)
        except Exception:
            logger.exception("Catch-up alert for %s failed", persona_id)


def _utc_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%d %b %Y, %H:%M")


def _catch_up_content(items: list[tuple]) -> dict:
    """What a catch-up alert says, shared by the email and Slack versions.
    items is non-empty and all from one decoy."""
    ranked = sorted(items, key=lambda item: _RISK_RANKS.get(item[2].risk_level, 0), reverse=True)
    persona_id = ranked[0][1].persona_id
    count = len(items)
    noun = "session" if count == 1 else "sessions"
    risk_counts: dict[str, int] = {}
    for _, _, summary in ranked:
        risk_counts[summary.risk_level] = risk_counts.get(summary.risk_level, 0) + 1
    started = min(session.started_at for _, session, _ in items)
    ended = max(session.ended_at for _, session, _ in items)
    top_risk = _humanize(ranked[0][2].risk_level).lower()
    return {
        "subject": f"[Echidra] {count} {noun} stored late on {persona_id}",
        "heading": f"Echidra: {count} {noun} stored late",
        "fix": (
            f"Review them on the Sessions page, starting with the {top_risk}-risk ones. "
            "They weren't alerted on one by one because they couldn't be stored when "
            "they ended (the database was unreachable, or Echidra was stopping)."
        ),
        "fields": [
            ("Decoy", persona_id),
            ("Captured", f"{_utc_time(started)} to {_utc_time(ended)} UTC"),
            ("Sessions", f"{count} at or above this decoy's alert level"),
            ("By risk", ", ".join(
                f"{_humanize(level)} {risk_counts[level]}"
                for level in _RISK_LEVEL_ORDER
                if level in risk_counts
            )),
            ("Review", f"{_dashboard_base_url()}/dashboard/sessions"),
        ],
        # Recorded in the alert history as the session this alert stands for.
        "top": ranked[0],
    }


def _dispatch_catch_up_alert(repository, config, persona_config, items: list[tuple]) -> None:
    content = _catch_up_content(items)
    run, session, summary = content["top"]

    if persona_config.alert_routing_level in ("email", "both") and persona_config.contact_email:
        body = (
            f"{content['heading']}\n\n"
            f"What to do: {content['fix']}\n\n"
            + "\n".join(f"{label + ':':<12}{value}" for label, value in content["fields"])
            + "\n"
        )
        html_body = (
            '<div style="font-family:sans-serif;font-size:14px;color:#111;">'
            f'<h2 style="margin:0 0 12px;">{_html_escape(content["heading"])}</h2>'
            '<p style="margin:0 0 16px;padding:10px 12px;background:#f4f6f8;border-left:3px solid #111;">'
            f"<b>What to do:</b> {_html_escape(content['fix'])}</p>"
            f'<table cellspacing="0" cellpadding="0">{_alert_html_field_rows(content["fields"])}</table>'
            "</div>"
        )
        err = _smtp_send(config, persona_config.contact_email, content["subject"], body, html_body)
        _record_alert_event(
            repository,
            _build_alert_event(
                run, session, summary,
                channel="email",
                contact_email=persona_config.contact_email,
                error=err,
            ),
        )

    if persona_config.alert_routing_level in ("slack", "both") and persona_config.slack_webhook:
        text = (
            f"*{content['subject']}*\n"
            f"*What to do:* {content['fix']}\n"
            + "\n".join(
                f"<{value}|{_LINK_FIELD_TEXT[label]}>" if label in _LINK_FIELD_TEXT else f"{label}: {value}"
                for label, value in content["fields"]
            )
        )
        err = _slack_post(persona_config.slack_webhook, text)
        _record_alert_event(
            repository,
            _build_alert_event(
                run, session, summary,
                channel="slack",
                contact_email=None,
                error=err,
            ),
        )


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
