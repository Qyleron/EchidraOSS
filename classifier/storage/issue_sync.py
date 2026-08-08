"""Roll real classifier output up into persisted, analyst-triaged issues."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any
from uuid import UUID, NAMESPACE_URL, uuid5

from classifier.rules.issue_playbook import (
    DEFAULT_MITRE_CATALOG_PATH,
    IssuePlaybook,
    load_issue_playbook,
    load_mitre_technique_catalog,
)
from classifier.rules.mitre_playbook import get_playbook_entry
from classifier.storage.config import redact_database_url
from classifier.storage.models import IssueRecord, MitreTechnique
from classifier.storage.repository import PostgresClassifierRepository


DEFAULT_ISSUE_PLAYBOOK_PATH = Path(__file__).resolve().parents[1] / "rules" / "issue_playbook.yaml"

logger = logging.getLogger(__name__)
_RISK_RANK_SEVERITIES = {4: "high", 3: "high", 2: "medium", 1: "low", 0: "low"}

# default_rules.yaml can also produce brute_force_bot/T1110 via classifier_runs
# (authentication_attempt, repeat_connections_same_ip), aggregated into an
# issue by the loop below like everything else. This repeat-connection check
# is a second, independent computation of the same actor/technique pair,
# straight off raw connection frequency per source IP in `sessions` rather
# than classifier_runs -- it's the more precise, purpose-built signal for
# this behavior. Both share the same deterministic issue ID (see
# _issue_id_for_pair), so running this after the loop lets it win and
# consolidates them into one issue instead of two duplicates.
_REPEAT_CONNECTION_ACTOR_LABEL = "brute_force_bot"
_REPEAT_CONNECTION_MITRE_TAG = "T1110"
_REPEAT_CONNECTION_WINDOW_SECONDS = 86_400
_REPEAT_CONNECTION_MIN_SESSIONS = 5


def sync_issues_from_classifier_runs(
    *,
    database_url: str | None = None,
    playbook_path: str | Path = DEFAULT_ISSUE_PLAYBOOK_PATH,
    mitre_catalog_path: str | Path = DEFAULT_MITRE_CATALOG_PATH,
    repeat_connection_window_seconds: int = _REPEAT_CONNECTION_WINDOW_SECONDS,
    repeat_connection_min_sessions: int = _REPEAT_CONNECTION_MIN_SESSIONS,
) -> list[IssueRecord]:
    """Aggregate stored classifier runs by (actor_label, MITRE technique).

    Each pair maps to a stable issue id, so re-running this is idempotent:
    counts get refreshed from real captured sessions but an analyst's
    open/closed status is never reset. Unlike a rule-id rollup, this reads
    directly off classifier_runs/classifier_signals -- any actor/technique
    combination your classifier actually produces shows up here, even
    without a dedicated rule written just for it. Repeat-connection
    brute-force detection runs alongside it, off raw session counts instead.
    """
    playbook = load_issue_playbook(playbook_path)
    mitre_catalog = load_mitre_technique_catalog(mitre_catalog_path)

    repository = PostgresClassifierRepository(database_url)
    synced: list[IssueRecord] = []
    for aggregate in repository.aggregate_classifier_runs_by_actor_and_technique():
        issue = _build_issue(aggregate, playbook, mitre_catalog)
        synced.append(repository.upsert_issue(issue))

    repeat_connections = repository.aggregate_repeat_connections_by_peer_ip(
        window_seconds=repeat_connection_window_seconds,
        min_sessions=repeat_connection_min_sessions,
    )
    if repeat_connections is not None:
        issue = _build_repeat_connection_issue(
            repeat_connections,
            playbook,
            mitre_catalog,
            window_seconds=repeat_connection_window_seconds,
            min_sessions=repeat_connection_min_sessions,
        )
        synced.append(repository.upsert_issue(issue))

    return synced


# Debounce/single-flight state for maybe_sync_issues_from_classifier_runs() --
# process-local only, like the login rate limiter's in-memory fallback path:
# fine for the single honeypot process and the single API process this runs
# in today (no `--workers` flag documented anywhere for uvicorn), but a
# multi-worker/multi-replica deployment would need this moved to something
# shared (eg. a DB timestamp/advisory lock) to actually coordinate across
# processes instead of once per process.
_ISSUE_SYNC_MIN_INTERVAL_SECONDS = 30.0
_issue_sync_lock = threading.Lock()
_last_issue_sync_monotonic: float | None = None
_issue_sync_running = False


def maybe_sync_issues_from_classifier_runs(
    *,
    database_url: str | None = None,
    playbook_path: str | Path = DEFAULT_ISSUE_PLAYBOOK_PATH,
    mitre_catalog_path: str | Path = DEFAULT_MITRE_CATALOG_PATH,
    min_interval_seconds: float = _ISSUE_SYNC_MIN_INTERVAL_SECONDS,
) -> bool:
    """Debounced, single-flight, backgrounded entry point for calling
    sync_issues_from_classifier_runs() straight from the live per-session
    pipeline (auto_classify_and_store / classify_and_store_session_endpoint),
    so Intelligence issues roll up automatically instead of requiring someone
    to run the `sync-issues` CLI command by hand. Returns True if a background
    sync was started, False if this call skipped (debounced, or one was
    already running).

    sync_issues_from_classifier_runs() re-aggregates *all* stored classifier
    runs every call -- cheap at low session volume, but its cost (and runtime)
    grows with total session count over time. Two things follow from that:

    1. Debouncing on elapsed time alone isn't enough to prevent overlap: if a
       run takes longer than min_interval_seconds, a second caller arriving
       after that window would see the debounce as expired and start a
       concurrent second run. _issue_sync_running is checked and set inside
       the same locked section as the elapsed-time check, so only one sync is
       ever in flight regardless of how long it takes.
    2. This must never run inline on the caller's own thread. Both call
       sites are latency-sensitive in different ways -- auto_classify_and_store
       runs on one of a small fixed pool of classification workers (see
       _CLASSIFICATION_WORKER_COUNT), so an inline full-table resync there
       would stall that worker from picking up the next queued session for
       as long as the resync takes; classify_and_store_session_endpoint would
       have an external caller's HTTP request hang open for the same
       duration. Spawning a daemon thread lets the caller return immediately
       either way, with the resync proceeding independently in the
       background.
    """
    global _last_issue_sync_monotonic, _issue_sync_running

    now = time.monotonic()
    with _issue_sync_lock:
        if _issue_sync_running:
            return False
        due = (
            _last_issue_sync_monotonic is None
            or now - _last_issue_sync_monotonic >= min_interval_seconds
        )
        if not due:
            return False
        _issue_sync_running = True
        _last_issue_sync_monotonic = now

    def _run() -> None:
        global _issue_sync_running
        try:
            sync_issues_from_classifier_runs(
                database_url=database_url,
                playbook_path=playbook_path,
                mitre_catalog_path=mitre_catalog_path,
            )
        except Exception as exc:
            # Not logger.exception(): some drivers/paths embed the raw DSN
            # (including the password) in an exception's own message, and a
            # traceback renders that message verbatim regardless of log
            # level. Log the redacted message instead of the exception
            # object -- matches the redact_database_url() discipline already
            # used for this same class of error in storage/cli.py and
            # _user_facing_error_detail() in api/app.py.
            logger.error(
                "Background issue sync failed: %s: %s",
                type(exc).__name__,
                redact_database_url(str(exc)),
            )
        finally:
            with _issue_sync_lock:
                _issue_sync_running = False

    try:
        threading.Thread(target=_run, name="issue-sync", daemon=True).start()
    except Exception:
        # If the thread never actually started, _run's finally above never
        # runs either -- reset the flag here or it stays stuck True forever,
        # silently disabling every future sync for the rest of this process's
        # life with no further error ever surfaced.
        logger.exception("Failed to start background issue-sync thread")
        with _issue_sync_lock:
            _issue_sync_running = False
        return False

    return True


def _build_issue(
    aggregate: dict[str, Any],
    playbook: IssuePlaybook,
    mitre_catalog: dict[str, str],
) -> IssueRecord:
    actor_label = aggregate["actor_label"]
    mitre_tag = aggregate["mitre_tag"]
    technique_name = _technique_name(mitre_tag, playbook, mitre_catalog)
    actor_display = playbook.actor_label_display(actor_label)
    fix = playbook.fix_for(actor_label, mitre_tag)
    technique_entry = get_playbook_entry(mitre_tag)

    return IssueRecord(
        id=_issue_id_for_pair(actor_label, mitre_tag),
        title=fix.title if fix else f"{actor_display} are exhibiting {technique_name} behavior.",
        severity=_RISK_RANK_SEVERITIES.get(aggregate["max_risk_rank"], "low"),
        evidence=_build_evidence(aggregate, technique_name),
        recommended_fix=fix.recommended_fix if fix else technique_entry.recommended_fix,
        impact=fix.impact if fix else technique_entry.impact,
        session_count=aggregate["session_count"],
        persona_count=aggregate["persona_count"],
        actor_label=actor_label,
        mitre=[MitreTechnique(id=mitre_tag, name=technique_name)],
        session_ids=aggregate.get("session_ids", []),
    )


def _technique_name(tag: str, playbook: IssuePlaybook, mitre_catalog: dict[str, str]) -> str:
    return playbook.mitre_technique_names.get(tag) or mitre_catalog.get(tag, tag)


def _build_evidence(aggregate: dict[str, Any], technique_name: str) -> str:
    samples = [text for text in (aggregate.get("sample_evidence") or []) if text]
    window = _seen_window(aggregate.get("first_seen"), aggregate.get("last_seen"))
    source_ips = aggregate.get("source_ip_count")

    parts = [
        f"{aggregate['session_count']} sessions across {aggregate['persona_count']} "
        f"personas exhibited {technique_name} behavior"
        + (f" from {source_ips} source IP{'s' if source_ips != 1 else ''}" if source_ips else "")
        + (f", {window}" if window else "")
        + "."
    ]
    if samples:
        parts.append("Matched: " + "; ".join(samples[:5]) + ".")
    return " ".join(parts)


def _seen_window(first_seen: float | None, last_seen: float | None) -> str | None:
    if first_seen is None or last_seen is None:
        return None
    from datetime import datetime, timezone

    same_instant = first_seen == last_seen
    first = datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if same_instant:
        return f"first and only seen {first}"
    last = datetime.fromtimestamp(last_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"first seen {first}, most recently {last}"


def _build_repeat_connection_issue(
    aggregate: dict[str, Any],
    playbook: IssuePlaybook,
    mitre_catalog: dict[str, str],
    *,
    window_seconds: int,
    min_sessions: int,
) -> IssueRecord:
    actor_label = _REPEAT_CONNECTION_ACTOR_LABEL
    mitre_tag = _REPEAT_CONNECTION_MITRE_TAG
    technique_name = _technique_name(mitre_tag, playbook, mitre_catalog)
    actor_display = playbook.actor_label_display(actor_label)
    fix = playbook.fix_for(actor_label, mitre_tag)
    technique_entry = get_playbook_entry(mitre_tag)

    return IssueRecord(
        id=_issue_id_for_pair(actor_label, mitre_tag),
        title=fix.title if fix else f"{actor_display} are repeatedly reconnecting from the same source.",
        severity=_repeat_connection_severity(aggregate["session_count"], min_sessions),
        evidence=_build_repeat_connection_evidence(aggregate, window_seconds, min_sessions),
        recommended_fix=fix.recommended_fix if fix else technique_entry.recommended_fix,
        impact=fix.impact if fix else technique_entry.impact,
        session_count=aggregate["session_count"],
        persona_count=aggregate["persona_count"],
        actor_label=actor_label,
        mitre=[MitreTechnique(id=mitre_tag, name=technique_name)],
        session_ids=aggregate.get("session_ids", []),
    )


def _repeat_connection_severity(session_count: int, min_sessions: int) -> str:
    if min_sessions <= 0:
        return "low"

    medium_threshold = max(min_sessions * 3, min_sessions + 10)
    high_threshold = max(min_sessions * 8, min_sessions + 40)

    if session_count >= high_threshold:
        return "high"
    if session_count >= medium_threshold:
        return "medium"
    return "low"


def _build_repeat_connection_evidence(
    aggregate: dict[str, Any],
    window_seconds: int,
    min_sessions: int,
) -> str:
    return (
        f"{aggregate['session_count']} connection attempts across {aggregate['persona_count']} "
        f"personas from {aggregate['source_ip_count']} source IPs, each making at least "
        f"{min_sessions} connections within {_format_window(window_seconds)}."
    )


def _format_window(window_seconds: int) -> str:
    if window_seconds % 86_400 == 0:
        days = window_seconds // 86_400
        return f"{days} day{'s' if days != 1 else ''}"
    if window_seconds % 3_600 == 0:
        hours = window_seconds // 3_600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{window_seconds} seconds"


def _issue_id_for_pair(actor_label: str, mitre_tag: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"echidra-issue-actor-technique:{actor_label}:{mitre_tag}")
