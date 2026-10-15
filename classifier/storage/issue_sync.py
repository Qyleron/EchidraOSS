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
from classifier.storage.repository import IssueSyncStore, PostgresClassifierRepository


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

# Queued classifier runs merged per transaction. Each batch commits on its
# own, so a large backlog is worked through in bounded steps.
_ISSUE_SYNC_BATCH_SIZE = 1_000
_SAMPLE_EVIDENCE_LIMIT = 5

_ROLLUP_SOURCE_CLASSIFIER = "classifier"
_ROLLUP_SOURCE_REPEAT_CONNECTIONS = "repeat_connections"


class IssueSyncInProgressError(RuntimeError):
    """Raised when another process is running the issue sync right now."""


def sync_issues_from_classifier_runs(
    *,
    database_url: str | None = None,
    playbook_path: str | Path = DEFAULT_ISSUE_PLAYBOOK_PATH,
    mitre_catalog_path: str | Path = DEFAULT_MITRE_CATALOG_PATH,
    repeat_connection_window_seconds: int = _REPEAT_CONNECTION_WINDOW_SECONDS,
    repeat_connection_min_sessions: int = _REPEAT_CONNECTION_MIN_SESSIONS,
    full: bool = False,
    batch_size: int = _ISSUE_SYNC_BATCH_SIZE,
) -> list[IssueRecord]:
    """Roll stored classifier runs up into one issue per (actor_label, MITRE
    technique) pair, and return the issues this pass created or updated.

    Incremental: every stored run is queued for this sync (see "Issue sync"
    in repository.py), and a pass merges only the queued runs into each
    issue's stored totals, so its cost follows how much arrived since the
    last pass, not how much is stored. The first pass on a database that has
    never been rebuilt -- and every pass with full=True -- rebuilds every
    issue from all stored runs instead.

    Each pair maps to a stable issue id, and merging is idempotent: a
    re-merged run changes nothing, and an analyst's open/closed status is
    kept -- unless a closed issue picks up new sessions, which reopens it.
    Unlike a rule-id rollup, this reads directly off classifier_runs/
    classifier_signals -- any actor/technique combination your classifier
    actually produces shows up here, even without a dedicated rule written
    just for it. Repeat-connection brute-force detection runs alongside it,
    off raw session counts instead.

    Raises IssueSyncInProgressError if another process holds the sync lock.
    """
    playbook = load_issue_playbook(playbook_path)
    mitre_catalog = load_mitre_technique_catalog(mitre_catalog_path)

    repository = PostgresClassifierRepository(database_url)
    synced: dict[UUID, IssueRecord] = {}

    with repository.issue_sync_transaction() as store:
        _require_lock(store)
        if full or not store.is_rebuilt():
            # Clear the queue before reading every run: a run stored after
            # the clear stays queued and is merged again below, which
            # changes nothing, so no run can be missed.
            store.clear_queue()
            _merge_runs(store, store.load_runs(), playbook, mitre_catalog, synced, rebuild=True)
            store.mark_rebuilt()

    while True:
        with repository.issue_sync_transaction() as store:
            _require_lock(store)
            run_ids = store.next_queued_run_ids(batch_size)
            if not run_ids:
                break
            _merge_runs(store, store.load_runs(run_ids=run_ids), playbook, mitre_catalog, synced)
            store.dequeue(run_ids)

    with repository.issue_sync_transaction() as store:
        _require_lock(store)
        _sync_repeat_connection_issue(
            store,
            playbook,
            mitre_catalog,
            synced,
            window_seconds=repeat_connection_window_seconds,
            min_sessions=repeat_connection_min_sessions,
        )

    return list(synced.values())


def _require_lock(store: IssueSyncStore | None) -> IssueSyncStore:
    if store is None:
        raise IssueSyncInProgressError("another issue sync is running")
    return store


def _merge_runs(
    store: IssueSyncStore,
    aggregates: list[dict[str, Any]],
    playbook: IssuePlaybook,
    mitre_catalog: dict[str, str],
    synced: dict[UUID, IssueRecord],
    *,
    rebuild: bool = False,
) -> None:
    """Merge the per-pair aggregates of the runs just loaded into each
    pair's issue. With rebuild=True those runs are every run of each pair,
    so each issue's stored totals are replaced instead of added to."""
    pairs = {
        (aggregate["actor_label"], aggregate["mitre_tag"]): _issue_id_for_pair(
            aggregate["actor_label"], aggregate["mitre_tag"]
        )
        for aggregate in aggregates
    }
    states = store.issue_states(list(pairs.values()))
    if not rebuild:
        # The repeat-connection check currently owns this issue and rewrites
        # it every pass; its classifier totals are rebuilt from all runs if
        # that check stops matching (see _sync_repeat_connection_issue).
        pairs = {
            key: issue_id
            for key, issue_id in pairs.items()
            if (states.get(issue_id) or {}).get("rollup_source") != _ROLLUP_SOURCE_REPEAT_CONNECTIONS
        }
    if not pairs:
        return

    # Start from zero when rebuilding, for a new issue, and for an issue
    # whose stored totals didn't come from classifier runs.
    fresh_ids = [
        issue_id
        for issue_id in pairs.values()
        if rebuild or (states.get(issue_id) or {}).get("rollup_source") != _ROLLUP_SOURCE_CLASSIFIER
    ]
    added = store.merge_pairs(pairs, reset_issue_ids=fresh_ids)

    for aggregate in aggregates:
        issue_id = pairs.get((aggregate["actor_label"], aggregate["mitre_tag"]))
        if issue_id is None:
            continue
        base = None if issue_id in fresh_ids else states.get(issue_id)
        rollup = _merge_rollup(base, aggregate, added[issue_id])
        issue = _build_issue({**aggregate, **rollup}, playbook, mitre_catalog)
        synced[issue_id] = store.write_rollup_issue(issue, rollup)


def _merge_rollup(
    base: dict[str, Any] | None,
    batch: dict[str, Any],
    added: dict[str, int],
) -> dict[str, Any]:
    """An issue's new totals: its stored totals (None to start from zero)
    plus the runs just merged. Counts grow only by sessions, personas and
    source IPs the issue didn't already have."""
    base = base or {}
    samples = set(base.get("sample_evidence") or []) | set(batch.get("sample_evidence") or [])
    return {
        "session_count": (base.get("session_count") or 0) + added["sessions"],
        "persona_count": (base.get("persona_count") or 0) + added["personas"],
        "source_ip_count": (base.get("source_ip_count") or 0) + added["source_ips"],
        "first_seen": _combine(min, base.get("first_seen"), batch.get("first_seen")),
        "last_seen": _combine(max, base.get("last_seen"), batch.get("last_seen")),
        "max_risk_rank": _combine(max, base.get("max_risk_rank"), batch.get("max_risk_rank")),
        # Python's str order is code point order, matching the COLLATE "C"
        # sort the samples were picked with.
        "sample_evidence": sorted(samples)[:_SAMPLE_EVIDENCE_LIMIT],
    }


def _combine(pick, first: Any, second: Any) -> Any:
    values = [value for value in (first, second) if value is not None]
    return pick(values) if values else None


def _sync_repeat_connection_issue(
    store: IssueSyncStore,
    playbook: IssuePlaybook,
    mitre_catalog: dict[str, str],
    synced: dict[UUID, IssueRecord],
    *,
    window_seconds: int,
    min_sessions: int,
) -> None:
    """Write the repeat-connection issue when the check matches. When it
    stops matching, give the shared brute_force_bot/T1110 issue back to the
    classifier, rebuilt from all of that pair's runs."""
    issue_id = _issue_id_for_pair(_REPEAT_CONNECTION_ACTOR_LABEL, _REPEAT_CONNECTION_MITRE_TAG)
    repeat_connections = store.aggregate_repeat_connections(
        window_seconds=window_seconds,
        min_sessions=min_sessions,
    )
    if repeat_connections is not None:
        issue = _build_repeat_connection_issue(
            repeat_connections,
            playbook,
            mitre_catalog,
            window_seconds=window_seconds,
            min_sessions=min_sessions,
        )
        synced[issue_id] = store.write_repeat_connection_issue(issue)
        return

    state = store.issue_states([issue_id]).get(issue_id)
    if state is None or state.get("rollup_source") != _ROLLUP_SOURCE_REPEAT_CONNECTIONS:
        return
    aggregates = store.load_runs(pair=(_REPEAT_CONNECTION_ACTOR_LABEL, _REPEAT_CONNECTION_MITRE_TAG))
    _merge_runs(store, aggregates, playbook, mitre_catalog, synced, rebuild=True)


# Debounce/single-flight state for maybe_sync_issues_from_classifier_runs() --
# process-local only, like the login rate limiter's in-memory fallback path:
# fine for the single honeypot process and the single API process this runs
# in today (no `--workers` flag documented anywhere for uvicorn). Passes in
# different processes never overlap either way: each sync transaction takes
# a Postgres advisory lock (see issue_sync_transaction in repository.py), and
# a process that can't get it skips its pass.
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

    A pass normally merges only the runs stored since the previous one, but
    the first pass after an upgrade (or on a database never rebuilt)
    rebuilds every issue from all stored runs, which can take minutes on a
    large database. Two things follow from that:

    1. Debouncing on elapsed time alone isn't enough to prevent overlap: if a
       run takes longer than min_interval_seconds, a second caller arriving
       after that window would see the debounce as expired and start a
       concurrent second run. _issue_sync_running is checked and set inside
       the same locked section as the elapsed-time check, so only one sync is
       ever in flight regardless of how long it takes. Across processes (the
       honeypot and the API both call this), a Postgres advisory lock does
       the same job: the process that doesn't get it skips its pass.
    2. This must never run inline on the caller's own thread. Both call
       sites are latency-sensitive in different ways -- auto_classify_and_store
       runs on one of a small fixed pool of classification workers (see
       _CLASSIFICATION_WORKER_COUNT), so an inline rebuild there
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
        except IssueSyncInProgressError:
            # The other process is syncing; whatever this pass would have
            # merged stays queued for the next one.
            logger.debug("Issue sync skipped: another process is running it")
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


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _build_evidence(aggregate: dict[str, Any], technique_name: str) -> str:
    samples = [text for text in (aggregate.get("sample_evidence") or []) if text]
    window = _seen_window(aggregate.get("first_seen"), aggregate.get("last_seen"))
    source_ips = aggregate.get("source_ip_count")

    parts = [
        f"{_count(aggregate['session_count'], 'session')} across "
        f"{_count(aggregate['persona_count'], 'persona')} exhibited {technique_name} behavior"
        + (f" from {_count(source_ips, 'source IP')}" if source_ips else "")
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
        f"{_count(aggregate['session_count'], 'connection attempt')} across "
        f"{_count(aggregate['persona_count'], 'persona')} from "
        f"{_count(aggregate['source_ip_count'], 'source IP')}, each making at least "
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
