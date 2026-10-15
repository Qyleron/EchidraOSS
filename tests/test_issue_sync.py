from contextlib import contextmanager
from uuid import uuid4

import pytest

from classifier.rules.issue_playbook import IssueFixEntry, IssuePlaybook
from classifier.rules.mitre_playbook import get_playbook_entry
from classifier.storage import issue_sync
from classifier.storage.models import MitreTechnique


def make_aggregate(**overrides):
    fields = {
        "actor_label": "automated_scanner",
        "mitre_tag": "T1087",
        "session_count": 24,
        "persona_count": 3,
        "max_risk_rank": 2,
    }
    fields.update(overrides)
    return fields


def test_build_issue_uses_curated_fix_when_pair_has_an_entry():
    aggregate = make_aggregate()
    playbook = IssuePlaybook(
        actor_label_names={"automated_scanner": "Automated scanners"},
        fixes={
            "automated_scanner": {
                "T1087": IssueFixEntry(
                    title="Automated scanners are enumerating accounts before deciding where to focus.",
                    recommended_fix="Return uniform error messages with no user-existence hints.",
                    impact="Removes the reconnaissance signal scanners use to pick high-value targets.",
                )
            }
        },
    )
    mitre_catalog = {"T1087": "Account Discovery"}

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog)

    assert issue.title == "Automated scanners are enumerating accounts before deciding where to focus."
    assert issue.recommended_fix == "Return uniform error messages with no user-existence hints."
    assert issue.impact == "Removes the reconnaissance signal scanners use to pick high-value targets."
    assert issue.severity == "medium"
    assert issue.session_count == 24
    assert issue.persona_count == 3
    assert issue.mitre == [MitreTechnique(id="T1087", name="Account Discovery")]
    assert "24 sessions across 3 personas exhibited Account Discovery behavior." == issue.evidence


def test_build_issue_falls_back_to_technique_playbook_when_pair_has_no_curated_fix():
    aggregate = make_aggregate(actor_label="brute_force_bot", mitre_tag="T1110", max_risk_rank=3)
    playbook = IssuePlaybook()
    mitre_catalog = {"T1110": "Brute Force"}

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog)

    technique_entry = get_playbook_entry("T1110")
    assert issue.title == "Brute Force Bot are exhibiting Brute Force behavior."
    assert issue.recommended_fix == technique_entry.recommended_fix
    assert issue.impact == technique_entry.impact
    assert technique_entry.is_fallback is False
    assert issue.severity == "high"
    assert issue.mitre == [MitreTechnique(id="T1110", name="Brute Force")]


def test_build_issue_falls_back_to_generic_entry_for_technique_playbook_gap():
    aggregate = make_aggregate(actor_label="script_kiddie", mitre_tag="T9999", max_risk_rank=1)
    playbook = IssuePlaybook()
    mitre_catalog = {}

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog)

    technique_entry = get_playbook_entry("T9999")
    assert technique_entry.is_fallback is True
    assert issue.recommended_fix == technique_entry.recommended_fix
    assert issue.impact == technique_entry.impact


def test_build_issue_uses_actor_label_display_override():
    aggregate = make_aggregate(actor_label="brute_force_bot", mitre_tag="T1110")
    playbook = IssuePlaybook(actor_label_names={"brute_force_bot": "Brute-force bots"})

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog={})

    assert issue.title == "Brute-force bots are exhibiting T1110 behavior."


def test_build_issue_uses_mitre_catalog_when_playbook_has_no_override():
    aggregate = make_aggregate()
    playbook = IssuePlaybook()
    mitre_catalog = {"T1087": "Account Discovery"}

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog)

    assert issue.mitre == [MitreTechnique(id="T1087", name="Account Discovery")]


def test_build_issue_prefers_playbook_technique_name_override_over_catalog():
    aggregate = make_aggregate()
    playbook = IssuePlaybook(mitre_technique_names={"T1087": "Custom Override Name"})
    mitre_catalog = {"T1087": "Account Discovery"}

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog)

    assert issue.mitre == [MitreTechnique(id="T1087", name="Custom Override Name")]


def test_build_evidence_includes_source_ips_window_and_matched_samples():
    aggregate = make_aggregate(
        source_ip_count=3,
        first_seen=1_700_000_000.0,
        last_seen=1_700_003_600.0,
        sample_evidence=["cat /etc/passwd", "whoami"],
    )

    evidence = issue_sync._build_evidence(aggregate, "Account Discovery")

    assert "3 source IPs" in evidence
    assert "first seen 2023-11-14" in evidence
    assert "most recently 2023-11-14" in evidence
    assert "Matched: cat /etc/passwd; whoami." in evidence


def test_evidence_uses_singular_nouns_for_a_count_of_one():
    aggregate = make_aggregate(session_count=1, persona_count=1, source_ip_count=1)

    evidence = issue_sync._build_evidence(aggregate, "Account Discovery")
    repeat_evidence = issue_sync._build_repeat_connection_evidence(
        {"session_count": 1, "persona_count": 1, "source_ip_count": 1}, 86_400, 5
    )

    assert evidence == "1 session across 1 persona exhibited Account Discovery behavior from 1 source IP."
    assert repeat_evidence.startswith("1 connection attempt across 1 persona from 1 source IP, ")


def test_issue_id_for_pair_is_stable_and_unique():
    assert issue_sync._issue_id_for_pair("automated_scanner", "T1087") == issue_sync._issue_id_for_pair(
        "automated_scanner", "T1087"
    )
    assert issue_sync._issue_id_for_pair("automated_scanner", "T1087") != issue_sync._issue_id_for_pair(
        "automated_scanner", "T1082"
    )
    assert issue_sync._issue_id_for_pair("automated_scanner", "T1087") != issue_sync._issue_id_for_pair(
        "commodity_bot", "T1087"
    )


class FakeDatabase:
    """In-memory stand-in for the tables the issue sync reads and writes,
    behaving like IssueSyncStore's SQL: bridge rows are sets, so a count
    only grows by rows that weren't there yet."""

    def __init__(self):
        self.runs = []
        self.queue = []
        self.rebuilt = False
        self.locked_elsewhere = False
        self.repeat_aggregate = None
        self.issues = {}
        self.bridges = {}
        self.loads = []

    def add_run(self, *, queued=True, evidence=(), **overrides):
        run = {
            "run_id": uuid4(),
            "session_id": uuid4(),
            "actor_label": "automated_scanner",
            "mitre_tag": "T1087",
            "risk_rank": 2,
            "persona_id": "persona-a",
            "peer_ip": "203.0.113.1",
            "started_at": 1_700_000_000.0,
            "evidence": list(evidence),
        }
        run.update(overrides)
        self.runs.append(run)
        if queued:
            self.queue.append(run["run_id"])
        return run


class FakeStore:
    def __init__(self, database):
        self.db = database
        self.loaded = []

    def is_rebuilt(self):
        return self.db.rebuilt

    def mark_rebuilt(self):
        self.db.rebuilt = True

    def clear_queue(self):
        self.db.queue.clear()

    def next_queued_run_ids(self, limit):
        return list(self.db.queue[:limit])

    def dequeue(self, run_ids):
        self.db.queue = [run_id for run_id in self.db.queue if run_id not in run_ids]

    def load_runs(self, *, run_ids=None, pair=None):
        self.db.loads.append({"run_ids": run_ids, "pair": pair})
        self.loaded = [
            run
            for run in self.db.runs
            if (run_ids is None or run["run_id"] in run_ids)
            and (pair is None or (run["actor_label"], run["mitre_tag"]) == pair)
        ]
        grouped = {}
        for run in self.loaded:
            grouped.setdefault((run["actor_label"], run["mitre_tag"]), []).append(run)
        return [
            {
                "actor_label": actor_label,
                "mitre_tag": mitre_tag,
                "max_risk_rank": max(run["risk_rank"] for run in runs),
                "first_seen": min(run["started_at"] for run in runs),
                "last_seen": max(run["started_at"] for run in runs),
                "sample_evidence": sorted({text for run in runs for text in run["evidence"]})[:5],
            }
            for (actor_label, mitre_tag), runs in sorted(grouped.items())
        ]

    def issue_states(self, issue_ids):
        return {issue_id: dict(self.db.issues[issue_id]) for issue_id in issue_ids if issue_id in self.db.issues}

    def merge_pairs(self, pairs, *, reset_issue_ids):
        for issue_id in pairs.values():
            self.db.issues.setdefault(
                issue_id,
                {"session_count": 0, "persona_count": 0, "status": "open", "rollup_source": None},
            )
        for issue_id in reset_issue_ids:
            self.db.bridges.pop(issue_id, None)

        added = {}
        for pair, issue_id in pairs.items():
            bridges = self.db.bridges.setdefault(issue_id, {"sessions": set(), "personas": set(), "source_ips": set()})
            counts = {"sessions": 0, "personas": 0, "source_ips": 0}
            for run in self.loaded:
                if (run["actor_label"], run["mitre_tag"]) != pair:
                    continue
                for key, value in (
                    ("sessions", run["session_id"]),
                    ("personas", run["persona_id"]),
                    ("source_ips", run["peer_ip"]),
                ):
                    if value is not None and value not in bridges[key]:
                        bridges[key].add(value)
                        counts[key] += 1
            added[issue_id] = counts
        return added

    def write_rollup_issue(self, issue, rollup):
        stored = self.db.issues[issue.id]
        status = "open" if issue.session_count > stored["session_count"] else stored["status"]
        stored.update(
            {
                "session_count": issue.session_count,
                "persona_count": issue.persona_count,
                "status": status,
                "rollup_source": "classifier",
                "evidence": issue.evidence,
                **rollup,
            }
        )
        return issue.model_copy(update={"status": status})

    def write_repeat_connection_issue(self, issue):
        stored = self.db.issues.setdefault(issue.id, {"session_count": 0, "status": "open"})
        status = "open" if issue.session_count > stored["session_count"] else stored["status"]
        stored.update(
            {
                "session_count": issue.session_count,
                "persona_count": issue.persona_count,
                "status": status,
                "rollup_source": "repeat_connections",
                "evidence": issue.evidence,
            }
        )
        return issue.model_copy(update={"status": status})

    def aggregate_repeat_connections(self, *, window_seconds, min_sessions):
        assert window_seconds == issue_sync._REPEAT_CONNECTION_WINDOW_SECONDS
        assert min_sessions == issue_sync._REPEAT_CONNECTION_MIN_SESSIONS
        return self.db.repeat_aggregate


def use_fake_database(monkeypatch, database):
    class FakeRepository:
        def __init__(self, database_url):
            assert database_url == "postgresql://example/echidra"

        @contextmanager
        def issue_sync_transaction(self):
            yield None if database.locked_elsewhere else FakeStore(database)

    monkeypatch.setattr(issue_sync, "PostgresClassifierRepository", FakeRepository)


def run_sync(**kwargs):
    return issue_sync.sync_issues_from_classifier_runs(database_url="postgresql://example/echidra", **kwargs)


def stored_issue(database, actor_label, mitre_tag):
    return database.issues[issue_sync._issue_id_for_pair(actor_label, mitre_tag)]


def test_first_sync_rebuilds_every_issue_from_all_stored_runs(monkeypatch):
    database = FakeDatabase()
    # Stored before the queue existed (an upgrade), so never queued.
    for persona_id in ("persona-a", "persona-b", "persona-c"):
        database.add_run(queued=False, persona_id=persona_id, risk_rank=2)
    database.add_run(queued=False, actor_label="commodity_bot", mitre_tag="T1552.001", risk_rank=3)
    use_fake_database(monkeypatch, database)

    result = run_sync()

    # Uses the real shipped issue_playbook.yaml + mitre_technique_names.json.
    assert [issue.title for issue in result] == [
        "Automated scanners are enumerating accounts before deciding where to focus.",
        "Commodity bots are searching for credentials stored in files.",
    ]
    assert [issue.severity for issue in result] == ["medium", "high"]
    assert result[0].session_count == 3
    assert result[0].persona_count == 3
    assert database.rebuilt is True
    assert database.loads[0] == {"run_ids": None, "pair": None}


def test_later_syncs_read_only_queued_runs(monkeypatch):
    database = FakeDatabase()
    database.add_run(queued=False, persona_id="persona-a")
    use_fake_database(monkeypatch, database)
    run_sync()

    new_run = database.add_run(persona_id="persona-a", peer_ip="198.51.100.7", started_at=1_700_086_400.0)
    database.loads.clear()
    result = run_sync()

    assert database.loads == [{"run_ids": [new_run["run_id"]], "pair": None}]
    assert database.queue == []
    issue = stored_issue(database, "automated_scanner", "T1087")
    assert issue["session_count"] == 2
    assert issue["persona_count"] == 1
    assert issue["source_ip_count"] == 2
    assert issue["first_seen"] == 1_700_000_000.0
    assert issue["last_seen"] == 1_700_086_400.0
    assert "2 sessions across 1 persona" in result[0].evidence
    assert "from 2 source IPs" in result[0].evidence


def test_sync_with_nothing_queued_changes_nothing(monkeypatch):
    database = FakeDatabase()
    database.add_run(queued=False)
    use_fake_database(monkeypatch, database)
    run_sync()

    assert run_sync() == []


def test_merging_the_same_run_twice_changes_nothing(monkeypatch):
    database = FakeDatabase()
    use_fake_database(monkeypatch, database)
    run = database.add_run()
    run_sync()
    before = dict(stored_issue(database, "automated_scanner", "T1087"))

    database.queue.append(run["run_id"])
    run_sync()

    assert stored_issue(database, "automated_scanner", "T1087") == before


def test_closed_issue_reopens_only_when_new_sessions_arrive(monkeypatch):
    database = FakeDatabase()
    use_fake_database(monkeypatch, database)
    run = database.add_run()
    run_sync()
    issue = stored_issue(database, "automated_scanner", "T1087")
    issue["status"] = "closed"

    # Another run for a session the issue already has: no new session.
    database.add_run(session_id=run["session_id"])
    run_sync()
    assert issue["status"] == "closed"

    database.add_run()
    run_sync()
    assert issue["status"] == "open"


def test_merged_samples_keep_the_first_five_distinct(monkeypatch):
    database = FakeDatabase()
    use_fake_database(monkeypatch, database)
    database.add_run(evidence=["wget", "uname -a", "cat /proc/cpuinfo"])
    run_sync()

    database.add_run(evidence=["cd /tmp", "whoami", "wget"])
    run_sync()

    assert stored_issue(database, "automated_scanner", "T1087")["sample_evidence"] == [
        "cat /proc/cpuinfo",
        "cd /tmp",
        "uname -a",
        "wget",
        "whoami",
    ]


def test_full_sync_rebuilds_even_after_the_first_rebuild(monkeypatch):
    database = FakeDatabase()
    use_fake_database(monkeypatch, database)
    database.add_run()
    run_sync()
    database.loads.clear()

    run_sync(full=True)

    assert database.loads[0] == {"run_ids": None, "pair": None}


def test_rebuild_replaces_stored_totals_instead_of_adding_to_them(monkeypatch):
    database = FakeDatabase()
    use_fake_database(monkeypatch, database)
    database.add_run()
    database.add_run()
    run_sync()

    run_sync(full=True)

    assert stored_issue(database, "automated_scanner", "T1087")["session_count"] == 2


def test_sync_raises_when_another_process_is_syncing(monkeypatch):
    database = FakeDatabase()
    database.locked_elsewhere = True
    use_fake_database(monkeypatch, database)

    with pytest.raises(issue_sync.IssueSyncInProgressError):
        run_sync()


def test_sync_issues_from_classifier_runs_skips_repeat_connections_when_none_qualify(monkeypatch):
    database = FakeDatabase()
    use_fake_database(monkeypatch, database)

    assert run_sync() == []


def test_classifier_runs_do_not_overwrite_the_repeat_connection_issue(monkeypatch):
    database = FakeDatabase()
    database.repeat_aggregate = {"session_count": 62, "persona_count": 4, "source_ip_count": 3}
    use_fake_database(monkeypatch, database)
    database.add_run(actor_label="brute_force_bot", mitre_tag="T1110")
    run_sync()

    database.add_run(actor_label="brute_force_bot", mitre_tag="T1110")
    run_sync()

    issue = stored_issue(database, "brute_force_bot", "T1110")
    assert issue["rollup_source"] == "repeat_connections"
    assert issue["session_count"] == 62


def test_issue_returns_to_classifier_runs_when_repeat_connections_stop(monkeypatch):
    database = FakeDatabase()
    database.repeat_aggregate = {"session_count": 62, "persona_count": 4, "source_ip_count": 3}
    use_fake_database(monkeypatch, database)
    database.add_run(actor_label="brute_force_bot", mitre_tag="T1110")
    run_sync()
    database.add_run(actor_label="brute_force_bot", mitre_tag="T1110")
    run_sync()

    database.repeat_aggregate = None
    database.loads.clear()
    run_sync()

    issue = stored_issue(database, "brute_force_bot", "T1110")
    assert database.loads == [{"run_ids": None, "pair": ("brute_force_bot", "T1110")}]
    assert issue["rollup_source"] == "classifier"
    assert issue["session_count"] == 2


def test_sync_issues_from_classifier_runs_includes_repeat_connection_issue(monkeypatch):
    database = FakeDatabase()
    database.repeat_aggregate = {"session_count": 62, "persona_count": 4, "source_ip_count": 3}
    use_fake_database(monkeypatch, database)

    result = run_sync()

    assert len(result) == 1
    issue = result[0]
    assert issue.session_count == 62
    assert issue.persona_count == 4
    assert issue.severity == "high"
    assert issue.mitre == [MitreTechnique(id="T1110", name="Brute Force")]
    assert "62 connection attempts across 4 personas from 3 source IPs" in issue.evidence
    assert "each making at least 5 connections within 1 day" in issue.evidence


def test_build_repeat_connection_issue_severity_thresholds():
    playbook = IssuePlaybook()
    low = issue_sync._build_repeat_connection_issue(
        {"session_count": 6, "persona_count": 1, "source_ip_count": 1},
        playbook,
        mitre_catalog={},
        window_seconds=3600,
        min_sessions=5,
    )
    medium = issue_sync._build_repeat_connection_issue(
        {"session_count": 20, "persona_count": 1, "source_ip_count": 1},
        playbook,
        mitre_catalog={},
        window_seconds=3600,
        min_sessions=5,
    )
    high = issue_sync._build_repeat_connection_issue(
        {"session_count": 80, "persona_count": 1, "source_ip_count": 1},
        playbook,
        mitre_catalog={},
        window_seconds=3600,
        min_sessions=5,
    )

    assert (low.severity, medium.severity, high.severity) == ("low", "medium", "high")
    assert "1 hour" in low.evidence


def test_repository_aggregate_repeat_connections_returns_none_when_no_offenders(monkeypatch):
    from classifier.storage.repository import PostgresClassifierRepository

    monkeypatch.setattr(
        "classifier.storage.repository._fetch_one",
        lambda *args, **kwargs: {"session_count": 0, "persona_count": 0, "source_ip_count": 0},
    )

    result = PostgresClassifierRepository("postgresql://example/echidra").aggregate_repeat_connections_by_peer_ip()

    assert result is None


def test_repository_aggregate_repeat_connections_returns_row_when_offenders_exist(monkeypatch):
    from classifier.storage.repository import PostgresClassifierRepository

    row = {"session_count": 12, "persona_count": 2, "source_ip_count": 1}
    calls = []

    def fake_fetch_one(database_url, sql, params):
        calls.append(params)
        return row

    monkeypatch.setattr("classifier.storage.repository._fetch_one", fake_fetch_one)

    result = PostgresClassifierRepository("postgresql://example/echidra").aggregate_repeat_connections_by_peer_ip(
        window_seconds=3600, min_sessions=10
    )

    assert result == row
    assert calls == [{"window_seconds": 3600, "min_sessions": 10}]
