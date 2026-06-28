from classifier.rules.issue_playbook import IssueFixEntry, IssuePlaybook
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
    assert "24 sessions across 3 personas exhibited Account Discovery behavior in captured data." == issue.evidence


def test_build_issue_falls_back_when_pair_has_no_curated_fix():
    aggregate = make_aggregate(actor_label="brute_force_bot", mitre_tag="T1110", max_risk_rank=3)
    playbook = IssuePlaybook()
    mitre_catalog = {"T1110": "Brute Force"}

    issue = issue_sync._build_issue(aggregate, playbook, mitre_catalog)

    assert issue.title == "Brute Force Bot are exhibiting Brute Force behavior."
    assert issue.recommended_fix == issue_sync._FALLBACK_RECOMMENDED_FIX
    assert issue.impact == issue_sync._FALLBACK_IMPACT
    assert issue.severity == "high"
    assert issue.mitre == [MitreTechnique(id="T1110", name="Brute Force")]


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


def test_sync_issues_from_classifier_runs_upserts_one_issue_per_pair(monkeypatch):
    aggregates = [
        make_aggregate(actor_label="automated_scanner", mitre_tag="T1087", session_count=24, persona_count=3, max_risk_rank=2),
        make_aggregate(actor_label="commodity_bot", mitre_tag="T1552.001", session_count=9, persona_count=2, max_risk_rank=3),
    ]
    upserted = []

    class FakeRepository:
        def __init__(self, database_url):
            assert database_url == "postgresql://example/echidra"

        def aggregate_classifier_runs_by_actor_and_technique(self):
            return aggregates

        def upsert_issue(self, issue):
            upserted.append(issue)
            return issue

    monkeypatch.setattr(issue_sync, "PostgresClassifierRepository", FakeRepository)

    result = issue_sync.sync_issues_from_classifier_runs(database_url="postgresql://example/echidra")

    # Uses the real shipped issue_playbook.yaml + mitre_technique_names.json.
    assert [issue.title for issue in result] == [
        "Automated scanners are enumerating accounts before deciding where to focus.",
        "Commodity bots are searching for credentials stored in files.",
    ]
    assert result == upserted
    assert result[0].severity == "medium"
    assert result[1].severity == "high"
