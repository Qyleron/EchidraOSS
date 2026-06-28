"""Roll real classifier output up into persisted, analyst-triaged issues."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID, NAMESPACE_URL, uuid5

from classifier.rules.issue_playbook import (
    DEFAULT_MITRE_CATALOG_PATH,
    IssuePlaybook,
    load_issue_playbook,
    load_mitre_technique_catalog,
)
from classifier.storage.models import IssueRecord, MitreTechnique
from classifier.storage.repository import PostgresClassifierRepository


DEFAULT_ISSUE_PLAYBOOK_PATH = Path(__file__).resolve().parents[1] / "rules" / "issue_playbook.yaml"
_FALLBACK_RECOMMENDED_FIX = (
    "Review matched session output and triage manually; add an entry for this "
    "actor/technique pair to classifier/rules/issue_playbook.yaml to automate "
    "this recommendation."
)
_FALLBACK_IMPACT = "Impact not yet documented for this pair in issue_playbook.yaml."
_RISK_RANK_SEVERITIES = {4: "high", 3: "high", 2: "medium", 1: "low", 0: "low"}


def sync_issues_from_classifier_runs(
    *,
    database_url: str | None = None,
    playbook_path: str | Path = DEFAULT_ISSUE_PLAYBOOK_PATH,
    mitre_catalog_path: str | Path = DEFAULT_MITRE_CATALOG_PATH,
) -> list[IssueRecord]:
    """Aggregate stored classifier runs by (actor_label, MITRE technique).

    Each pair maps to a stable issue id, so re-running this is idempotent:
    counts get refreshed from real captured sessions but an analyst's
    open/closed status is never reset. Unlike a rule-id rollup, this reads
    directly off classifier_runs/classifier_signals -- any actor/technique
    combination your classifier actually produces shows up here, even
    without a dedicated rule written just for it.
    """
    playbook = load_issue_playbook(playbook_path)
    mitre_catalog = load_mitre_technique_catalog(mitre_catalog_path)

    repository = PostgresClassifierRepository(database_url)
    synced: list[IssueRecord] = []
    for aggregate in repository.aggregate_classifier_runs_by_actor_and_technique():
        issue = _build_issue(aggregate, playbook, mitre_catalog)
        synced.append(repository.upsert_issue(issue))

    return synced


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

    return IssueRecord(
        id=_issue_id_for_pair(actor_label, mitre_tag),
        title=fix.title if fix else f"{actor_display} are exhibiting {technique_name} behavior.",
        severity=_RISK_RANK_SEVERITIES[aggregate["max_risk_rank"]],
        evidence=_build_evidence(aggregate, technique_name),
        recommended_fix=fix.recommended_fix if fix else _FALLBACK_RECOMMENDED_FIX,
        impact=fix.impact if fix else _FALLBACK_IMPACT,
        session_count=aggregate["session_count"],
        persona_count=aggregate["persona_count"],
        mitre=[MitreTechnique(id=mitre_tag, name=technique_name)],
    )


def _technique_name(tag: str, playbook: IssuePlaybook, mitre_catalog: dict[str, str]) -> str:
    return playbook.mitre_technique_names.get(tag) or mitre_catalog.get(tag, tag)


def _build_evidence(aggregate: dict[str, Any], technique_name: str) -> str:
    return (
        f"{aggregate['session_count']} sessions across {aggregate['persona_count']} "
        f"personas exhibited {technique_name} behavior in captured data."
    )


def _issue_id_for_pair(actor_label: str, mitre_tag: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"echidra-issue-actor-technique:{actor_label}:{mitre_tag}")
