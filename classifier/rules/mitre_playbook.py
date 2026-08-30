"""Technique-keyed fix lookup for the Intelligence page's MITRE reference.

See mitre_playbook.yaml for how this differs from issue_playbook.py's
actor_label + technique mapping.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from classifier.rules.issue_playbook import load_mitre_technique_catalog

DEFAULT_MITRE_PLAYBOOK_PATH = Path(__file__).with_name("mitre_playbook.yaml")

_GENERIC_FALLBACK_FIX = (
    "Review the session evidence for this technique and triage manually; add "
    "an entry to classifier/rules/mitre_playbook.yaml to automate this "
    "recommendation."
)
_GENERIC_FALLBACK_IMPACT = "Impact not yet documented for this technique in mitre_playbook.yaml."


class _RawPlaybookEntry(BaseModel):
    """One curated YAML entry, keyed externally by technique id."""

    name: str = Field(min_length=1)
    recommended_fix: str = Field(min_length=1)
    impact: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class PlaybookEntry(BaseModel):
    """The fix guidance returned for one MITRE technique id."""

    technique_id: str
    name: str
    recommended_fix: str
    impact: str
    is_fallback: bool

    model_config = ConfigDict(extra="forbid")


@lru_cache(maxsize=1)
def load_technique_playbook(
    path: str | Path = DEFAULT_MITRE_PLAYBOOK_PATH,
) -> dict[str, _RawPlaybookEntry]:
    """Load and validate the technique_id -> fix mapping from YAML."""
    with open(path, encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    return {
        technique_id: _RawPlaybookEntry.model_validate(entry)
        for technique_id, entry in raw.items()
    }


def get_playbook_entry(technique_id: str) -> PlaybookEntry:
    """Return the curated fix for one MITRE technique id.

    Falls back to a generic, clearly-labeled entry for any technique id not
    yet written up, so newly observed classifier output always has something
    to show on the Intelligence page instead of a blank cell.
    """
    entry = load_technique_playbook().get(technique_id)
    if entry is None:
        technique_name = load_mitre_technique_catalog().get(technique_id, technique_id)
        return PlaybookEntry(
            technique_id=technique_id,
            name=technique_name,
            recommended_fix=_GENERIC_FALLBACK_FIX,
            impact=_GENERIC_FALLBACK_IMPACT,
            is_fallback=True,
        )
    return PlaybookEntry(
        technique_id=technique_id,
        name=entry.name,
        recommended_fix=entry.recommended_fix,
        impact=entry.impact,
        is_fallback=False,
    )
