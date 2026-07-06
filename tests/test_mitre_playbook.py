import re
from pathlib import Path

from classifier.rules.mitre_playbook import get_playbook_entry, load_technique_playbook

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "classifier" / "rules" / "default_rules.yaml"


def test_get_playbook_entry_returns_curated_fix_for_known_technique():
    entry = get_playbook_entry("T1110")

    assert entry.technique_id == "T1110"
    assert entry.name == "Brute Force"
    assert entry.is_fallback is False
    assert entry.recommended_fix
    assert entry.impact


def test_get_playbook_entry_falls_back_for_unknown_technique():
    entry = get_playbook_entry("T9999")

    assert entry.technique_id == "T9999"
    assert entry.name == "T9999"
    assert entry.is_fallback is True
    assert entry.recommended_fix
    assert entry.impact


def test_get_playbook_entry_fallback_guidance_is_non_empty_for_unknown_technique():
    entry = get_playbook_entry("T9999")

    assert entry.is_fallback is True
    assert entry.technique_id == "T9999"
    assert entry.recommended_fix.strip()
    assert entry.impact.strip()


def test_every_technique_the_classifier_can_produce_has_a_curated_entry():
    """Every mitre_tags value in default_rules.yaml must resolve without falling back."""
    rules_text = DEFAULT_RULES_PATH.read_text(encoding="utf-8")
    technique_ids = set(re.findall(r"T\d{4}(?:\.\d{3})?", rules_text))
    assert technique_ids, "expected at least one MITRE technique id in default_rules.yaml"

    playbook = load_technique_playbook()
    missing = technique_ids - playbook.keys()
    assert not missing, f"mitre_playbook.yaml is missing entries for: {sorted(missing)}"

    for technique_id in technique_ids:
        entry = get_playbook_entry(technique_id)
        assert entry.is_fallback is False, f"{technique_id} unexpectedly used the generic fallback"
