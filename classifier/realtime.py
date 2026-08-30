"""Periodic classification of an active honeypot session."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from functools import lru_cache
from typing import Any

from classifier.pipeline import DEFAULT_RULES_PATH, classify_session
from classifier.rules.engine import RuleSet, load_rules
from classifier.schemas.session import SessionRecord
from classifier.scoring.session import ClassificationSummary

logger = logging.getLogger(__name__)
LiveResultCallback = Callable[[ClassificationSummary], Awaitable[None] | None]
LIVE_RULE_IDS = {
    "automated_discovery_burst",
    "sensitive_file_probe",
    "repeat_connections_same_ip",
    "authentication_attempt",
    "script_kiddie_tool_names",
    "interactive_low_and_slow",
}


@lru_cache(maxsize=1)
def load_live_rules() -> RuleSet:
    """Load only rules whose inputs are meaningful before session close."""
    rules = load_rules(DEFAULT_RULES_PATH)
    return RuleSet(
        rules_version=rules.rules_version,
        rules=[rule for rule in rules.rules if rule.id in LIVE_RULE_IDS],
    )


class LiveSessionClassifier:
    """Classify a mutable session snapshot periodically until cancelled."""

    def __init__(
        self,
        session: Any,
        *,
        interval_seconds: float = 30.0,
        on_result: LiveResultCallback | None = None,
    ) -> None:
        self.session = session
        self.interval_seconds = interval_seconds
        self.on_result = on_result
        self.latest_summary: ClassificationSummary | None = None
        self.highest_alerted_rank = -1
        self.rules = load_live_rules()

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self.interval_seconds)
            try:
                summary = classify_session(self._snapshot(), self.rules, active=True)
                self.latest_summary = summary
                if self.on_result is not None:
                    result = self.on_result(summary)
                    if result is not None:
                        await asyncio.wait_for(result, timeout=5)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Live classification failed for session %s", self.session.session_id)

    def _snapshot(self) -> SessionRecord:
        return SessionRecord.model_validate(self.session.active_record())
