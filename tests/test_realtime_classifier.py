import asyncio
import time

import pytest

from classifier.realtime import LIVE_RULE_IDS, LiveSessionClassifier, load_live_rules
from honeypot.core.session import SessionState


@pytest.mark.asyncio
async def test_live_classifier_emits_partial_result_without_real_time_wait():
    session = SessionState(("127.0.0.1", 4444))
    session.start_time = time.time() - 10
    for command in ("whoami", "hostname", "ls"):
        session.log_command(command)

    observed = []
    ready = asyncio.Event()

    def receive(summary):
        observed.append(summary)
        ready.set()

    classifier = LiveSessionClassifier(
        session,
        interval_seconds=0.001,
        on_result=receive,
    )
    task = asyncio.create_task(classifier.run())
    await asyncio.wait_for(ready.wait(), timeout=1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert observed[0].classification_status == "partial"
    assert observed[0].feature_summary.command_count == 3


def test_live_snapshot_does_not_finalize_the_real_session():
    session = SessionState(("127.0.0.1", 4444))

    snapshot = LiveSessionClassifier(session)._snapshot()

    assert snapshot.end_reason == "disconnect"
    assert session.end_time is None
    assert session.end_reason is None


def test_live_rules_exclude_post_session_clean_exit_rule():
    rules = load_live_rules()

    assert {rule.id for rule in rules.rules} == LIVE_RULE_IDS
    assert "scripted_probe_with_clean_exit" not in LIVE_RULE_IDS
