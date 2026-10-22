"""Tests for classifier/catch_up.py: keeping sessions the database couldn't
take, and storing them once it's reachable again."""

import os
import stat
import uuid

import pytest

import classifier.alerts as alerts_module
import classifier.catch_up as catch_up_module
import classifier.pipeline as pipeline_module
import classifier.storage as storage_module
import classifier.storage.issue_sync as issue_sync_module
from classifier.schemas.session import SessionRecord
from tests.test_classifier_pipeline import make_record

psycopg = pytest.importorskip("psycopg")


def _session():
    return SessionRecord.model_validate(make_record(session_id=str(uuid.uuid4())))


class _Repository:
    """Database stand-in: reachable unless told otherwise, with some sessions
    already stored."""

    reachable = True
    already_stored: set = set()

    def ping(self):
        if not self.reachable:
            raise psycopg.OperationalError("connection refused")

    def stored_session_ids(self, session_ids):
        return {session_id for session_id in session_ids if session_id in self.already_stored}


@pytest.fixture
def stored_and_alerted(monkeypatch):
    """Records what catch_up_pending_sessions stores and alerts on."""
    _Repository.reachable = True
    _Repository.already_stored = set()
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", _Repository)
    monkeypatch.setattr(issue_sync_module, "maybe_sync_issues_from_classifier_runs", lambda: None)
    result = {"stored": [], "alerted": []}

    def fake_classify_and_store(session, repository, rules=None):
        result["stored"].append(session.session_id)
        return None, object()

    monkeypatch.setattr(pipeline_module, "classify_and_store", fake_classify_and_store)
    monkeypatch.setattr(alerts_module, "send_catch_up_alerts", result["alerted"].append)
    return result


def test_kept_sessions_are_owner_only_and_counted(tmp_path):
    path = tmp_path / "pending-sessions.jsonl"

    catch_up_module.keep_pending_session(_session(), path)
    catch_up_module.keep_pending_session(_session(), path)

    assert catch_up_module.count_pending_sessions(path) == 2
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_catch_up_waits_while_the_database_is_unreachable(tmp_path, stored_and_alerted):
    path = tmp_path / "pending-sessions.jsonl"
    catch_up_module.keep_pending_session(_session(), path)
    _Repository.reachable = False

    assert catch_up_module.catch_up_pending_sessions(path) == 0

    assert stored_and_alerted["stored"] == []
    assert catch_up_module.count_pending_sessions(path) == 1


def test_catch_up_stores_pending_sessions_once_and_sends_one_summary(tmp_path, stored_and_alerted):
    path = tmp_path / "pending-sessions.jsonl"
    first, second = _session(), _session()
    catch_up_module.keep_pending_session(first, path)
    catch_up_module.keep_pending_session(second, path)
    _Repository.already_stored = {first.session_id}

    assert catch_up_module.catch_up_pending_sessions(path) == 1

    assert stored_and_alerted["stored"] == [second.session_id]
    assert len(stored_and_alerted["alerted"]) == 1
    assert catch_up_module.count_pending_sessions(path) == 0


def test_catch_up_puts_sessions_back_when_the_database_drops_again(
    tmp_path, stored_and_alerted, monkeypatch
):
    path = tmp_path / "pending-sessions.jsonl"
    first, second = _session(), _session()
    catch_up_module.keep_pending_session(first, path)
    catch_up_module.keep_pending_session(second, path)

    def drops_on_the_second(session, repository):
        if session.session_id == second.session_id:
            raise psycopg.OperationalError("server closed the connection unexpectedly")
        stored_and_alerted["stored"].append(session.session_id)
        return None, object()

    monkeypatch.setattr(pipeline_module, "classify_and_store", drops_on_the_second)

    assert catch_up_module.catch_up_pending_sessions(path) == 1

    # Both go back; the first is skipped next time as already stored.
    assert catch_up_module.count_pending_sessions(path) == 2
    assert len(stored_and_alerted["alerted"]) == 1


def test_catch_up_skips_a_session_that_fails_for_another_reason(
    tmp_path, stored_and_alerted, monkeypatch
):
    path = tmp_path / "pending-sessions.jsonl"
    broken, fine = _session(), _session()
    catch_up_module.keep_pending_session(broken, path)
    catch_up_module.keep_pending_session(fine, path)

    def fails_on_broken(session, repository):
        if session.session_id == broken.session_id:
            raise ValueError("unknown feature field")
        stored_and_alerted["stored"].append(session.session_id)
        return None, object()

    monkeypatch.setattr(pipeline_module, "classify_and_store", fails_on_broken)

    assert catch_up_module.catch_up_pending_sessions(path) == 1

    assert stored_and_alerted["stored"] == [fine.session_id]
    assert catch_up_module.count_pending_sessions(path) == 0


def test_catch_up_resumes_a_catch_up_that_stopped_part_way(tmp_path, stored_and_alerted):
    path = tmp_path / "pending-sessions.jsonl"
    session = _session()
    catching_up = tmp_path / "pending-sessions.jsonl.catching-up"
    catching_up.write_text(session.model_dump_json() + "\n", encoding="utf-8")

    assert catch_up_module.catch_up_pending_sessions(path) == 1

    assert stored_and_alerted["stored"] == [session.session_id]
    assert not catching_up.exists()


def test_catch_up_skips_a_session_stored_meanwhile_by_another_process(
    tmp_path, stored_and_alerted, monkeypatch
):
    path = tmp_path / "pending-sessions.jsonl"
    catch_up_module.keep_pending_session(_session(), path)
    monkeypatch.setattr(pipeline_module, "classify_and_store", lambda session, repository: None)

    assert catch_up_module.catch_up_pending_sessions(path) == 0

    assert stored_and_alerted["alerted"] == []
    assert catch_up_module.count_pending_sessions(path) == 0


def test_import_stores_new_sessions_and_counts_the_rest(tmp_path, stored_and_alerted):
    log = tmp_path / "sessions.jsonl"
    old, new = _session(), _session()
    log.write_text(
        old.model_dump_json() + "\n" + "not json\n" + "\n" + new.model_dump_json() + "\n",
        encoding="utf-8",
    )
    _Repository.already_stored = {old.session_id}

    result = catch_up_module.import_session_log(log)

    assert stored_and_alerted["stored"] == [new.session_id]
    assert (result.stored, result.already_stored, result.invalid_lines, result.failed) == (1, 1, 1, 0)
    # Imported sessions are usually old: no alerts.
    assert stored_and_alerted["alerted"] == []


def test_import_refuses_to_start_while_the_database_is_unreachable(tmp_path, stored_and_alerted):
    log = tmp_path / "sessions.jsonl"
    log.write_text(_session().model_dump_json() + "\n", encoding="utf-8")
    _Repository.reachable = False

    with pytest.raises(psycopg.OperationalError):
        catch_up_module.import_session_log(log)

    assert stored_and_alerted["stored"] == []


def test_auto_classification_keeps_the_session_when_the_database_is_unreachable(monkeypatch):
    class Repository:
        def record_session_and_count_from_ip(self, session):
            raise psycopg.OperationalError("connection refused")

        def save_classifier_run(self, session, summary):
            raise psycopg.OperationalError("connection refused")

    kept = []
    monkeypatch.setattr(storage_module, "PostgresClassifierRepository", Repository)
    monkeypatch.setattr(catch_up_module, "keep_pending_session", kept.append)
    session = _session()

    pipeline_module.auto_classify_and_store(session)

    assert kept == [session]
