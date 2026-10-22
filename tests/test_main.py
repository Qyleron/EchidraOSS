import asyncio
import os
import signal

import pytest

import honeypot.main as main_module


class _FailsToBindListener:
    """Stands in for SSHListener/ProtocolServer when every port is taken."""

    async def start(self):
        raise OSError(98, "error while attempting to bind on address")

    async def shutdown(self):
        pass


class _RunsUntilCancelledListener:
    """Stands in for a listener that bound successfully and is serving."""

    def __init__(self):
        self._stop = asyncio.Event()

    async def start(self):
        await self._stop.wait()

    async def shutdown(self):
        self._stop.set()


@pytest.fixture(autouse=True)
def _disable_extra_ports_and_classification(monkeypatch):
    monkeypatch.setattr(main_module, "HTTP_PORT", 0)
    monkeypatch.setattr(main_module, "FTP_PORT", 0)
    monkeypatch.setattr(main_module, "TELNET_PORT", 0)
    monkeypatch.setattr(main_module, "start_classification_workers", lambda: None)

    async def fake_stop_classification_workers():
        pass

    monkeypatch.setattr(main_module, "stop_classification_workers", fake_stop_classification_workers)
    monkeypatch.setattr(main_module, "catch_up_pending_sessions", lambda: 0)


def test_main_exits_nonzero_when_every_listener_fails_to_bind(monkeypatch):
    monkeypatch.setattr(main_module, "SSHListener", _FailsToBindListener)

    with pytest.raises(SystemExit) as exc_info:
        asyncio.run(main_module.main())

    assert exc_info.value.code == 1


def test_main_returns_normally_on_graceful_shutdown(monkeypatch):
    monkeypatch.setattr(main_module, "SSHListener", _RunsUntilCancelledListener)

    async def run_and_signal_shutdown():
        task = asyncio.create_task(main_module.main())
        await asyncio.sleep(0.1)
        os.kill(os.getpid(), signal.SIGTERM)
        await task

    # No SystemExit -- a listener that's still running when the shutdown
    # signal arrives is a clean stop, not the all-failed error path.
    asyncio.run(run_and_signal_shutdown())


def test_start_updates_the_database_tables(monkeypatch):
    """An upgrade must work without running init-db by hand."""
    import classifier.storage.repository as repository_module

    calls = []
    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://echidra:secret@db/echidra")
    monkeypatch.setattr(
        repository_module,
        "apply_schema",
        lambda url, **kwargs: calls.append((url, kwargs)),
    )

    main_module._update_database_schema()

    assert calls == [("postgresql://echidra:secret@db/echidra", {"lock_timeout_seconds": 5})]


def test_start_without_a_database_leaves_the_tables_alone(monkeypatch):
    import classifier.storage.repository as repository_module

    def must_not_run(*args, **kwargs):
        raise AssertionError("no database is configured")

    monkeypatch.setattr(repository_module, "apply_schema", must_not_run)

    main_module._update_database_schema()


def test_a_failed_table_update_says_what_to_run_and_still_starts(monkeypatch, caplog):
    import classifier.storage.repository as repository_module

    def unreachable(url, **kwargs):
        raise OSError("connection to postgresql://echidra:secret@db/echidra failed")

    monkeypatch.setenv("ECHIDRA_DATABASE_URL", "postgresql://echidra:secret@db/echidra")
    monkeypatch.setattr(repository_module, "apply_schema", unreachable)

    with caplog.at_level("WARNING", logger=main_module.logger.name):
        main_module._update_database_schema()

    assert len(caplog.records) == 1
    message = caplog.records[0].message
    assert "init-db" in message and "Upgrading" in message
    assert "secret" not in message
