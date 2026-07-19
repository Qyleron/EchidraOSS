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
