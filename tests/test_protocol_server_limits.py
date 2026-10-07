import asyncio

import pytest
import pytest_asyncio

from honeypot.network.protocol_server import ProtocolServer
from tests.conftest import require_bound_server_address


"""Real-socket coverage for ProtocolServer's global MAX_CONNECTIONS limit.

The check-then-add in _handle_client (len(self.tasks) >= max_connections,
then self.tasks.add(task)) has no await between the two, so under asyncio's
cooperative scheduler it is atomic with respect to other connections. These
tests pin that behavior with real TCP clients: the connection over the limit
is closed immediately, the one under it is untouched, and a slot frees up
again once a handler finishes. Replaces the old
tests/test_integration_tcp.py::test_server_rejects_connections_over_global_limit,
deleted along with that file in 7d75957."""


def _holding_handler(started: asyncio.Event, release: asyncio.Event) -> type:
    """Build a handler that keeps its connection open until `release` is set."""

    class HoldingHandler:
        def __init__(self, reader, writer, session_logger=None):
            self.reader = reader
            self.writer = writer

        async def handle(self):
            started.set()
            await release.wait()
            self.writer.write(b"ok")
            await self.writer.drain()
            self.writer.close()
            await self.writer.wait_closed()

    return HoldingHandler


@pytest_asyncio.fixture
async def limited_server():
    """Start a real ProtocolServer with max_connections=1 and a holding handler."""
    started = asyncio.Event()
    release = asyncio.Event()
    server = ProtocolServer(
        "127.0.0.1",
        0,
        _holding_handler(started, release),
        max_connections=1,
        session_logger=object(),
    )
    task = asyncio.create_task(server.start())

    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)

    host, port = require_bound_server_address(server)

    try:
        yield server, host, port, started, release
    finally:
        release.set()
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_connection_over_global_limit_is_closed_immediately(limited_server):
    server, host, port, started, release = limited_server

    first_reader, first_writer = await asyncio.open_connection(host, port)
    await asyncio.wait_for(started.wait(), timeout=5)
    assert len(server.tasks) == 1

    second_reader, second_writer = await asyncio.open_connection(host, port)
    # Server closes the over-limit socket without sending anything: EOF.
    assert await asyncio.wait_for(second_reader.read(), timeout=5) == b""
    assert len(server.tasks) == 1
    second_writer.close()
    await second_writer.wait_closed()

    # The connection under the limit was never disturbed.
    release.set()
    assert await asyncio.wait_for(first_reader.read(), timeout=5) == b"ok"
    first_writer.close()
    await first_writer.wait_closed()


@pytest.mark.asyncio
async def test_slot_is_freed_once_a_handler_finishes(limited_server):
    server, host, port, started, release = limited_server

    release.set()  # handlers finish as soon as they start
    first_reader, first_writer = await asyncio.open_connection(host, port)
    assert await asyncio.wait_for(first_reader.read(), timeout=5) == b"ok"
    first_writer.close()
    await first_writer.wait_closed()

    # done_callback discards the finished task, so the next client is accepted.
    for _ in range(50):
        if not server.tasks:
            break
        await asyncio.sleep(0.01)
    assert not server.tasks

    second_reader, second_writer = await asyncio.open_connection(host, port)
    assert await asyncio.wait_for(second_reader.read(), timeout=5) == b"ok"
    second_writer.close()
    await second_writer.wait_closed()
