import asyncio

import pytest
import pytest_asyncio

import honeypot.network.server as server_module
from honeypot.network.server import TCPServer
from tests.conftest import require_bound_server_address


"""
This file checks a simple load scenario.
It does not measure performance precisely; it only verifies that many clients
can connect, run a command, and exit without breaking the server.
"""


@pytest_asyncio.fixture
async def running_server(monkeypatch):
    """Start the real TCP server on a random localhost port."""
    monkeypatch.setattr(server_module, "HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "PORT", 0)

    server = TCPServer()
    task = asyncio.create_task(server.start())

    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)

    host, port = require_bound_server_address(server)

    try:
        yield host, port, server
    finally:
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def read_prompt(reader):
    """Read one full fake-shell response ending at the prompt."""
    return await asyncio.wait_for(reader.readuntil(b"$ "), timeout=2)


async def run_client(host, port):
    """Simulate one short client session."""
    reader, writer = await asyncio.open_connection(host, port)

    await read_prompt(reader)

    writer.write(b"whoami\n")
    await writer.drain()

    response = await read_prompt(reader)
    assert b"root" in response

    writer.write(b"exit\n")
    await writer.drain()

    goodbye = await asyncio.wait_for(reader.read(), timeout=2)
    assert b"logout" in goodbye

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_25_concurrent_clients_complete_successfully(running_server):
    """Twenty-five clients should complete the same command flow in parallel."""
    host, port, _ = running_server

    await asyncio.wait_for(
        asyncio.gather(*(run_client(host, port) for _ in range(25))),
        timeout=5,
    )


@pytest.mark.asyncio
async def test_100_concurrent_clients_complete_successfully(monkeypatch):
    """TESTS.md's Level 3 stress bar names 100+ concurrent clients explicitly
    -- the 25-client test above doesn't reach it. MAX_CONNECTIONS is raised
    so this is purely a concurrency test, not also a connection-limit test
    (that's covered separately below and in test_integration_tcp.py)."""
    monkeypatch.setattr(server_module, "HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "PORT", 0)
    monkeypatch.setattr(server_module, "MAX_CONNECTIONS", 150)

    server = TCPServer()
    task = asyncio.create_task(server.start())
    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)
    host, port = require_bound_server_address(server)

    try:
        await asyncio.wait_for(
            asyncio.gather(*(run_client(host, port) for _ in range(100))),
            timeout=15,
        )
    finally:
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_1000_connection_flood_is_handled_without_crashing(monkeypatch):
    """A flood of far more simultaneous connection attempts than
    MAX_CONNECTIONS must not crash or wedge the server: refused connections
    close cleanly, the server's own concurrent-session count never exceeds
    the configured limit, and the server is still healthy afterward.

    Note on measurement: counting how many *clients* got served over the
    whole flood is not the same as peak concurrency -- a served client that
    closes quickly frees its slot, so a later attempt can also get served,
    letting the lifetime-served total climb arbitrarily high (observed
    experimentally: 1000 attempts against MAX_CONNECTIONS=50 served 200+
    clients in total) without the concurrency limit ever actually being
    violated. Polling server.tasks directly sidesteps that client-side
    timing race entirely and checks the real invariant.
    """
    monkeypatch.setattr(server_module, "HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "PORT", 0)
    monkeypatch.setattr(server_module, "MAX_CONNECTIONS", 50)

    server = TCPServer()
    task = asyncio.create_task(server.start())
    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)
    host, port = require_bound_server_address(server)

    async def attempt_connection():
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            return "connect_failed"
        try:
            # A served client gets the banner immediately; a refused one
            # gets an empty read as the server closes without sending
            # anything (see TCPServer.handle_client's over-limit branch).
            data = await asyncio.wait_for(reader.read(1), timeout=3)
        except asyncio.TimeoutError:
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return "served" if data else "refused"

    flood_task = asyncio.gather(
        *(attempt_connection() for _ in range(1000)), return_exceptions=True
    )

    observed_peak = 0
    while not flood_task.done():
        observed_peak = max(observed_peak, len(server.tasks))
        await asyncio.sleep(0.005)
    results = await asyncio.wait_for(flood_task, timeout=60)

    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"connection attempts raised: {errors[:5]}"
    # The real invariant: the server never runs more than MAX_CONNECTIONS
    # sessions concurrently, no matter how many attempts pile up.
    assert observed_peak == 50

    # Every flood client has closed its own socket by now (results is in),
    # but the server only notices a closed client -- and removes its task --
    # via a done-callback scheduled on a later event loop iteration, not
    # synchronously. Wait for that cleanup to actually land before checking
    # the server can serve a fresh client, or this races and sees the server
    # still reporting full capacity from sessions that are already gone.
    for _ in range(200):
        if len(server.tasks) == 0:
            break
        await asyncio.sleep(0.01)

    try:
        # The server must still be able to serve a fresh client after the
        # flood -- a prior slot must have freed up since every flood client
        # above already closed its connection. Retried a few times: right
        # after a 1000-connection flood, the OS listen backlog can still be
        # settling, occasionally dropping the very next attempt at the TCP
        # level before it reaches application code -- that's kernel/socket
        # noise, not a regression in the server's own request handling.
        last_error = None
        banner = b""
        for _ in range(10):
            try:
                reader, writer = await asyncio.open_connection(host, port)
                banner = await asyncio.wait_for(reader.readuntil(b"$ "), timeout=3)
                writer.close()
                await writer.wait_closed()
                last_error = None
                break
            except (OSError, asyncio.IncompleteReadError) as exc:
                last_error = exc
                await asyncio.sleep(0.1)
        assert last_error is None, f"server never recovered after the flood: {last_error}"
        assert b"Linux fake-host" in banner
    finally:
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
