import asyncio

import pytest
import pytest_asyncio

import honeypot.network.server as server_module
from honeypot.network.server import TCPServer
from tests.conftest import require_bound_server_address


"""
These are end-to-end TCP tests.
They start the real asyncio server on localhost, connect a real client, then
verify that banner, command handling, and connection limits work together.
"""


@pytest_asyncio.fixture
async def running_server(monkeypatch):
    """Start a temporary server on a random localhost port for one test."""
    # Patch the imported server module values, not the config file itself.
    monkeypatch.setattr(server_module, "HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "PORT", 0)

    server = TCPServer()
    task = asyncio.create_task(server.start())

    # Wait briefly for asyncio.start_server() to finish binding the socket.
    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)

    host, port = require_bound_server_address(server)

    try:
        yield host, port, server
    finally:
        # Always close the server task so tests do not leak background work.
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def read_prompt(reader):
    """Read until the fake shell prompt appears."""
    return await asyncio.wait_for(reader.readuntil(b"$ "), timeout=1)


@pytest.mark.asyncio
async def test_tcp_client_receives_banner(running_server):
    """A real TCP client should receive the login banner immediately."""
    host, port, _ = running_server

    reader, writer = await asyncio.open_connection(host, port)

    banner = await read_prompt(reader)

    assert b"Linux fake-host" in banner
    assert b"/home/admin$ " in banner

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_tcp_client_can_run_command_and_exit(running_server):
    """A real TCP client should run a command, then exit cleanly."""
    host, port, _ = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    writer.write(b"whoami\n")
    await writer.drain()

    response = await read_prompt(reader)

    assert b"root" in response
    assert b"/home/admin$ " in response

    writer.write(b"exit\n")
    await writer.drain()

    goodbye = await asyncio.wait_for(reader.read(), timeout=1)

    assert b"logout" in goodbye
    assert b"Connection closed by remote host" in goodbye

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_tcp_clients_have_independent_sessions(running_server):
    """Two clients should keep separate prompts, command flow, and responses."""
    host, port, _ = running_server

    reader_a, writer_a = await asyncio.open_connection(host, port)
    reader_b, writer_b = await asyncio.open_connection(host, port)

    await read_prompt(reader_a)
    await read_prompt(reader_b)

    writer_a.write(b"cat /etc/passwd\n")
    writer_b.write(b"pwd\n")
    await writer_a.drain()
    await writer_b.drain()

    response_a = await read_prompt(reader_a)
    response_b = await read_prompt(reader_b)

    assert b"root:x:0:0" in response_a
    assert b"/home/admin" in response_b

    writer_a.close()
    writer_b.close()
    await writer_a.wait_closed()
    await writer_b.wait_closed()


@pytest.mark.asyncio
async def test_server_rejects_connections_over_global_limit(monkeypatch):
    """The server should refuse new clients after MAX_CONNECTIONS is reached."""
    monkeypatch.setattr(server_module, "HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "PORT", 0)
    monkeypatch.setattr(server_module, "MAX_CONNECTIONS", 1)

    server = TCPServer()
    task = asyncio.create_task(server.start())

    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)

    host, port = require_bound_server_address(server)

    reader_1, writer_1 = await asyncio.open_connection(host, port)
    await read_prompt(reader_1)

    reader_2, writer_2 = await asyncio.open_connection(host, port)
    refused_data = await asyncio.wait_for(reader_2.read(), timeout=1)

    assert refused_data == b""

    writer_1.close()
    writer_2.close()
    await writer_1.wait_closed()
    await writer_2.wait_closed()

    await server.shutdown()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
