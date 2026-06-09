import asyncio

import pytest
import pytest_asyncio

import honeypot.network.server as server_module
from honeypot.network.server import TCPServer
from tests.conftest import require_bound_server_address


"""
These tests check that the TCP server stays usable around edge cases:
disconnects, bad shell input, repeated commands, and shutdown behavior.
"""


@pytest_asyncio.fixture
async def running_server(monkeypatch):
    """Start a temporary real server for stability tests."""
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
    """Read until the prompt so each test sees one complete response."""
    return await asyncio.wait_for(reader.readuntil(b"$ "), timeout=1)


async def wait_for_no_tasks(server):
    """Poll until ConnectionHandler tasks have cleaned themselves up."""
    for _ in range(50):
        if not server.tasks:
            return
        await asyncio.sleep(0.01)

    assert server.tasks == set()


@pytest.mark.asyncio
async def test_client_disconnects_after_banner_cleans_up_task(running_server):
    """A client that disconnects early should not leave a task behind."""
    host, port, server = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    writer.close()
    await writer.wait_closed()

    await wait_for_no_tasks(server)


@pytest.mark.asyncio
async def test_unknown_command_returns_prompt_and_session_stays_alive(running_server):
    """After an unknown command, the same client should still be usable."""
    host, port, _ = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    writer.write(b"notarealcommand\n")
    await writer.drain()

    unknown_response = await read_prompt(reader)

    assert b"bash: notarealcommand: command not found" in unknown_response
    assert b"/home/admin$ " in unknown_response

    writer.write(b"whoami\n")
    await writer.drain()

    whoami_response = await read_prompt(reader)

    assert b"root" in whoami_response

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_malformed_shell_input_returns_syntax_error(running_server):
    """Bad quoting should produce a syntax error instead of crashing."""
    host, port, _ = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    writer.write(b"cat 'unterminated\n")
    await writer.drain()

    response = await read_prompt(reader)

    assert b"bash: syntax error near unexpected token" in response
    assert b"/home/admin$ " in response

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_multiple_sequential_commands_preserve_prompt_behavior(running_server):
    """Several commands in a row should each return output plus a prompt."""
    host, port, _ = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    commands = [
        (b"pwd\n", b"/home/admin"),
        (b"cat /home/admin/notes.txt\n", b"TODO: rotate credentials"),
        (b"ls /etc\n", b"hosts  passwd"),
        (b"uname -a\n", b"Linux fake-host"),
    ]

    for command, expected in commands:
        writer.write(command)
        await writer.drain()

        response = await read_prompt(reader)

        assert expected in response
        assert response.endswith(b"/home/admin$ ")

    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_shutdown_closes_active_client_tasks(running_server):
    """Server shutdown should close active clients and clear task tracking."""
    host, port, server = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    assert len(server.tasks) == 1

    await server.shutdown()
    data = await asyncio.wait_for(reader.read(), timeout=1)

    assert data == b""
    assert server.tasks == set()

    writer.close()
    await writer.wait_closed()
