import asyncio

import pytest
import pytest_asyncio

import honeypot.network.server as server_module
from honeypot.network.server import TCPServer


@pytest_asyncio.fixture
async def running_server(monkeypatch):
    monkeypatch.setattr(server_module, "HOST", "127.0.0.1")
    monkeypatch.setattr(server_module, "PORT", 0)

    server = TCPServer()
    task = asyncio.create_task(server.start())

    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)

    assert server.server is not None
    host, port = server.server.sockets[0].getsockname()[:2]

    try:
        yield host, port, server
    finally:
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def read_prompt(reader):
    return await asyncio.wait_for(reader.readuntil(b"$ "), timeout=1)


async def wait_for_no_tasks(server):
    for _ in range(50):
        if not server.tasks:
            return
        await asyncio.sleep(0.01)

    assert server.tasks == set()


@pytest.mark.asyncio
async def test_client_disconnects_after_banner_cleans_up_task(running_server):
    host, port, server = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    writer.close()
    await writer.wait_closed()

    await wait_for_no_tasks(server)


@pytest.mark.asyncio
async def test_unknown_command_returns_prompt_and_session_stays_alive(running_server):
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
    host, port, _ = running_server

    reader, writer = await asyncio.open_connection(host, port)
    await read_prompt(reader)

    commands = [
        (b"pwd\n", b"/home/admin"),
        (b"cat /home/admin/notes.txt\n", b"TODO: rotate credentials"),
        (b"ls /etc\n", b"hosts  passwd  ssh"),
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
