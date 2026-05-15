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
    return await asyncio.wait_for(reader.readuntil(b"$ "), timeout=2)


async def run_client(host, port):
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
    host, port, _ = running_server

    await asyncio.wait_for(
        asyncio.gather(*(run_client(host, port) for _ in range(25))),
        timeout=5,
    )
