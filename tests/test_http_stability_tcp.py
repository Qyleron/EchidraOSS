import asyncio
import json

import pytest
import pytest_asyncio

from honeypot.logging.session_logger import SessionLogger
from honeypot.network.http_handler import HttpHandler
from honeypot.network.protocol_server import ProtocolServer
from tests.conftest import require_bound_server_address


"""Real-socket regression coverage for HttpHandler, complementing the mocked
FakeReader-based unit tests in test_http_handler.py. A mocked reader can
match whatever contract the code under test assumes, even a wrong one --
readline() documents that it catches its own internal LimitOverrunError and
re-raises it as a plain ValueError, a contract a naive mock can easily get
wrong (see connection.py's oversized-line handling). These tests exercise
the actual asyncio.StreamReader behavior a real TCP client triggers, such as
a POST body arriving across multiple TCP writes."""


@pytest_asyncio.fixture
async def running_http_server(tmp_path):
    """Start a temporary real HttpHandler listener for stability tests."""
    log_path = tmp_path / "sessions.jsonl"
    server = ProtocolServer(
        "127.0.0.1", 0, HttpHandler, session_logger=SessionLogger(str(log_path))
    )
    task = asyncio.create_task(server.start())

    for _ in range(50):
        if server.server and server.server.sockets:
            break
        await asyncio.sleep(0.01)

    host, port = require_bound_server_address(server)

    try:
        yield host, port, log_path
    finally:
        await server.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def _read_records(log_path):
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]


@pytest.mark.asyncio
async def test_post_body_split_across_tcp_writes_is_captured_in_full(running_http_server):
    """A POST body sent as several separate writes (simulating TCP segmentation)
    must be captured whole, not truncated to whatever had arrived by the time
    the server's first read happened."""
    host, port, log_path = running_http_server
    # Stays under the handler's 1024-char logged-body cap so the full body
    # is expected to survive into the JSONL record verbatim.
    body = b"log=admin&pwd=hunter2-" + b"x" * 700

    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        b"POST /wp-login.php HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n"
    )
    await writer.drain()
    await asyncio.sleep(0.02)  # let the header read complete before the body trickles in

    # Send the body in small chunks with a yield between each, so the
    # server's first attempt to read it sees only a fraction of the total.
    for offset in range(0, len(body), 64):
        writer.write(body[offset : offset + 64])
        await writer.drain()
        await asyncio.sleep(0.005)

    await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    await writer.wait_closed()

    for _ in range(50):
        records = _read_records(log_path)
        if records:
            break
        await asyncio.sleep(0.02)

    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert any(body.decode() in cmd for cmd in commands)


@pytest.mark.asyncio
async def test_post_body_shorter_than_declared_content_length_is_still_captured(
    running_http_server,
):
    """If a client declares a Content-Length larger than what it actually
    sends and then disconnects, the partial body should still be captured
    instead of the request being dropped entirely."""
    host, port, log_path = running_http_server
    actual_body = b"log=admin&pwd=hunter2"

    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        b"POST /wp-login.php HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: " + str(len(actual_body) + 500).encode() + b"\r\n"
        b"\r\n" + actual_body
    )
    await writer.drain()
    writer.close()
    await writer.wait_closed()

    for _ in range(50):
        records = _read_records(log_path)
        if records:
            break
        await asyncio.sleep(0.02)

    assert records
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert any(actual_body.decode() in cmd for cmd in commands)
