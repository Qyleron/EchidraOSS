import asyncio
import json

import pytest

from honeypot.logging.session_logger import SessionLogger
from honeypot.network.http_handler import HttpHandler


"""
These tests exercise HttpHandler without opening a real network socket.
FakeReader replays raw request bytes line-by-line (readline) and serves the
request body from a separate buffer (read), matching how HttpHandler consumes
headers and bodies. FakeWriter stores the response for inspection.
"""


class FakeWriter:
    """Small stand-in for asyncio's StreamWriter used by the server."""

    def __init__(self):
        self.buffer = b""
        self.closed = False

    def write(self, data):
        self.buffer += data

    async def drain(self):
        pass

    def get_extra_info(self, name):
        return ("198.51.100.7", 51515)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeReader:
    """Small stand-in for asyncio's StreamReader serving a fixed HTTP request."""

    def __init__(self, raw: bytes, body: bytes = b""):
        self._lines = raw.splitlines(keepends=True)
        self._body = body

    async def readline(self):
        await asyncio.sleep(0)
        if self._lines:
            return self._lines.pop(0)
        return b""

    async def read(self, n):
        await asyncio.sleep(0)
        chunk, self._body = self._body[:n], self._body[n:]
        return chunk


class OverrunReader:
    """Reader that simulates a too-long header line arriving from the client.

    Real asyncio.StreamReader.readline() catches its own internal
    LimitOverrunError and re-raises it as a plain ValueError -- that's the
    exception callers actually see, so this fake matches that contract.
    """

    async def readline(self):
        await asyncio.sleep(0)
        raise ValueError("line too long")


def read_records(log_path):
    """Load JSONL records written by one handler test."""
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.asyncio
async def test_http_root_request_returns_persona_banner(tmp_path):
    """A GET / should get a 200 response with the persona's server banner."""
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 200 OK")
    assert "Server: Apache/2.4.54 (Debian)" in output
    assert "Apache2 Ubuntu Default Page" in output


@pytest.mark.asyncio
async def test_http_connection_produces_session_record(tmp_path):
    """A completed connection should persist a well-formed session record."""
    raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    record = records[0]
    assert record["protocol"] == "http"
    assert record["session_id"] == handler.session.session_id
    assert record["peer_ip"] == "198.51.100.7"
    assert record["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_http_request_line_and_credentials_are_captured(tmp_path):
    """The request line, User-Agent, and POST credential body should be logged."""
    body = b"log=admin&pwd=hunter2"
    raw = (
        b"POST /wp-login.php HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: curl/8.0\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n"
    )
    reader = FakeReader(raw, body=body)
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert "POST /wp-login.php HTTP/1.1" in commands
    assert "User-Agent: curl/8.0" in commands
    assert any("log=admin&pwd=hunter2" in cmd for cmd in commands)


@pytest.mark.asyncio
async def test_http_session_written_to_jsonl_on_disconnect(tmp_path):
    """A client that disconnects immediately should still produce a JSONL record."""
    reader = FakeReader(b"")
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["command_count"] == 0
    assert records[0]["end_reason"] == "disconnect"
    assert writer.closed is True


@pytest.mark.asyncio
async def test_http_malformed_request_does_not_crash(tmp_path):
    """Binary garbage with no valid HTTP structure should not raise or hang."""
    raw = b"\x00\x01\x02NOT-HTTP-AT-ALL\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "disconnect"
    assert writer.closed is True
    # The garbled request line itself must still be captured, not dropped.
    assert records[0]["command_count"] == 1
    assert records[0]["commands"][0]["cmd"] == "\x00\x01\x02NOT-HTTP-AT-ALL"


@pytest.mark.asyncio
async def test_http_malformed_oversized_input_does_not_crash(tmp_path):
    """An overrun header line should surface as an error probe, not a silent disconnect."""
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(OverrunReader(), writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "error"
    assert writer.closed is True
