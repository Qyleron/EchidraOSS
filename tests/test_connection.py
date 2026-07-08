import asyncio
import json

import pytest

import honeypot.network.connection as connection_module
from honeypot.logging.session_logger import SessionLogger
from honeypot.network.connection import ConnectionHandler
from classifier.pipeline import classify_session
from classifier.schemas.session import SessionRecord


"""
These tests exercise ConnectionHandler without opening a real network socket.
FakeReader acts like a client sending lines. FakeWriter stores everything the
honeypot would send back, so the tests can inspect it.
"""


class FakeWriter:
    """Small stand-in for asyncio's StreamWriter used by the server."""

    def __init__(self):
        self.buffer = b""
        self.closed = False

    def write(self, data):
        # Store outgoing bytes instead of sending them over the network.
        self.buffer += data

    async def drain(self):
        # Real StreamWriter.drain waits for network writes to flush.
        pass

    def get_extra_info(self, name):
        # ConnectionHandler asks for peername during setup.
        return ("127.0.0.1", 4444)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeReader:
    """Small stand-in for asyncio's StreamReader."""

    def __init__(self, messages):
        # The real server reads one newline-terminated command at a time.
        self.messages = [
            m.encode() + b"\n"
            for m in messages
        ]

    async def readline(self):
        await asyncio.sleep(0)

        if self.messages:
            return self.messages.pop(0)

        return b""


class SlowReader:
    """Reader that stays idle long enough to trigger the configured timeout."""

    async def readline(self):
        await asyncio.sleep(1)
        return b""


class LongReader:
    """Reader that simulates a too-long line arriving from the client.

    Real asyncio.StreamReader.readline() documents that it catches its own
    internal LimitOverrunError and re-raises it as a plain ValueError -- only
    readuntil() raises LimitOverrunError directly. Raising ValueError here
    (not LimitOverrunError) matches that real contract; a version of this
    mock that raised LimitOverrunError directly let a real bug (the handler
    only caught LimitOverrunError, never actually triggered via readline())
    go undetected.
    """

    async def readline(self):
        raise ValueError("Separator is not found, and chunk exceed the limit")


def read_records(log_path):
    """Load JSONL records written by one connection test."""
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.asyncio
async def test_connection_exit():
    """A client that sends exit should receive logout text and close cleanly."""
    reader = FakeReader(["exit"])
    writer = FakeWriter()

    handler = ConnectionHandler(reader, writer)

    await handler.handle()

    output = writer.buffer.decode()

    assert "logout" in output
    assert writer.closed is True


@pytest.mark.asyncio
async def test_connection_whoami():
    """The handler should pass commands into the shell engine and return output."""
    reader = FakeReader(["whoami", "exit"])
    writer = FakeWriter()

    handler = ConnectionHandler(reader, writer)

    await handler.handle()

    output = writer.buffer.decode()

    assert "root" in output


@pytest.mark.asyncio
async def test_live_classification_applies_adaptive_response_delay(monkeypatch):
    handler = ConnectionHandler(FakeReader([]), FakeWriter())
    now = handler.session.start_time
    handler.session.commands = [
        {"cmd": "whoami", "timestamp": now + 0.1},
        {"cmd": "hostname", "timestamp": now + 0.2},
        {"cmd": "ls", "timestamp": now + 0.3},
        {"cmd": "cat /etc/passwd", "timestamp": now + 0.4},
    ]
    handler.session.command_count = 4
    handler.session.decoy_files_surfaced = ["/etc/passwd"]
    record = handler.session.active_record()
    record["ended_at"] = now + 1
    record["duration_seconds"] = 1
    summary = classify_session(SessionRecord.parse_obj(record), active=True)

    async def no_alert(*_args, **_kwargs):
        return None

    # No alert import is reached when this severity was already dispatched.
    handler._highest_alerted_rank = 4
    await handler._handle_live_classification(summary)

    assert handler._response_delay_seconds == 0.5


@pytest.mark.asyncio
async def test_connection_logs_logout_reason(tmp_path):
    """Shell logout should persist commands and the explicit logout reason."""
    log_path = tmp_path / "sessions.jsonl"
    handler = ConnectionHandler(
        FakeReader(["whoami", "exit"]),
        FakeWriter(),
        session_logger=SessionLogger(str(log_path)),
    )

    await handler.handle()

    record = read_records(log_path)[0]

    assert record["end_reason"] == "logout"
    assert [command["cmd"] for command in record["commands"]] == [
        "whoami",
        "exit",
    ]


@pytest.mark.asyncio
async def test_connection_logs_disconnect_reason(tmp_path):
    """A client disappearing without logout should be recorded as a disconnect."""
    log_path = tmp_path / "sessions.jsonl"
    handler = ConnectionHandler(
        FakeReader([]),
        FakeWriter(),
        session_logger=SessionLogger(str(log_path)),
    )

    await handler.handle()

    assert read_records(log_path)[0]["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_connection_logs_timeout_reason(tmp_path, monkeypatch):
    """Idle clients should be recorded separately from explicit disconnects."""
    monkeypatch.setattr(connection_module, "READ_TIMEOUT", 0.001)
    log_path = tmp_path / "sessions.jsonl"
    handler = ConnectionHandler(
        SlowReader(),
        FakeWriter(),
        session_logger=SessionLogger(str(log_path)),
    )

    await handler.handle()

    assert read_records(log_path)[0]["end_reason"] == "timeout"


@pytest.mark.asyncio
async def test_connection_handles_long_input_error(tmp_path):
    """The handler should catch overly long lines without crashing the server."""
    log_path = tmp_path / "sessions.jsonl"
    writer = FakeWriter()
    handler = ConnectionHandler(
        LongReader(),
        writer,
        session_logger=SessionLogger(str(log_path)),
    )

    await handler.handle()

    assert read_records(log_path)[0]["end_reason"] == "error"
    assert "Input too long" in writer.buffer.decode()
