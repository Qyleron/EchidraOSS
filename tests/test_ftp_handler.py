import asyncio
import json

import pytest

from honeypot.logging.session_logger import SessionLogger
from honeypot.network.ftp_handler import FtpHandler


"""
These tests exercise FtpHandler without opening a real network socket.
FakeReader acts like an FTP client sending lines. FakeWriter stores everything
the honeypot would send back, so the tests can inspect it.
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
        return ("203.0.113.5", 40444)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeReader:
    """Small stand-in for asyncio's StreamReader that yields one line per call."""

    def __init__(self, messages):
        self.messages = [m.encode() + b"\r\n" for m in messages]

    async def readline(self):
        await asyncio.sleep(0)
        if self.messages:
            return self.messages.pop(0)
        return b""


class OverrunReader:
    """Reader that simulates a too-long line arriving from the client.

    Real asyncio.StreamReader.readline() catches its own internal
    LimitOverrunError and re-raises it as a plain ValueError -- that's the
    exception callers actually see, so this fake matches that contract
    instead of leaking the internal LimitOverrunError type.
    """

    async def readline(self):
        await asyncio.sleep(0)
        raise ValueError("line too long")


class RawLineReader:
    """Reader that serves exact raw bytes lines, bypassing str encoding."""

    def __init__(self, lines: list[bytes]):
        self.lines = list(lines)

    async def readline(self):
        await asyncio.sleep(0)
        if self.lines:
            return self.lines.pop(0)
        return b""


def read_records(log_path):
    """Load JSONL records written by one handler test."""
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.asyncio
async def test_ftp_banner_and_credentials_are_captured(tmp_path):
    """The vsFTPd banner should be sent and the USER/PASS pair logged."""
    reader = FakeReader(["USER admin", "PASS hunter2"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("220 (vsFTPd 3.0.3)")
    assert "530 Login incorrect." in output

    records = read_records(log_path)
    assert len(records) == 1
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert "USER admin" in commands
    assert "PASS hunter2" in commands


@pytest.mark.asyncio
async def test_ftp_connection_produces_session_record(tmp_path):
    """A completed connection should persist a well-formed session record."""
    reader = FakeReader(["USER root", "PASS toor"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    record = records[0]
    assert record["protocol"] == "ftp"
    assert record["session_id"] == handler.session.session_id
    assert record["peer_ip"] == "203.0.113.5"
    assert record["end_reason"] == "disconnect"
    assert record["command_count"] == 2


@pytest.mark.asyncio
async def test_ftp_immediate_disconnect_still_logs_session(tmp_path):
    """A client that vanishes right after the banner should still be logged."""
    reader = FakeReader([])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "disconnect"
    assert records[0]["command_count"] == 0
    assert writer.closed is True


@pytest.mark.asyncio
async def test_ftp_non_user_first_command_rejected_without_crash(tmp_path):
    """A first line that isn't USER should be rejected, not raise."""
    reader = FakeReader(["HELP"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    output = writer.buffer.decode()
    assert "530 Login incorrect." in output

    records = read_records(log_path)
    assert records[0]["commands"][0]["cmd"] == "HELP"


@pytest.mark.asyncio
async def test_ftp_malformed_oversized_input_does_not_crash(tmp_path):
    """An overrun line from the client should be handled, not crash the server."""
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(OverrunReader(), writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "error"
    assert writer.closed is True
    # Nothing was actually received before the overrun, so there is nothing
    # to capture — the record itself (proof the probe wasn't lost) is what matters.
    assert records[0]["command_count"] == 0


@pytest.mark.asyncio
async def test_ftp_undecodable_bytes_are_still_captured(tmp_path):
    """Invalid UTF-8 in a received line should not crash, and the cleaned-up
    text that was actually received should still land in the JSONL record."""
    reader = RawLineReader([b"\x80\x81\x82garbage-command\r\n"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    output = writer.buffer.decode()
    assert "530 Login incorrect." in output

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "disconnect"
    assert records[0]["command_count"] == 1
    assert records[0]["commands"][0]["cmd"] == "garbage-command"
