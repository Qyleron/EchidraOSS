import asyncio
import json

import pytest

import honeypot.logging.session_logger as session_logger_module
import honeypot.network.ftp_handler as ftp_handler_module
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


class BufferReader:
    """Small stand-in for asyncio's StreamReader over bytes the client sent.

    The handler reads the first byte on its own (to spot TLS and
    remote-desktop openings) and the rest line by line, so this supports
    both read(n) and readline() over one buffer.
    """

    def __init__(self, data: bytes):
        self.data = data

    async def read(self, n=-1):
        await asyncio.sleep(0)
        if n < 0:
            n = len(self.data)
        chunk, self.data = self.data[:n], self.data[n:]
        return chunk

    async def readline(self):
        await asyncio.sleep(0)
        index = self.data.find(b"\n")
        end = len(self.data) if index < 0 else index + 1
        line, self.data = self.data[:end], self.data[end:]
        return line


class FakeReader(BufferReader):
    """A client sending these text lines."""

    def __init__(self, messages):
        super().__init__(b"".join(m.encode() + b"\r\n" for m in messages))


class OverrunReader(BufferReader):
    """Reader that simulates a too-long line arriving from the client.

    Real asyncio.StreamReader.readline() catches its own internal
    LimitOverrunError and re-raises it as a plain ValueError -- that's the
    exception callers actually see, so this fake matches that contract
    instead of leaking the internal LimitOverrunError type.
    """

    def __init__(self):
        super().__init__(b"A")

    async def readline(self):
        await asyncio.sleep(0)
        raise ValueError("line too long")


class RawLineReader(BufferReader):
    """Reader that serves exact raw bytes lines, bypassing str encoding."""

    def __init__(self, lines: list[bytes]):
        super().__init__(b"".join(lines))


class StalledReader:
    """A client that sends its first bytes, then nothing more."""

    def __init__(self, first: bytes):
        self.first = first

    async def read(self, n=-1):
        if self.first:
            chunk, self.first = self.first, b""
            return chunk
        await asyncio.sleep(10)
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
async def test_ftp_session_schedules_auto_classification_after_logging(tmp_path, monkeypatch):
    """Every completed session should be handed to the auto-classification
    hook, not just written to JSONL -- otherwise nothing ever classifies an
    FTP session unless an operator runs `echidra classify` manually."""
    scheduled = []
    monkeypatch.setattr(
        session_logger_module, "schedule_auto_classification", scheduled.append
    )
    reader = FakeReader(["USER admin", "PASS hunter2"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    assert len(scheduled) == 1
    assert str(scheduled[0].session_id) == handler.session.session_id


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


async def _first_command(tmp_path, reader):
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = FtpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    assert "530 Login incorrect." in writer.buffer.decode()
    record = read_records(log_path)[0]
    assert record["command_count"] == 1
    return record


@pytest.mark.asyncio
async def test_a_tls_handshake_is_logged_as_a_marker(tmp_path):
    hello = bytes.fromhex("16 03 01 02 00 01 00 01 fc 03 03") + bytes(40)

    record = await _first_command(tmp_path, BufferReader(hello))

    assert record["commands"][0]["cmd"] == "[TLS handshake] 16 03 01 02 00 01 00 01 fc 03 03 00 00 00 00 00"


@pytest.mark.asyncio
async def test_a_remote_desktop_request_is_logged_with_its_cookie(tmp_path):
    request = b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=hello\r\n\x01\x00\x08\x00\x03\x00\x00\x00"

    record = await _first_command(tmp_path, BufferReader(request))

    assert record["commands"][0]["cmd"] == "[RDP connection request] mstshash=hello"


@pytest.mark.asyncio
async def test_a_binary_opening_without_a_line_break_does_not_wait_for_one(tmp_path, monkeypatch):
    monkeypatch.setattr(ftp_handler_module, "BINARY_READ_SECONDS", 0.05)

    record = await asyncio.wait_for(_first_command(tmp_path, StalledReader(b"\x16")), timeout=2)

    assert record["commands"][0]["cmd"] == "[TLS handshake] 16"
    assert record["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_a_web_request_is_logged_as_sent(tmp_path):
    record = await _first_command(tmp_path, FakeReader(["GET / HTTP/1.1", "Host: example"]))

    assert record["commands"][0]["cmd"] == "GET / HTTP/1.1"
