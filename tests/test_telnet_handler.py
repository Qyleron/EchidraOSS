import asyncio
import json

import pytest

from honeypot.logging.session_logger import SessionLogger
from honeypot.network.telnet_handler import DO, IAC, WILL, TelnetHandler


"""
These tests exercise TelnetHandler without opening a real network socket.
FakeReader serves a fixed IAC negotiation chunk (read) followed by a sequence
of login/password lines (readline), matching how TelnetHandler consumes input.
FakeWriter stores everything the honeypot would send back for inspection.
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
        return ("192.0.2.44", 33333)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeReader:
    """Small stand-in for asyncio's StreamReader for a Telnet session.

    `initial` is returned once by read(), covering IAC option negotiation.
    `lines` are returned one at a time by readline(), covering the
    login/password exchange.
    """

    def __init__(self, initial: bytes, lines):
        self._initial = initial
        self._lines = [
            line if isinstance(line, bytes) else line.encode()
            for line in lines
        ]

    async def read(self, n):
        await asyncio.sleep(0)
        data, self._initial = self._initial[:n], self._initial[n:]
        return data

    async def readline(self):
        await asyncio.sleep(0)
        if self._lines:
            return self._lines.pop(0)
        return b""


def read_records(log_path):
    """Load JSONL records written by one handler test."""
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.asyncio
async def test_telnet_banner_and_login_prompt(tmp_path):
    """The OS banner and hostname login prompt should be sent to the client."""
    reader = FakeReader(b"", ["root\r\n", "toor\r\n"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    output = writer.buffer.decode("latin-1")
    assert "Linux fake-host 5.15.0-91-generic x86_64" in output
    assert "fake-host login:" in output
    assert "Login incorrect" in output


@pytest.mark.asyncio
async def test_telnet_connection_produces_session_record(tmp_path):
    """A completed connection should persist a well-formed session record."""
    reader = FakeReader(b"", ["admin\r\n", "admin\r\n"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    record = records[0]
    assert record["protocol"] == "telnet"
    assert record["session_id"] == handler.session.session_id
    assert record["peer_ip"] == "192.0.2.44"
    assert record["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_telnet_login_and_password_attempts_captured(tmp_path):
    """The username and password lines should be logged as separate commands."""
    reader = FakeReader(b"", ["root\r\n", "toor\r\n"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert "login: root" in commands
    assert "password: toor" in commands


@pytest.mark.asyncio
async def test_telnet_immediate_disconnect_still_logs_session(tmp_path):
    """A client that disconnects before sending a username should still be logged."""
    reader = FakeReader(b"", [])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "disconnect"
    assert records[0]["command_count"] == 0
    assert writer.closed is True


@pytest.mark.asyncio
async def test_telnet_malformed_iac_negotiation_does_not_crash(tmp_path):
    """A garbled IAC negotiation prefix should not raise, and produces a
    minimal session record even when nothing follows it."""
    garbled_iac = b"\xff\xfd"  # DO command missing its trailing option byte
    reader = FakeReader(garbled_iac, [])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    assert records[0]["end_reason"] == "disconnect"
    assert records[0]["command_count"] == 0


@pytest.mark.asyncio
async def test_telnet_username_sent_in_same_burst_as_iac_negotiation_is_not_lost(tmp_path):
    """Regression test: a fast client (most real Mirai-style bots) that sends
    its username in the same packet as its IAC options, before waiting for
    any prompt, must still have that username captured -- not silently
    discarded along with the negotiation bytes."""
    burst = (
        IAC + WILL + b"\x01"  # WILL ECHO
        + IAC + WILL + b"\x03"  # WILL SUPPRESS-GO-AHEAD
        + b"root\r\n"  # username sent immediately, no waiting for a prompt
    )
    reader = FakeReader(burst, ["toor\r\n"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert "login: root" in commands
    assert "password: toor" in commands


@pytest.mark.asyncio
async def test_telnet_username_and_password_sent_in_one_burst_are_both_captured(tmp_path):
    """An even faster client sends username AND password in the same initial
    burst as its IAC options -- both must still be captured."""
    burst = IAC + DO + b"\x18" + b"root\r\ntoor\r\n"  # DO TERMINAL-TYPE
    reader = FakeReader(burst, [])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert "login: root" in commands
    assert "password: toor" in commands


@pytest.mark.asyncio
async def test_telnet_credentials_are_captured_despite_malformed_iac_prefix(tmp_path):
    """A real login attempt sent right after a garbled IAC prefix must still
    be captured — a corrupt negotiation sequence must not swallow the probe."""
    garbled_iac = b"\xff\xfd"  # DO command missing its trailing option byte
    reader = FakeReader(garbled_iac, ["admin\r\n", "letmein\r\n"])
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = TelnetHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    records = read_records(log_path)
    assert len(records) == 1
    commands = [entry["cmd"] for entry in records[0]["commands"]]
    assert "login: admin" in commands
    assert "password: letmein" in commands
