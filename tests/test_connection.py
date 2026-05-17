import asyncio

import pytest

from honeypot.network.connection import ConnectionHandler


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
