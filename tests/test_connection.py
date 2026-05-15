import asyncio

import pytest

from honeypot.network.connection import ConnectionHandler


class FakeWriter:

    def __init__(self):
        self.buffer = b""
        self.closed = False

    def write(self, data):
        self.buffer += data

    async def drain(self):
        pass

    def get_extra_info(self, name):
        return ("127.0.0.1", 4444)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeReader:

    def __init__(self, messages):
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
    reader = FakeReader(["exit"])
    writer = FakeWriter()

    handler = ConnectionHandler(reader, writer)

    await handler.handle()

    output = writer.buffer.decode()

    assert "logout" in output
    assert writer.closed is True


@pytest.mark.asyncio
async def test_connection_whoami():
    reader = FakeReader(["whoami", "exit"])
    writer = FakeWriter()

    handler = ConnectionHandler(reader, writer)

    await handler.handle()

    output = writer.buffer.decode()

    assert "root" in output