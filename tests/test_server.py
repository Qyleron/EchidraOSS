import pytest

from honeypot.network.http_handler import HttpHandler
from honeypot.network.protocol_server import ProtocolServer


"""Basic construction tests for the TCP server wrapper."""


class LFReader:
    """Reader that delivers headers separated by bare LF newline characters."""

    def __init__(self, payload: bytes):
        self.payload = payload

    async def readline(self):
        if not self.payload:
            return b""
        newline_index = self.payload.find(b"\n")
        if newline_index == -1:
            line = self.payload
            self.payload = b""
            return line
        line = self.payload[: newline_index + 1]
        self.payload = self.payload[newline_index + 1 :]
        return line


class RecordingHandler:
    created = []

    def __init__(self, reader, writer, session_logger=None):
        self.reader = reader
        self.writer = writer
        self.session_logger = session_logger
        RecordingHandler.created.append(self)

    async def handle(self):
        return None


@pytest.mark.asyncio
async def test_protocol_server_passes_shared_session_logger_to_handlers():
    """Each connection should receive the shared session logger from the server."""
    RecordingHandler.created = []
    shared_logger = object()
    server = ProtocolServer("127.0.0.1", 0, RecordingHandler, session_logger=shared_logger)

    await server._handle_client(object(), object())

    assert RecordingHandler.created[-1].session_logger is shared_logger


def test_http_handler_root_response_matches_persona_processes():
    """Root-page content should follow the same persona signal as the advertised server header."""
    handler = HttpHandler.__new__(HttpHandler)
    handler.session = type("Session", (), {"persona": type("Persona", (), {"running_processes": ("nginx", "php-fpm"), "persona_id": "ubuntu_web_server", "http_server_type": "nginx"})()})()

    response = handler._build_response("GET", "/", "HTTP/1.1", 1)

    assert b"Server: nginx/1.18.0 (Ubuntu)" in response
    assert b"WordPress" in response


@pytest.mark.asyncio
async def test_http_handler_accepts_lf_header_line_endings():
    """Bare-LF request headers should be parsed without waiting for the read timeout."""
    handler = HttpHandler.__new__(HttpHandler)
    handler.reader = LFReader(b"GET / HTTP/1.1\nHost: example.com\n\n")

    headers = await handler._read_headers()

    assert headers == b"GET / HTTP/1.1\nHost: example.com\n\n"
