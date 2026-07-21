import asyncio
import json

import pytest

import honeypot.logging.session_logger as session_logger_module
import honeypot.network.http_handler as http_handler_module
from honeypot.core.persona import PRESET_PERSONAS
from honeypot.logging.session_logger import SessionLogger
from honeypot.network.http_handler import HttpHandler, _server_kind


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

    async def readexactly(self, n):
        await asyncio.sleep(0)
        chunk, self._body = self._body[:n], self._body[n:]
        if len(chunk) < n:
            raise asyncio.IncompleteReadError(chunk, n)
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


@pytest.mark.parametrize(
    "persona_id,expected_kind",
    [
        ("generic_linux", "apache"),
        ("ubuntu_web_server", "nginx"),
        ("centos_database", "apache"),
        ("debian_mail_server", "apache"),
        ("busybox_router", "busybox"),
    ],
)
def test_server_kind_maps_every_preset_persona_explicitly(persona_id, expected_kind):
    assert _server_kind(PRESET_PERSONAS[persona_id]) == expected_kind


def test_server_kind_rejects_a_persona_with_http_server_type_none():
    """A persona explicitly configured with no web server must not silently
    get an Apache page it doesn't run -- see the busybox_router/Apache
    mismatch this same file used to have, before http_server_type existed."""
    class _FakePersona:
        persona_id = "iot_camera"
        http_server_type = "none"

    with pytest.raises(ValueError, match="iot_camera"):
        _server_kind(_FakePersona())


@pytest.mark.asyncio
async def test_http_rejects_a_persona_with_no_web_server_without_leaking_a_traceback(tmp_path, monkeypatch):
    """A persona _server_kind can't classify must close the connection with
    zero bytes sent -- an unhandled exception's traceback reaching the wire
    would fingerprint the honeypot to anyone who reads the response."""
    class _FakePersona:
        persona_id = "iot_camera"
        http_server_type = "none"
        hostname = "iot-cam-01"

    monkeypatch.setattr(http_handler_module, "get_active_persona", lambda: _FakePersona())
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    assert writer.buffer == b""
    assert writer.closed is True


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
async def test_http_options_returns_allow_header_and_no_body(tmp_path):
    raw = b"OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 200 OK")
    assert "Allow: GET, HEAD, POST, OPTIONS" in output
    assert output.endswith("\r\n\r\n")


@pytest.mark.parametrize("verb", ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH"])
@pytest.mark.asyncio
async def test_http_unsupported_verbs_get_405_not_the_get_page(tmp_path, verb):
    """A real server 405s these instead of silently treating every verb as
    GET -- serving an identical response regardless of method is a tell a
    careful scanner would notice (see the smoke-test finding this fixes)."""
    raw = f"{verb} / HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 405 Method Not Allowed")
    assert "Allow: GET, HEAD, POST, OPTIONS" in output
    assert "Apache2 Ubuntu Default Page" not in output


@pytest.mark.asyncio
async def test_http_1_1_without_host_header_gets_400(tmp_path):
    """RFC 7230 5.4 requires Host on HTTP/1.1 -- a real Apache/nginx 400s a
    request missing it instead of serving the homepage."""
    raw = b"GET / HTTP/1.1\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 400 Bad Request")
    assert "Apache2 Ubuntu Default Page" not in output


@pytest.mark.asyncio
async def test_http_1_0_without_host_header_still_gets_200(tmp_path):
    """HTTP/1.0 never required Host -- only 1.1 requests should be gated."""
    raw = b"GET / HTTP/1.0\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 200 OK")


@pytest.mark.asyncio
async def test_http_malformed_version_token_gets_400_not_a_normal_response(tmp_path):
    """A version token that isn't an exact "HTTP/1.1" match must not slip
    past the Host check via string inequality -- "HTTP/1.1 extra" is not
    "HTTP/1.1", so the old `==` comparison let a malformed version dodge the
    missing-Host rejection entirely and get an ordinary 200."""
    raw = b"GET / HTTP/1.1 extra\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 400 Bad Request")
    assert "Apache2 Ubuntu Default Page" not in output


@pytest.mark.asyncio
async def test_http_lowercase_version_token_gets_400(tmp_path):
    raw = b"GET / http/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 400 Bad Request")


@pytest.mark.asyncio
async def test_http_duplicate_host_header_gets_400(tmp_path):
    """RFC 7230 5.4: a server MUST reject a request with more than one Host
    header -- a dict silently collapses duplicates into whichever came
    last, which would otherwise hide this entirely."""
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: attacker.example\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 400 Bad Request")


@pytest.mark.asyncio
async def test_http_lowercase_method_gets_405_not_treated_as_get(tmp_path):
    """HTTP methods are case-sensitive tokens (RFC 7230 3.1.1) -- real
    Apache doesn't normalize "get" to "GET", so uppercasing it here would
    make a lowercase-verb probe look like a normal request instead of
    reaching the unsupported-method response."""
    raw = b"get / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 405 Method Not Allowed")
    assert "Allow: GET, HEAD, POST, OPTIONS" in output
    assert "Apache2 Ubuntu Default Page" not in output


@pytest.mark.asyncio
async def test_http_session_schedules_auto_classification_after_logging(tmp_path, monkeypatch):
    """Every completed session should be handed to the auto-classification
    hook, not just written to JSONL -- otherwise nothing ever classifies an
    HTTP session unless an operator runs `echidra classify` manually."""
    scheduled = []
    monkeypatch.setattr(
        session_logger_module, "schedule_auto_classification", scheduled.append
    )
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    log_path = tmp_path / "sessions.jsonl"
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(log_path)))

    await handler.handle()

    assert len(scheduled) == 1
    assert str(scheduled[0].session_id) == handler.session.session_id


@pytest.mark.asyncio
async def test_http_head_request_gets_headers_but_no_body(tmp_path):
    """A HEAD response must report the same Content-Length a GET would, but
    never send the body itself -- sending one anyway is a protocol-level
    tell real servers don't make."""
    raw = b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 200 OK")
    content_length = int(
        next(line for line in output.split("\r\n") if line.startswith("Content-Length:"))
        .split(":", 1)[1]
        .strip()
    )
    assert content_length > 0
    body = output.split("\r\n\r\n", 1)[1]
    assert body == ""


@pytest.mark.asyncio
async def test_http_robots_txt_returns_realistic_content(tmp_path):
    raw = b"GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output = writer.buffer.decode()
    assert output.startswith("HTTP/1.1 200 OK")
    assert "Content-Type: text/plain" in output
    assert "Disallow:" in output


@pytest.mark.asyncio
async def test_http_favicon_returns_200_not_404(tmp_path):
    """Nearly every real server returns something for /favicon.ico -- a 404
    here while everything else 200s is a small, free scanner tell."""
    raw = b"GET /favicon.ico HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reader = FakeReader(raw)
    writer = FakeWriter()
    handler = HttpHandler(reader, writer, session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")))

    await handler.handle()

    output_bytes = writer.buffer
    assert output_bytes.startswith(b"HTTP/1.1 200 OK")
    assert b"Content-Type: image/x-icon" in output_bytes
    assert b"\r\n\r\n" in output_bytes


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
