"""FTP honeypot handler — captures credential stuffing attempts on port 21."""

from __future__ import annotations

import asyncio
import logging
import re

from honeypot.logging.session_logger import SessionLogger, finalize_and_schedule
from honeypot.network.config import READ_TIMEOUT, SESSION_LOG_PATH, get_active_persona
from honeypot.network.protocol_session import ProtocolSession

logger = logging.getLogger(__name__)

# First bytes of a TLS handshake (0x16) and a remote-desktop connection
# request (0x03, a TPKT header). Neither is text, so neither ends with a
# line break the way an FTP command does.
_BINARY_FIRST_BYTES = {0x16, 0x03}
# How long to wait for the rest of a binary opening once its first byte is in.
BINARY_READ_SECONDS = 2.0
_RDP_COOKIE_PATTERN = re.compile(rb"mstshash=([\x21-\x7e]{1,64})")


def _describe_first_message(data: bytes) -> str:
    """The first message as a log line; TLS and remote-desktop openings
    become a readable marker instead of binary noise."""
    if data[:1] == b"\x16" and data[1:2] in (b"\x03", b""):
        return f"[TLS handshake] {data[:16].hex(' ')}"
    if data[:2] == b"\x03\x00":
        cookie = _RDP_COOKIE_PATTERN.search(data)
        return "[RDP connection request]" + (
            f" mstshash={cookie.group(1).decode('ascii')}" if cookie else ""
        )
    return data.decode(errors="ignore").rstrip("\r\n")


class FtpHandler:
    """
    Fake FTP server that captures username and password attempts.

    Presents a realistic vsFTPd banner, accepts one USER/PASS exchange,
    always returns 530 Login incorrect, and logs the credential pair.
    FTP attackers are primarily running credential stuffing — this captures
    the username/password pairs they are testing.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_logger: SessionLogger | None = None,
    ):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")
        self.session = ProtocolSession(self.peer, "ftp", get_active_persona())
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)

    async def handle(self) -> None:
        """Run the fake FTP conversation and log the credential attempt."""
        end_reason = "disconnect"
        try:
            await self._send("220 (vsFTPd 3.0.3)\r\n")

            username = await self._read_first_message()
            if not username:
                return

            # Normalize and log the USER command
            if username.upper().startswith("USER"):
                user = username[4:].strip()
                self.session.log_command(f"USER {user}")
                await self._send("331 Please specify the password.\r\n")
            else:
                self.session.log_command(username)
                await self._send("530 Login incorrect.\r\n")
                return

            password = await self._read_command()
            if not password:
                return

            if password.upper().startswith("PASS"):
                passwd = password[4:].strip()
                self.session.log_command(f"PASS {passwd}")
            else:
                self.session.log_command(password)

            await self._send("530 Login incorrect.\r\n")
            await self._send("421 Timeout.\r\n")
            end_reason = "disconnect"

        except asyncio.TimeoutError:
            end_reason = "timeout"
        except asyncio.CancelledError:
            end_reason = "shutdown"
        except Exception:
            logger.exception("FTP handler error from %s", self.peer)
            end_reason = "error"
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            self.session.finalize(end_reason)
            finalize_and_schedule(self.session_logger, self.session, "FTP", logger)

    async def _send(self, text: str) -> None:
        self.writer.write(text.encode())
        await self.writer.drain()

    async def _read_first_message(self) -> str | None:
        """Read the client's first message, which is not always FTP.

        Scanners send web requests, TLS handshakes and remote-desktop
        requests to every open port. A binary opening has no line break, so
        waiting for one would sit until the read timeout and record nothing.
        """
        first = await asyncio.wait_for(self.reader.read(1), timeout=READ_TIMEOUT)
        if not first:
            return None
        if first[0] in _BINARY_FIRST_BYTES:
            try:
                rest = await asyncio.wait_for(self.reader.read(4096), timeout=BINARY_READ_SECONDS)
            except asyncio.TimeoutError:
                rest = b""
        else:
            rest = await asyncio.wait_for(self.reader.readline(), timeout=READ_TIMEOUT)
        return _describe_first_message(first + rest)

    async def _read_command(self) -> str | None:
        try:
            data = await asyncio.wait_for(
                self.reader.readline(),
                timeout=READ_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise
        if not data:
            return None
        return data.decode(errors="ignore").rstrip("\r\n")
