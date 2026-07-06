"""Telnet honeypot handler — captures Mirai-style IoT credential attacks on port 23."""

from __future__ import annotations

import asyncio
import logging

from honeypot.logging.session_logger import SessionLogger
from honeypot.network.config import READ_TIMEOUT, SESSION_LOG_PATH, get_active_persona
from honeypot.network.protocol_session import ProtocolSession

logger = logging.getLogger(__name__)

# IAC negotiation sequence — Telnet clients typically send these option bytes.
# Responding with WONT/DONT suppresses further negotiation cleanly.
IAC = b"\xff"
DONT = b"\xfe"
DO = b"\xfd"
WONT = b"\xfc"
WILL = b"\xfb"


class TelnetHandler:
    """
    Fake Telnet login prompt that captures credential attempts.

    Most Telnet attacks are Mirai botnet variants scanning for default
    IoT credentials. This handler presents a plausible login prompt,
    accepts one username/password pair, always rejects it, and logs both.
    The credential intelligence (real username+password pairs being tried
    across the internet) is the primary value of this listener.
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
        self.session = ProtocolSession(self.peer, "telnet", get_active_persona())
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)

    async def handle(self) -> None:
        """Run the fake Telnet login and log the credential attempt."""
        end_reason = "disconnect"
        persona = self.session.persona
        try:
            # Drain any IAC negotiation bytes the client sends immediately
            await self._drain_iac()

            banner = f"\r\n{persona.os_banner}\r\n\r\n"
            await self._send(banner)
            await self._send(f"{persona.hostname} login: ")

            username = await self._read_line()
            if username is None:
                return

            username = username.strip()
            if username:
                self.session.log_command(f"login: {username}")

            await self._send("Password: ")

            password = await self._read_line(echo=False)
            if password is None:
                return

            password = password.strip()
            if password:
                self.session.log_command(f"password: {password}")

            await asyncio.sleep(1)
            await self._send("\r\nLogin incorrect\r\n")
            await self._send(f"\r\n{persona.hostname} login: ")
            end_reason = "disconnect"

        except asyncio.TimeoutError:
            end_reason = "timeout"
        except asyncio.CancelledError:
            end_reason = "shutdown"
        except Exception:
            logger.exception("Telnet handler error from %s", self.peer)
            end_reason = "error"
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            self.session.finalize(end_reason)
            try:
                self.session_logger.log(self.session)
            except Exception:
                logger.exception("Failed to log Telnet session %s", self.session.session_id)

    async def _send(self, text: str) -> None:
        self.writer.write(text.encode("latin-1", errors="replace"))
        await self.writer.drain()

    async def _read_line(self, echo: bool = True) -> str | None:
        try:
            data = await asyncio.wait_for(
                self.reader.readline(),
                timeout=READ_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise
        if not data:
            return None
        line = ""
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 0xFF:
                # Skip a full IAC negotiation sequence if present, else just the marker
                i += 3 if i + 2 < len(data) else 1
                continue
            if byte in (0x08, 0x7F):
                line = line[:-1]
                i += 1
                continue
            ch = chr(byte)
            if ch in ("\r", "\n"):
                if echo:
                    await self._send("\r\n")
                break
            line += ch
            i += 1
        return line

    async def _drain_iac(self) -> None:
        """Consume and respond to any initial Telnet option negotiation bytes."""
        try:
            data = await asyncio.wait_for(self.reader.read(64), timeout=2)
            reply = b""
            i = 0
            while i < len(data):
                if data[i:i+1] == IAC and i + 2 < len(data):
                    cmd = data[i+1:i+2]
                    opt = data[i+2:i+3]
                    if cmd == DO:
                        reply += IAC + WONT + opt
                    elif cmd == WILL:
                        reply += IAC + DONT + opt
                    i += 3
                else:
                    i += 1
            if reply:
                self.writer.write(reply)
                await self.writer.drain()
        except (asyncio.TimeoutError, Exception):
            pass
