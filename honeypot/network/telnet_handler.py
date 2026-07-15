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

# Real Mirai-family bots iterate several pairs from a fixed wordlist in one
# connection before giving up, not just one -- capping at 5 covers the vast
# majority of that behavior without letting one connection loop forever.
MAX_LOGIN_ATTEMPTS = 5
# Module-level so tests can shrink it to 0 instead of eating this delay for
# real once they cover more than one attempt per connection.
REJECTION_DELAY_SECONDS = 1


class TelnetHandler:
    """
    Fake Telnet login prompt that captures credential attempts.

    Most Telnet attacks are Mirai botnet variants scanning for default
    IoT credentials. This handler presents a plausible login prompt,
    accepts up to MAX_LOGIN_ATTEMPTS username/password pairs (always
    rejecting each one), and logs all of them. The credential intelligence
    (real username+password pairs being tried across the internet) is the
    primary value of this listener.
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
            # Drain any IAC negotiation bytes the client sends immediately.
            # A fast client (most Mirai-style bots) often sends its username
            # in the same packet as its IAC options, before the server has
            # even sent a prompt -- leftover carries those bytes forward
            # instead of discarding them.
            leftover = await self._drain_iac()

            banner = f"\r\n{persona.os_banner}\r\n\r\n"
            await self._send(banner)

            for _ in range(MAX_LOGIN_ATTEMPTS):
                await self._send(f"{persona.hostname} login: ")

                username, leftover = await self._read_line(initial=leftover)
                if username is None:
                    return

                username = username.strip()
                if username:
                    self.session.log_command(f"login: {username}")

                await self._send("Password: ")

                password, leftover = await self._read_line(initial=leftover, echo=False)
                if password is None:
                    return

                password = password.strip()
                if password:
                    self.session.log_command(f"password: {password}")

                await asyncio.sleep(REJECTION_DELAY_SECONDS)
                await self._send("\r\nLogin incorrect\r\n")

            end_reason = "disconnect"

        except asyncio.TimeoutError:
            end_reason = "timeout"
        except asyncio.CancelledError:
            end_reason = "shutdown"
        except ConnectionError:
            # Client disconnected mid-conversation (RST, closed socket,
            # broken pipe, etc.) -- normal for an internet-facing listener,
            # not a protocol/input error worth logging as one.
            end_reason = "disconnect"
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

    async def _read_line(
        self,
        echo: bool = True,
        initial: bytes = b"",
    ) -> tuple[str | None, bytes]:
        """Read one line, returning (line, unconsumed bytes after it).

        `initial` is bytes already in hand from a previous read (the
        non-negotiation leftover from _drain_iac(), or bytes left over after
        a prior line parsed from the same burst) that must be parsed before
        waiting on the network for more -- otherwise a client that sends its
        username and password in one packet loses everything after the
        first line.
        """
        data = initial
        if b"\r" not in data and b"\n" not in data:
            try:
                more = await asyncio.wait_for(
                    self.reader.readline(),
                    timeout=READ_TIMEOUT,
                )
            except asyncio.TimeoutError:
                raise
            if not more and not data:
                return None, b""
            data += more

        line = ""
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 0xFF:
                # Skip a full IAC negotiation sequence if present; a truncated
                # sequence at the buffer tail is unrecoverable, so stop here
                # rather than risk appending its command/option byte to `line`.
                if i + 2 < len(data):
                    i += 3
                    continue
                break
            if byte in (0x08, 0x7F):
                line = line[:-1]
                i += 1
                continue
            if byte in (0x0D, 0x0A):
                consumed = i + 1
                # Swallow a paired \n right after \r so it isn't mistaken
                # for the start of the next line.
                if byte == 0x0D and consumed < len(data) and data[consumed] == 0x0A:
                    consumed += 1
                if echo:
                    await self._send("\r\n")
                return line, data[consumed:]
            line += chr(byte)
            i += 1
        return line, b""

    async def _drain_iac(self) -> bytes:
        """Consume and respond to any initial Telnet option negotiation bytes.

        Returns any non-negotiation bytes read in the same burst (e.g. a
        username a fast client sent immediately after its IAC options)
        instead of discarding them -- most Mirai-style bots don't wait for
        a prompt before sending credentials.
        """
        try:
            data = await asyncio.wait_for(self.reader.read(64), timeout=2)
        except (asyncio.TimeoutError, OSError):
            return b""

        reply = b""
        leftover = b""
        i = 0
        while i < len(data):
            if data[i:i+1] == IAC:
                if i + 2 < len(data):
                    cmd = data[i+1:i+2]
                    opt = data[i+2:i+3]
                    if cmd == DO:
                        reply += IAC + WONT + opt
                    elif cmd == WILL:
                        reply += IAC + DONT + opt
                    i += 3
                else:
                    # Truncated IAC sequence at the end of this read -- an
                    # IAC marker is never literal content, and nothing
                    # coherent follows, so there's nothing left to recover.
                    break
            else:
                leftover += data[i:i+1]
                i += 1

        if reply:
            try:
                self.writer.write(reply)
                await self.writer.drain()
            except OSError:
                pass

        return leftover
