"""FTP honeypot handler — captures credential stuffing attempts on port 21."""

from __future__ import annotations

import asyncio
import logging

from honeypot.logging.session_logger import SessionLogger, finalize_and_schedule
from honeypot.network.config import READ_TIMEOUT, SESSION_LOG_PATH, get_active_persona
from honeypot.network.protocol_session import ProtocolSession

logger = logging.getLogger(__name__)


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

            username = await self._read_command()
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
