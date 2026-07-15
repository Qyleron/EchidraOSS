"""Real SSH honeypot listener, built on asyncssh.

Presents a genuine SSH handshake and host key (unlike a raw TCP socket
speaking plaintext prompts, a real `ssh` client can actually connect here),
always accepts whatever credentials are submitted after a short delay, and
then drops the client into the same fake shell (InteractionEngine) used
everywhere else in the honeypot.
"""

from __future__ import annotations

import asyncio
import logging
import random

import asyncssh

from honeypot.core.engine import InteractionEngine
from honeypot.core.session import SessionState
from honeypot.logging.session_logger import SessionLogger
from honeypot.network.config import (
    HOST,
    MAX_CONNECTIONS,
    PORT,
    READ_TIMEOUT,
    SESSION_LOG_PATH,
    SSH_HOST_KEY_PATH,
    get_active_persona,
)
from honeypot.network.ssh_keys import ensure_host_key
from classifier.alerts import _maybe_send_alert
from classifier.realtime import LiveSessionClassifier

logger = logging.getLogger(__name__)

# asyncssh sends "SSH-2.0-" + this string as its version exchange line, so
# a persona's ssh_banner (which already includes that prefix, matching how
# a real server's banner reads) must have it stripped before being handed
# back in as server_version -- otherwise the wire banner would double it.
_SSH_VERSION_PREFIX = "SSH-2.0-"


def _server_version_for(persona) -> str:
    banner = persona.ssh_banner
    if banner.startswith(_SSH_VERSION_PREFIX):
        return banner[len(_SSH_VERSION_PREFIX):]
    return banner

# A honeypot that authenticates any credential instantly is a cheap tell --
# real sshd takes a variable amount of time to check them. Module-level so
# tests can shrink it to (0, 0) instead of eating this delay for real.
AUTH_DELAY_RANGE = (0.5, 1.8)

# Ranks used to dispatch each increased alert severity only once per session,
# same convention as the other protocol handlers.
_RISK_RANKS = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class HoneypotSSHServer(asyncssh.SSHServer):
    """One instance per SSH connection.

    Captures the login attempt and always accepts it (rejecting would end
    the engagement before any post-login behavior could be observed), then
    hands off to handle_shell() for the fake shell once a session opens.
    """

    def __init__(
        self,
        session_logger: SessionLogger | None = None,
        on_connection_made=None,
        on_connection_lost=None,
    ):
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)
        self.session: SessionState | None = None
        self.end_reason = "disconnect"
        self._finalized = False
        self._on_connection_made = on_connection_made
        self._on_connection_lost = on_connection_lost
        self._admitted = False
        self._conn: asyncssh.SSHServerConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        if self._on_connection_made is not None and not self._on_connection_made(conn):
            logger.warning("SSH connection refused: max limit reached")
            conn.abort()
            return

        self._admitted = True
        peer = conn.get_extra_info("peername")
        self.session = SessionState(peer, persona=get_active_persona())
        conn.set_extra_info(honeypot_server=self)

    def connection_lost(self, exc: Exception | None) -> None:
        if self._admitted and self._on_connection_lost is not None:
            self._on_connection_lost(self._conn)
        self._finalize("error" if exc else self.end_reason)

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        username = username.strip()
        if username:
            self.session.log_command(f"login: {username}")

        password = password.strip()
        if password:
            self.session.log_command(f"password: {password}")

        await asyncio.sleep(random.uniform(*AUTH_DELAY_RANGE))
        return True

    def _finalize(self, end_reason: str) -> None:
        """Log the session exactly once, however the connection ended.

        Both connection_lost (fires for every connection, including ones
        that never reached a shell) and handle_shell's own cleanup call
        this -- whichever runs first wins; the guard makes the other a
        no-op instead of double-logging the same session.
        """
        if self._finalized or self.session is None:
            return
        self._finalized = True
        self.session.finalize(end_reason)
        try:
            self.session_logger.log(self.session)
        except Exception:
            logger.exception("Failed to log SSH session %s", self.session.session_id)


async def handle_shell(process: asyncssh.SSHServerProcess) -> None:
    """Drive one authenticated SSH session through the fake shell."""
    server: HoneypotSSHServer = process.get_extra_info("honeypot_server")
    session = server.session
    engine = InteractionEngine()

    state = {"response_delay_seconds": 0.0, "highest_alerted_rank": -1}

    async def handle_live_classification(summary) -> None:
        if summary.deception_action is not None:
            state["response_delay_seconds"] = max(
                state["response_delay_seconds"],
                summary.deception_action.delay_seconds,
            )

        if summary.alert_action is None:
            return
        rank = _RISK_RANKS.get(summary.risk_level, 0)
        if rank <= state["highest_alerted_rank"]:
            return
        state["highest_alerted_rank"] = rank

        try:
            await asyncio.to_thread(
                _maybe_send_alert,
                None,
                session.active_record(),
                summary,
            )
        except Exception:
            logger.exception(
                "Live alert dispatch failed for session %s", session.session_id
            )

    live_classifier = LiveSessionClassifier(session, on_result=handle_live_classification)
    live_task = asyncio.create_task(live_classifier.run())

    end_reason = "disconnect"
    try:
        if process.command:
            # A non-interactive client (`ssh host "whoami"`) -- run the one
            # command through the same engine and exit, no shell loop. Not
            # "logout": no exit was typed, the client just ran one command.
            response = engine.process(process.command, session)
            if response != "__CLOSE__":
                process.stdout.write(response)
            end_reason = "disconnect"
        else:
            process.stdout.write(engine.build_banner(session))

            while True:
                try:
                    line = await asyncio.wait_for(
                        process.stdin.readline(),
                        timeout=READ_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    process.stdout.write("Session timed out.\n")
                    end_reason = "timeout"
                    break

                if not line:
                    end_reason = "disconnect"
                    break

                response = engine.process(line.rstrip("\r\n"), session)

                if response == "__CLOSE__":
                    process.stdout.write(
                        "logout\nConnection closed by remote host.\n"
                    )
                    end_reason = "logout"
                    break

                if state["response_delay_seconds"]:
                    await asyncio.sleep(state["response_delay_seconds"])

                process.stdout.write(response)

    except asyncio.CancelledError:
        end_reason = "shutdown"
    except Exception:
        logger.exception("SSH shell handler error for session %s", session.session_id)
        end_reason = "error"
    finally:
        live_task.cancel()
        await asyncio.gather(live_task, return_exceptions=True)
        server.end_reason = end_reason
        server._finalize(end_reason)
        # Returning from a process_factory handler does not close the SSH
        # channel by itself (asyncssh just lets the coroutine finish as a
        # background task) -- without this, the client hangs waiting for
        # EOF that never comes.
        if not process.channel.is_closing():
            process.exit(0)


class SSHListener:
    """Ingress layer for the SSH honeypot -- mirrors TCPServer/ProtocolServer's
    start()/shutdown() contract so main.py can manage it the same way.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        max_connections: int | None = None,
        host_key_path: str | None = None,
        session_logger: SessionLogger | None = None,
    ):
        # Resolved here (not as default parameter values) so tests that
        # monkeypatch these config names before constructing a listener --
        # the same pattern TCPServer/ProtocolServer already rely on --
        # actually take effect, instead of being baked in at import time.
        self.host = HOST if host is None else host
        self.port = PORT if port is None else port
        self.max_connections = MAX_CONNECTIONS if max_connections is None else max_connections
        self.host_key_path = SSH_HOST_KEY_PATH if host_key_path is None else host_key_path
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)
        self._acceptor: asyncssh.SSHAcceptor | None = None
        self._active_count = 0
        self._active_connections: set[asyncssh.SSHServerConnection] = set()

    def _server_factory(self) -> HoneypotSSHServer:
        return HoneypotSSHServer(
            session_logger=self.session_logger,
            on_connection_made=self._admit,
            on_connection_lost=self._release,
        )

    def _admit(self, conn: asyncssh.SSHServerConnection) -> bool:
        """Return False to refuse once the session limit is reached."""
        if self._active_count >= self.max_connections:
            return False
        self._active_count += 1
        self._active_connections.add(conn)
        return True

    def _release(self, conn: asyncssh.SSHServerConnection) -> None:
        self._active_count = max(0, self._active_count - 1)
        self._active_connections.discard(conn)

    async def start(self) -> None:
        """Bind the SSH listener and serve clients until cancelled."""
        key = ensure_host_key(self.host_key_path)

        self._acceptor = await asyncssh.create_server(
            self._server_factory,
            self.host,
            self.port,
            server_host_keys=[key],
            process_factory=handle_shell,
            server_version=_server_version_for(get_active_persona()),
        )
        logger.info("SSH server listening on %s:%s", self.host, self.port)

        # asyncssh's acceptor runs entirely via event-loop callbacks; keep
        # this coroutine alive (matching the other listeners' serve_forever
        # contract) until shutdown() cancels the task wrapping it.
        await asyncio.Event().wait()

    async def shutdown(self) -> None:
        """Stop accepting clients and close active sessions."""
        logger.info("Shutting down SSH server...")
        if self._acceptor is not None:
            self._acceptor.close()
            await self._acceptor.wait_closed()
        connections = list(self._active_connections)
        for conn in connections:
            conn.abort()
        await asyncio.gather(
            *(conn.wait_closed() for conn in connections),
            return_exceptions=True,
        )
        logger.info("SSH server shutdown complete.")
