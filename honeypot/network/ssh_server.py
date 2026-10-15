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

from honeypot.core.engine import CLOSE_SIGNAL, InteractionEngine
from honeypot.core.session import SessionState
from honeypot.logging.session_logger import SessionLogger, finalize_and_schedule
from honeypot.network.config import (
    HOST,
    MAX_CONNECTIONS,
    PORT,
    READ_TIMEOUT,
    SESSION_LOG_PATH,
    SSH_HOST_KEY_PATH,
    get_active_persona,
)
from honeypot.network.ssh_keys import ensure_host_key, ensure_host_keys
from honeypot.network.ssh_profile import SshProfile, profile_for_banner
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

_CLIENT_VERSION_LIMIT = 255
_END_ERROR_LIMIT = 1000


def _printable(text: str, limit: int) -> str:
    """Client-supplied text, with control characters replaced, cut to limit."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:limit]


def _close_detail(exc: Exception | None, client_host_key_algs: list[str] | None) -> str | None:
    """The reason a connection failed, for the session record.

    A plain close carries no detail. asyncssh's host key mismatch message
    doesn't name the client's types, so they are added from what the
    client offered.
    """
    if exc is None:
        return None
    text = str(exc)
    if isinstance(exc, asyncssh.ConnectionLost) and text == "Connection lost":
        return None
    if isinstance(exc, asyncssh.KeyExchangeFailed) and "host key" in text and client_host_key_algs:
        text += f"; client offered {','.join(client_host_key_algs)}"
    return _printable(text, _END_ERROR_LIMIT) or None


# Ranks used to send a live alert only when the session's level rises, so
# the 30-second live check doesn't call the alert path on every pass.
# classifier/alerts.py applies the same rule again at session end.
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
        profile: SshProfile | None = None,
    ):
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)
        self._profile = profile
        self.session: SessionState | None = None
        self.end_reason = "disconnect"
        self._finalized = False
        self._on_connection_made = on_connection_made
        self._on_connection_lost = on_connection_lost
        self._admitted = False
        self._conn: asyncssh.SSHServerConnection | None = None
        self._auth_started = False
        self._password_sent = False
        self._client_host_key_algs: list[str] | None = None

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

        offered = self._profile.apply_to(conn) if self._profile is not None else None

        # asyncssh's "Unable to find compatible server host key" doesn't say
        # what the client asked for, so note the client's host key types as
        # asyncssh picks a key. asyncssh would also pick a key type it holds
        # but didn't offer (SHA-1 "ssh-rsa" from the RSA key), so the choice
        # is limited to what was offered.
        choose_server_host_key = conn.choose_server_host_key

        def note_client_host_key_algs(peer_host_key_algs):
            self._client_host_key_algs = [
                _printable(alg.decode("ascii", "replace"), 100) for alg in peer_host_key_algs[:30]
            ]
            if offered is not None:
                peer_host_key_algs = [alg for alg in peer_host_key_algs if alg in offered]
            return choose_server_host_key(peer_host_key_algs)

        conn.choose_server_host_key = note_client_host_key_algs

    def connection_lost(self, exc: Exception | None) -> None:
        if self._admitted and self._on_connection_lost is not None:
            self._on_connection_lost(self._conn)
        if self.session is not None and self.session.end_stage is None:
            # The connection ended before a shell opened.
            self.record_client_version()
            self.session.end_stage = self._stage_at_close(exc)
            self.session.end_error = _close_detail(exc, self._client_host_key_algs)
        self._finalize(self._end_reason_at_close(exc))

    def record_client_version(self) -> None:
        """Copy the client's SSH version line into the session, once it has one."""
        if self.session is None or self.session.client_version or self._conn is None:
            return
        version = self._conn.get_extra_info("client_version")
        if version:
            self.session.client_version = _printable(version, _CLIENT_VERSION_LIMIT)

    def _stage_at_close(self, exc: Exception | None) -> str:
        if isinstance(exc, asyncssh.ProtocolNotSupported):
            return "not_ssh"
        if isinstance(exc, asyncssh.KeyExchangeFailed):
            return "key_exchange_failed"
        if self.session.client_version is None:
            return "no_version"
        if self._password_sent:
            return "after_password"
        if self._auth_started:
            return "auth_without_password"
        return "before_auth"

    def _end_reason_at_close(self, exc: Exception | None) -> str:
        """A failed handshake or broken protocol is an error; a client
        closing the connection or giving up on logging in is a disconnect."""
        if exc is None:
            return self.end_reason
        if isinstance(exc, asyncssh.ConnectionLost) and "timeout" in str(exc).lower():
            return "timeout"
        if not isinstance(exc, asyncssh.DisconnectError) or isinstance(
            exc,
            (asyncssh.KeyExchangeFailed, asyncssh.ProtocolNotSupported, asyncssh.ProtocolError),
        ):
            return "error"
        return self.end_reason

    def begin_auth(self, username: str) -> bool:
        self._auth_started = True
        self.record_client_version()
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        self._password_sent = True
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
        finalize_and_schedule(self.session_logger, self.session, "SSH", logger)


async def handle_shell(process: asyncssh.SSHServerProcess) -> None:
    """Drive one authenticated SSH session through the fake shell."""
    server: HoneypotSSHServer = process.get_extra_info("honeypot_server")
    session = server.session
    session.end_stage = "shell"
    server.record_client_version()
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
            # No prompt after the output: `ssh host cmd` never shows one.
            response = engine.process(process.command, session)
            process.stdout.write(
                response.removesuffix(CLOSE_SIGNAL).removesuffix(session.prompt())
            )
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
                    # bash's own TMOUT wording
                    process.stdout.write(
                        "\ntimed out waiting for input: auto-logout\n"
                    )
                    end_reason = "timeout"
                    break

                if not line:
                    end_reason = "disconnect"
                    break

                response = engine.process(line.rstrip("\r\n"), session)

                if response.endswith(CLOSE_SIGNAL):
                    # Only "logout" comes from the server; the "Connection
                    # to ... closed." line is printed by the client itself.
                    # Output from earlier commands on the line comes first.
                    process.stdout.write(response.removesuffix(CLOSE_SIGNAL))
                    process.stdout.write("logout\n")
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
        self._profile: SshProfile | None = None

    def _server_factory(self) -> HoneypotSSHServer:
        return HoneypotSSHServer(
            session_logger=self.session_logger,
            on_connection_made=self._admit,
            on_connection_lost=self._release,
            profile=self._profile,
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
        persona = get_active_persona()
        # An OpenSSH persona offers that version's handshake lists and the
        # RSA, ECDSA and Ed25519 keys a default sshd has. Other personas
        # (Dropbear) keep the single Ed25519 key and asyncssh's lists.
        self._profile = profile_for_banner(persona.ssh_banner)
        if self._profile is not None:
            keys = ensure_host_keys(self.host_key_path)
            algorithm_options = self._profile.server_options()
        else:
            keys = [ensure_host_key(self.host_key_path)]
            algorithm_options = {}

        self._acceptor = await asyncssh.create_server(
            self._server_factory,
            self.host,
            self.port,
            server_host_keys=keys,
            **algorithm_options,
            process_factory=handle_shell,
            server_version=_server_version_for(persona),
            # Lets the shell send raw bytes (a program file's header) and
            # keeps a client's invalid UTF-8 from ending the session; the
            # session log stores those bytes as \xNN text.
            errors="surrogateescape",
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
