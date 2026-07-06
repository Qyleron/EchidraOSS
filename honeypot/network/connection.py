import asyncio
import logging

# Core session state and fake-shell response generation
from honeypot.core.engine import InteractionEngine
from honeypot.core.session import SessionState
from honeypot.logging.session_logger import SessionLogger
from honeypot.network.config import READ_TIMEOUT, SESSION_LOG_PATH, get_active_persona
from classifier.alerts import _maybe_send_alert
from classifier.realtime import LiveSessionClassifier

logger = logging.getLogger(__name__)


class ConnectionHandler:
    """
    Handle one client session from banner delivery through command processing
    and connection cleanup.
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


        # Each connection gets isolated state and the currently configured persona
        self.session = SessionState(self.peer, persona=get_active_persona())
        self.engine = InteractionEngine()
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)
        self._closed = False
        self._response_delay_seconds = 0.0
        self._highest_alerted_rank = -1

    async def handle(self):  
        """Run the client command loop until timeout, disconnect, exit, or shutdown."""
        logger.info("Connection from %s", self.peer)
        graceful = False  # True when the client exits through the fake shell
        end_reason = "disconnect"
        live_classifier = LiveSessionClassifier(
            self.session,
            on_result=self._handle_live_classification,
        )
        live_task = asyncio.create_task(live_classifier.run())

        try:
            # Send the initial fake login/banner text
            await self._send(self.engine.build_banner(self.session))

            # Read and respond to one newline-terminated command at a time
            while True:
                try:
                    # Close idle sessions after the configured read timeout
                    data = await asyncio.wait_for(
                        self.reader.readline(),
                        timeout=READ_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    # Client stayed idle past READ_TIMEOUT
                    logger.warning("Timeout: %s", self.peer)
                    await self._send("Session timed out.\n")
                    end_reason = "timeout"
                    break
                except asyncio.LimitOverrunError as exc:
                    logger.warning("Input too long from %s: %s", self.peer, exc)
                    await self._send("Input too long. Connection closed.\n")
                    end_reason = "error"
                    break
                
                # Empty reads indicate that the client disconnected
                if not data:
                    logger.info("Disconnected: %s", self.peer)
                    break
                
                # Decode defensively so malformed input cannot crash the handler
                message = data.decode(errors="ignore").rstrip("\r\n")

                # Generate the fake shell response for this command
                response = self.engine.process(message, self.session)

                # "__CLOSE__" is the engine's internal signal for a shell logout
                if response == "__CLOSE__":
                    await self._send("logout\nConnection closed by remote host.\n")
                    graceful = True
                    end_reason = "logout"
                    break

                if self._response_delay_seconds:
                    await asyncio.sleep(self._response_delay_seconds)
                
                # Send command output and the next prompt
                await self._send(response)

        except asyncio.CancelledError:
            # Server shutdown cancels active handler tasks
            logger.warning("Connection cancelled: %s", self.peer)
            end_reason = "shutdown"

        except Exception as e:
            # Keep one failed session from crashing the server
            logger.exception("Error with %s", self.peer)
            end_reason = "error"

        finally:
            live_task.cancel()
            await asyncio.gather(live_task, return_exceptions=True)
            # Always close the transport after the session ends
            await self.close(fast=not graceful)
            self.session.finalize(end_reason)
            try:
                self.session_logger.log(self.session)
            except Exception as e:
                # Logging failures should not keep dead connections open.
                logger.exception(
                    "Failed to persist session %s: %s",
                    self.session.session_id,
                    e,
                )

    async def _handle_live_classification(self, summary) -> None:
        """Apply local deception and dispatch each increased alert severity once."""
        if summary.deception_action is not None:
            self._response_delay_seconds = max(
                self._response_delay_seconds,
                summary.deception_action.delay_seconds,
            )

        if summary.alert_action is None:
            return
        ranks = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        rank = ranks.get(summary.risk_level, 0)
        if rank <= self._highest_alerted_rank:
            return
        self._highest_alerted_rank = rank

        # SMTP and PostgreSQL calls are blocking; keep them off the connection loop.

        await asyncio.to_thread(_maybe_send_alert, None, self.session.active_record(), summary)

    async def _send(self, text: str):
        """Send text to the connected client."""
        if self._closed:
            return
        
        # Encode text and queue it for transport
        self.writer.write(text.encode())
        # Flush the writer buffer before continuing
        await self.writer.drain()

    async def close(self, fast: bool = False):
        """Close the client connection, optionally aborting immediately."""
        if self._closed:
            return

        self._closed = True

        try:
            if fast:
                # Abort non-graceful disconnects and cancellation paths immediately
                transport = self.writer.transport
                if transport is not None:
                    transport.abort()
            else:
                # Graceful close lets pending output flush before closing the stream
                await self.writer.drain()
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            # Ignore close errors after the connection is already being torn down
            pass

        logger.info("Connection closed: %s", self.peer)
