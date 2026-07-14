"""Generic asyncio TCP server for non-shell protocol honeypot handlers."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from honeypot.logging.session_logger import SessionLogger
from honeypot.network.config import SESSION_LOG_PATH

logger = logging.getLogger(__name__)


class ProtocolServer:
    """
    Accepts TCP connections on a single port and dispatches them to a handler class.

    The handler class must accept (reader, writer) as its first two arguments
    and expose an async handle() method (e.g. TelnetHandler, FtpHandler, HttpHandler).
    """

    def __init__(
        self,
        host: str,
        port: int,
        handler_class: type,
        max_connections: int = 100,
        session_logger: Any | None = None,
    ):
        self.host = host
        self.port = port
        self.handler_class = handler_class
        self.max_connections = max_connections
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)
        self.server: Any = None
        self.tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        """Start listening and serve clients until cancelled."""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )
        sockets = self.server.sockets or ()
        if sockets:
            logger.info(
                "%s listening on %s",
                self.handler_class.__name__,
                sockets[0].getsockname(),
            )

        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if len(self.tasks) >= self.max_connections:
            logger.warning(
                "%s: connection refused — max limit reached",
                self.handler_class.__name__,
            )
            writer.close()
            await writer.wait_closed()
            return

        try:
            handler = self.handler_class(
                reader,
                writer,
                session_logger=self.session_logger,
            )
        except Exception:
            logger.exception("%s: failed to construct handler", self.handler_class.__name__)
            writer.close()
            await writer.wait_closed()
            return
        task = asyncio.create_task(handler.handle())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def shutdown(self) -> None:
        """Stop accepting connections and cancel active handler tasks."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
