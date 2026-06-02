import asyncio
import logging

# TCP listener configuration and per-client session handler
from honeypot.network.connection import ConnectionHandler
from honeypot.network.config import HOST, PORT, MAX_CONNECTIONS

logger = logging.getLogger(__name__)


class TCPServer:
    """
    TCP ingress layer for the honeypot.

    Accepts client connections, enforces the active connection limit, and tracks
    session tasks so they can be cancelled during shutdown.
    """

    def __init__(self):
        self.server = None
        # Active connection tasks are tracked so shutdown can cancel them
        self.tasks = set()

    async def start(self):
        """Start the TCP server and serve clients until cancelled."""

        # asyncio calls handle_client for each accepted connection
        self.server = await asyncio.start_server(
            self.handle_client,
            HOST,
            PORT,
        )

        addr = self.server.sockets[0].getsockname()
        logger.info("Server listening on %s", addr)

        # Keep serving until the task is cancelled during shutdown.
        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, reader, writer):
        """Accept one client and start its ConnectionHandler task."""

        # Refuse new clients once the configured session limit is reached
        if len(self.tasks) >= MAX_CONNECTIONS:
            logger.warning("Connection refused: max limit reached")
            writer.close()
            await writer.wait_closed()
            return

        
        handler = ConnectionHandler(reader, writer)

        # Run the client session concurrently with future connections
        task = asyncio.create_task(handler.handle())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        

    async def shutdown(self):
        """Stop accepting clients and cancel active session tasks."""

        logger.info("Shutting down server...")

        # Stop accepting new connections
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Cancel a stable snapshot so callbacks cannot change what we await.
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("Shutdown complete.")
