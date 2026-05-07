import asyncio
from honeypot.network.connection import ConnectionHandler
from honeypot.network.config import HOST, PORT, MAX_CONNECTIONS


class TCPServer:
    """
    TCP Server responsible for:
    - Binding to port
    - Accepting connections
    - Spawning handlers
    """

    def __init__(self):
        self.server = None
        self.tasks = set()

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client,
            HOST,
            PORT
        )

        addr = self.server.sockets[0].getsockname()
        print(f"[+] Server listening on {addr}")

        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, reader, writer):
        if len(self.tasks) >= MAX_CONNECTIONS:
            print("[!] Connection refused: max limit reached")
            writer.close()
            await writer.wait_closed()
            return

        handler = ConnectionHandler(reader, writer)

        task = asyncio.create_task(handler.handle())
        self.tasks.add(task)

        # Cleanup finished tasks
        task.add_done_callback(self.tasks.discard)

    async def shutdown(self):
        print("\n[!] Shutting down server...")

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        for task in self.tasks:
            task.cancel()

        await asyncio.gather(*self.tasks, return_exceptions=True)

        print("[+] Shutdown complete.")