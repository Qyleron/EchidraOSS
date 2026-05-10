import asyncio

# Importing external settings and the 'worker' class (ConnectionHandler)
from honeypot.network.connection import ConnectionHandler
from honeypot.network.config import HOST, PORT, MAX_CONNECTIONS


class TCPServer:
    """
    TCP ingress layer: The 'Front Door' of the honeypot.
    It accepts incoming connections and passes them to a handler.
    """

    def __init__(self):
        self.server = None
        # We keep track of active connections (tasks) in a set
        # so we can manage them and close them all at once later.
        self.tasks = set()

    async def start(self):
        """
        Step 1: Boots up the server and keeps it running forever.
        """
        # Create the server object and tell it which function to run 
        # whenever someone connects (self.handle_client)
        self.server = await asyncio.start_server(
            self.handle_client,
            HOST,
            PORT,
        )

        addr = self.server.sockets[0].getsockname()
        print(f"[+] Server listening on {addr}")

        # 'serve_forever' keeps the script from finishing immediately
        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, reader, writer):
        """
        Step 2: Triggered every time a new user connects.
        """
        # SECURITY CHECK: Is the building full?
        if len(self.tasks) >= MAX_CONNECTIONS:
            print("[!] Connection refused: max limit reached")
            writer.close()
            await writer.wait_closed()
            return

        # Create a 'Handler' object to talk to this specific user
        handler = ConnectionHandler(reader, writer)

        # We wrap the handler's work in a 'Task' so it runs in the 
        # background without blocking other new connections.
        task = asyncio.create_task(handler.handle())

        # Register the task so we know it's active
        self.tasks.add(task)

        # When the conversation ends, automatically remove it from our set
        task.add_done_callback(self.tasks.discard)

    async def shutdown(self):
        """
        Step 3: Gracefully turn off the lights.
        """
        print("\n[!] Shutting down server...")

        # Stop accepting NEW connections
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Tell all CURRENT conversations to stop immediately
        for task in list(self.tasks):
            task.cancel()
   
        # Wait for all tasks to acknowledge the cancellation
        await asyncio.gather(*self.tasks, return_exceptions=True)

        print("[+] Shutdown complete.")