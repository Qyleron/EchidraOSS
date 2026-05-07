import asyncio
from honeypot.core.session import SessionState
from honeypot.network.config import READ_TIMEOUT


class ConnectionHandler:
    """
    Handles a single TCP client connection.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")

        # Session per attacker
        self.session = SessionState(self.peer)

        self._closed = False  # prevent double close

    async def handle(self):
        print(f"[+] Connection from {self.peer}")

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        self.reader.read(1024),
                        timeout=READ_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    print(f"[!] Timeout: {self.peer}")
                    break

                if not data:
                    print(f"[-] Disconnected: {self.peer}")
                    break

                message = data.decode(errors="ignore").strip()

                # Log command
                self.session.log_command(message)

                print(f"[{self.peer}] >> {message}")

                # Placeholder response
                response = "Echo: " + message + "\n"

                self.writer.write(response.encode())
                await self.writer.drain()

        except asyncio.CancelledError:
            print(f"[!] Connection cancelled: {self.peer}")

        except Exception as e:
            print(f"[!] Error with {self.peer}: {e}")

        finally:
            await self.close()

    async def close(self):
        """
        Clean connection shutdown.
        Safe against double execution.
        """
        if self._closed:
            return

        self._closed = True

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

        print(f"[x] Connection closed: {self.peer}")