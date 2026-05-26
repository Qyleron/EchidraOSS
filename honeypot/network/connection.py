import asyncio

# Core session state and fake-shell response generation
from honeypot.core.engine import InteractionEngine
from honeypot.core.session import SessionState
from honeypot.network.config import READ_TIMEOUT, get_active_persona


class ConnectionHandler:
    """
    Handle one client session from banner delivery through command processing
    and connection cleanup.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")


        # Each connection gets isolated state and the currently configured persona
        self.session = SessionState(self.peer, persona=get_active_persona())
        self.engine = InteractionEngine()
        self._closed = False

    async def handle(self):  
        """Run the client command loop until timeout, disconnect, exit, or shutdown."""
        print(f"[+] Connection from {self.peer}")
        graceful = False  # True when the client exits through the fake shell

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
                    print(f"[!] Timeout: {self.peer}")
                    await self._send("Session timed out.\n")
                    break
                
                # Empty reads indicate that the client disconnected
                if not data:
                    print(f"[-] Disconnected: {self.peer}")
                    break
                
                # Decode defensively so malformed input cannot crash the handler
                message = data.decode(errors="ignore").rstrip("\r\n")

                # Generate the fake shell response for this command
                response = self.engine.process(message, self.session)

                # "__CLOSE__" is the engine's internal signal for a shell logout
                if response == "__CLOSE__":
                    await self._send("logout\nConnection closed by remote host.\n")
                    graceful = True  
                    break
                
                # Send command output and the next prompt
                await self._send(response)

        except asyncio.CancelledError:
            # Server shutdown cancels active handler tasks
            print(f"[!] Connection cancelled: {self.peer}")

        except Exception as e:
            # Keep one failed session from crashing the server
            print(f"[!] Error with {self.peer}: {e}")

        finally:
            # Always close the transport after the session ends
            await self.close(fast=not graceful)

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

        print(f"[x] Connection closed: {self.peer}")
