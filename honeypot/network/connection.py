import asyncio

# These are internal tools used to process what the hacker types
from honeypot.core.engine import InteractionEngine
from honeypot.core.session import SessionState
from honeypot.network.config import READ_TIMEOUT, get_active_persona


class ConnectionHandler:
    """
    This class is the manager for one single visitor (the 'attacker').
    It follows a simple loop: Hello -> Listen -> Think -> Respond -> Goodbye.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # reader: used to 'hear' what the visitor types
        self.reader = reader

        # writer: used to 'speak' (send data) back to the visitor
        self.writer = writer

        # Get the IP address and port of the visitor
        self.peer = writer.get_extra_info("peername")

        # SessionState stores facts about this specific visitor (like history)
        self.session = SessionState(self.peer, persona=get_active_persona())

        # InteractionEngine is the 'brain' that decides what to say back
        self.engine = InteractionEngine()

        # A safety switch to make sure we don't try to close a closed connection
        self._closed = False

    async def handle(self):  
        """This is the main 'brain' loop of the connection."""
        print(f"[+] Connection from {self.peer}")
        graceful = False  # Tracks if the visitor left nicely or just vanished

        try:
            # 1. SEND WELCOME: Send the fake login banner (e.g., "Ubuntu 22.04 Login:")
            await self._send(self.engine.build_banner(self.session))

            # 2. THE CHAT LOOP: Keep talking until someone leaves
            while True:
                try:
                    # Wait for the visitor to type a line. If they take too long, stop.
                    data = await asyncio.wait_for(
                        self.reader.readline(),
                        timeout=READ_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    # The visitor went silent for too long
                    print(f"[!] Timeout: {self.peer}")
                    await self._send("Session timed out.\n")
                    break
                
                # If the visitor closes their terminal, we get empty data
                if not data:
                    print(f"[-] Disconnected: {self.peer}")
                    break
                
                # Convert the raw bytes from the internet into readable text
                message = data.decode(errors="ignore").rstrip("\r\n")

                # Ask the 'brain' (engine) what to do with this message
                response = self.engine.process(message, self.session)

                # Special command: if the brain says "close", we exit the loop
                if response == "__CLOSE__":
                    await self._send("logout\nConnection closed by remote host.\n")
                    graceful = True  # They logged out properly
                    break
                
                # Send the brain's response back to the visitor
                await self._send(response)

        except asyncio.CancelledError:
            # System is shutting down
            print(f"[!] Connection cancelled: {self.peer}")

        except Exception as e:
            # Something went wrong (network error, etc.)
            print(f"[!] Error with {self.peer}: {e}")

        finally:
            # 3. CLEAN UP: Always close the door when finished
            await self.close(fast=not graceful)

    async def _send(self, text: str):
        """A helper tool to push text out to the visitor's screen."""
        if self._closed:
            return
        
        # Convert text to bytes and put it in the outgoing buffer
        self.writer.write(text.encode())
        # 'drain' makes sure the text actually leaves our computer and goes to them
        await self.writer.drain()

    async def close(self, fast: bool = False):
        """Shuts down the connection."""
        if self._closed:
            return

        self._closed = True

        try:
            if fast:
                # 'abort' is like hanging up the phone instantly
                transport = self.writer.transport
                if transport is not None:
                    transport.abort()
            else:
                # 'close' is like saying goodbye and waiting for the other person to hang up
                await self.writer.drain()
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            # If closing fails, we don't really care, the connection is dead anyway
            pass

        print(f"[x] Connection closed: {self.peer}")
