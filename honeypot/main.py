import asyncio
import signal

# Import the custom TCPServer class (the 'brain' of the honeypot)
from honeypot.network.server import TCPServer


async def main():
    # 1. SETUP PHASE
    # Create the server object
    server = TCPServer()

    # An 'Event' is like a light switch. 
    # It starts at 'OFF' (False). When we flip it to 'ON', the program knows to stop.
    stop_event = asyncio.Event()

    # Get the 'loop' (the manager that schedules all the tasks)
    loop = asyncio.get_running_loop()

    # This function runs ONLY when you press Ctrl+C or kill the process
    def shutdown_signal():
        print("\n[!] Received shutdown signal")
        # Flip the 'stop_event' switch to ON
        stop_event.set()

    # Tell the manager: "If you see a SIGINT (Ctrl+C) or SIGTERM, run shutdown_signal"
    loop.add_signal_handler(signal.SIGINT, shutdown_signal)
    loop.add_signal_handler(signal.SIGTERM, shutdown_signal)

    # 2. RUNNING PHASE
    # 'create_task' starts the server in the background.
    # It doesn't wait for it to finish; it just kicks it off.
    server_task = asyncio.create_task(server.start())

    # The program pauses here and "waits" until the stop_event switch is flipped to ON.
    # This keeps the script alive while the server runs in the background.
    await stop_event.wait()

    # 3. CLEANUP PHASE (Runs after you press Ctrl+C)
    print("[*] Shutting down gracefully...")

    # Tell the server to stop accepting new connections and close existing ones
    await server.shutdown()

    # Tell the background server task to stop completely
    server_task.cancel()

    # 'gather' waits for the task to actually finish up. 
    # 'return_exceptions=True' prevents the program from crashing if the task complains about being cancelled.
    await asyncio.gather(server_task, return_exceptions=True)


if __name__ == "__main__":
    try:
        # Start the whole engine
        asyncio.run(main())
    except KeyboardInterrupt:
        # Final safety net in case the shutdown logic is bypassed
        print("[!] Forced exit")