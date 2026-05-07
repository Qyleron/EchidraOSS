import asyncio
import signal
from honeypot.network.server import TCPServer


async def main():
    server = TCPServer()
    loop = asyncio.get_running_loop()

    stop_event = asyncio.Event()

    def shutdown_signal():
        print("\n[!] Received shutdown signal")
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, shutdown_signal)
    loop.add_signal_handler(signal.SIGTERM, shutdown_signal)

    server_task = asyncio.create_task(server.start())

    await stop_event.wait()

    await server.shutdown()

    server_task.cancel()
    await asyncio.gather(server_task, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Forced exit")