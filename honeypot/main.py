import asyncio
import logging
import signal

# TCPServer owns listener startup, connection handling, and shutdown
from honeypot.network.server import TCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def main():
    # Start the TCP listener and keep the process alive until a shutdown signal
    server = TCPServer()
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()


    def shutdown_signal():
        logger.info("Received shutdown signal")
        stop_event.set()


    # Handle normal process termination from Ctrl+C or service managers
    loop.add_signal_handler(signal.SIGINT, shutdown_signal)
    if hasattr(signal, 'SIGTERM'):
        loop.add_signal_handler(signal.SIGTERM, shutdown_signal)


    server_task = asyncio.create_task(server.start())
    await stop_event.wait()


    logger.info("Shutting down gracefully...")
    await server.shutdown()

    server_task.cancel()
    await asyncio.gather(server_task, return_exceptions=True)


if __name__ == "__main__":
    try:
        # Run the honeypot until interrupted
        asyncio.run(main())
    except KeyboardInterrupt:
        # Fallback if signal-based shutdown is bypassed
        logger.warning("Forced exit")