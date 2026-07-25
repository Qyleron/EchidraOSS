import asyncio
import logging
import signal

from classifier.pipeline import start_classification_workers, stop_classification_workers
from honeypot.network.config import HTTP_PORT, FTP_PORT, TELNET_PORT, HOST, MAX_CONNECTIONS
from honeypot.network.ftp_handler import FtpHandler
from honeypot.network.http_handler import HttpHandler
from honeypot.network.protocol_server import ProtocolServer
from honeypot.network.ssh_server import SSHListener
from honeypot.network.telnet_handler import TelnetHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def main():
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def shutdown_signal():
        logger.info("Received shutdown signal")
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, shutdown_signal)
    if hasattr(signal, "SIGTERM"):
        loop.add_signal_handler(signal.SIGTERM, shutdown_signal)

    # Primary SSH honeypot listener
    ssh_server = SSHListener()

    # Additional protocol listeners (disabled when port == 0)
    extra_servers: list[ProtocolServer] = []
    if HTTP_PORT:
        extra_servers.append(
            ProtocolServer(HOST, HTTP_PORT, HttpHandler, MAX_CONNECTIONS)
        )
    if FTP_PORT:
        extra_servers.append(
            ProtocolServer(HOST, FTP_PORT, FtpHandler, MAX_CONNECTIONS)
        )
    if TELNET_PORT:
        extra_servers.append(
            ProtocolServer(HOST, TELNET_PORT, TelnetHandler, MAX_CONNECTIONS)
        )

    tasks = [asyncio.create_task(ssh_server.start())]
    tasks += [asyncio.create_task(s.start()) for s in extra_servers]
    stop_task = asyncio.create_task(stop_event.wait())

    try:
        start_classification_workers()

        remaining = list(tasks)
        stopped_by_signal = False
        while remaining:
            done, _ = await asyncio.wait(
                [stop_task, *remaining],
                return_when=asyncio.FIRST_COMPLETED,
            )
            if stop_task in done:
                stopped_by_signal = True
                break
            for task in done:
                try:
                    task.result()
                except Exception:
                    logger.exception("A protocol listener terminated unexpectedly")
            remaining = [t for t in remaining if t not in done]

        if not stopped_by_signal:
            # Every listener task finished on its own without a shutdown
            # signal -- since they otherwise run until cancelled, that only
            # happens when every one of them has crashed. Exit with an error
            # instead of a clean 0, so nothing keeps running unnoticed with
            # no listeners actually up, and the wrapping `echidra start`
            # process reports the failure instead of looking successful.
            logger.critical("All protocol listeners have failed -- nothing is listening.")
            raise SystemExit(1)
    finally:
        logger.info("Shutting down gracefully...")
        await ssh_server.shutdown()
        for s in extra_servers:
            await s.shutdown()
        await stop_classification_workers()

        stop_task.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(stop_task, *tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        # Run the honeypot until interrupted
        asyncio.run(main())
    except KeyboardInterrupt:
        # Fallback if signal-based shutdown is bypassed
        logger.warning("Forced exit")