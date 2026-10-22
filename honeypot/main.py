import asyncio
import logging
import signal

from classifier.catch_up import catch_up_pending_sessions
from classifier.pipeline import start_classification_workers, stop_classification_workers
from honeypot.network.config import HTTP_PORT, FTP_PORT, TELNET_PORT, HOST, MAX_CONNECTIONS, get_active_persona
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

_CATCH_UP_INTERVAL_SECONDS = 60.0
# How long applying the schema at start may wait for a table lock before
# giving up (see apply_schema).
_SCHEMA_LOCK_TIMEOUT_SECONDS = 5


def _update_database_schema() -> None:
    """Add any tables and columns this version needs, so an upgrade works
    without running init-db by hand. The schema is safe to apply again; on
    an up-to-date database it changes nothing."""
    from classifier.storage import get_database_url
    from classifier.storage.config import redact_database_url
    from classifier.storage.repository import apply_schema

    database_url = get_database_url()
    if database_url is None:
        return
    try:
        apply_schema(database_url, lock_timeout_seconds=_SCHEMA_LOCK_TIMEOUT_SECONDS)
    except Exception as exc:
        reason = (str(exc).strip().splitlines() or [type(exc).__name__])[0]
        logger.warning(
            "Couldn't update the database tables at start (%s). If sessions fail "
            "to store, run init-db: see 'Upgrading' in docs/DEPLOYMENT.md",
            redact_database_url(reason),
        )


async def _catch_up_loop() -> None:
    """Store sessions captured while the database was unreachable, within a
    minute of it coming back (classifier/catch_up.py)."""
    while True:
        try:
            await asyncio.to_thread(catch_up_pending_sessions)
        except Exception:
            logger.exception("Catching up pending sessions failed")
        await asyncio.sleep(_CATCH_UP_INTERVAL_SECONDS)


async def main():
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def shutdown_signal():
        logger.info("Received shutdown signal")
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, shutdown_signal)
    if hasattr(signal, "SIGTERM"):
        loop.add_signal_handler(signal.SIGTERM, shutdown_signal)

    # Before the persona lookup and the first session, both of which read
    # tables an upgrade may add to.
    await asyncio.to_thread(_update_database_schema)

    # Load the persona once, off the event loop, before anything listens:
    # after this, connections get the cached persona and stale reloads run
    # in the background (see get_active_persona).
    await asyncio.to_thread(get_active_persona)

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
    catch_up_task = asyncio.create_task(_catch_up_loop())

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
        catch_up_task.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(stop_task, catch_up_task, *tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        # Run the honeypot until interrupted
        asyncio.run(main())
    except KeyboardInterrupt:
        # Fallback if signal-based shutdown is bypassed
        logger.warning("Forced exit")