from honeypot.network.server import TCPServer


"""Basic construction tests for the TCP server wrapper."""


def test_server_initialization():
    """A new server should have no live asyncio server and no client tasks."""
    server = TCPServer()

    assert server.server is None
    assert isinstance(server.tasks, set)
