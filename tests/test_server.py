from honeypot.network.server import TCPServer


def test_server_initialization():
    server = TCPServer()

    assert server.server is None
    assert isinstance(server.tasks, set)