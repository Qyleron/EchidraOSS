import asyncio
import json

import asyncssh
import pytest
import pytest_asyncio

import honeypot.network.ssh_server as ssh_server_module
from honeypot.logging.session_logger import SessionLogger
from honeypot.network.ssh_server import SSHListener, _server_version_for


"""
These are end-to-end tests against a real asyncssh server: a genuine SSH
handshake, host key, and USERAUTH exchange, not a mocked reader/writer --
that's the whole point of moving off the old raw-TCP fake login prompt.
"""


class _FakePersona:
    def __init__(self, ssh_banner):
        self.ssh_banner = ssh_banner


def test_server_version_for_strips_the_ssh_2_0_prefix():
    """asyncssh prepends "SSH-2.0-" itself when sending the wire banner --
    passing a persona's ssh_banner through unstripped would double it."""
    persona = _FakePersona("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

    assert _server_version_for(persona) == "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


def test_server_version_for_leaves_a_prefixless_banner_untouched():
    persona = _FakePersona("dropbear_2019.78")

    assert _server_version_for(persona) == "dropbear_2019.78"


@pytest_asyncio.fixture
async def running_server(tmp_path, monkeypatch):
    """Start a real SSHListener on an ephemeral localhost port."""
    monkeypatch.setattr(ssh_server_module, "AUTH_DELAY_RANGE", (0.0, 0.0))
    log_path = tmp_path / "sessions.jsonl"

    listener = SSHListener(
        host="127.0.0.1",
        port=0,
        host_key_path=str(tmp_path / "ssh_host_key"),
        session_logger=SessionLogger(str(log_path)),
    )
    task = asyncio.create_task(listener.start())

    for _ in range(100):
        if listener._acceptor is not None:
            break
        await asyncio.sleep(0.01)

    port = listener._acceptor.get_port()

    try:
        yield port, listener, log_path
    finally:
        await listener.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def connect(port, username="op", password="operator"):
    return await asyncio.wait_for(
        asyncssh.connect(
            "127.0.0.1",
            port,
            username=username,
            password=password,
            known_hosts=None,
        ),
        timeout=5,
    )


def read_records(log_path):
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.asyncio
async def test_accepts_any_credentials_and_reaches_the_fake_shell(running_server):
    """Rejecting credentials would end the engagement before any post-login
    behavior could be observed -- unlike Telnet/FTP, this listener must
    always let the client in, regardless of what it submits."""
    port, _, _ = running_server

    conn = await connect(port, username="whatever", password="anything-at-all")
    result = await conn.run("whoami", check=True)

    assert "root" in result.stdout

    conn.close()
    await conn.wait_closed()


@pytest.mark.asyncio
async def test_server_version_advertises_the_active_persona_ssh_banner(running_server):
    """A wire banner reading "AsyncSSH_x.y.z" (asyncssh's own default) instead
    of the persona's configured OpenSSH version is a one-command `nmap -sV`
    tell. asyncssh reconstructs the full "SSH-2.0-" + server_version string
    for this extra_info field, so it should read back out exactly as the
    persona's ssh_banner -- the active persona here is generic_linux, whose
    ssh_banner is "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"."""
    port, _, _ = running_server

    conn = await connect(port)
    assert conn.get_extra_info("server_version") == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

    conn.close()
    await conn.wait_closed()


@pytest.mark.asyncio
async def test_submitted_credentials_are_captured_before_shell_access(running_server):
    port, _, log_path = running_server

    conn = await connect(port, username="root", password="xc3511")
    await conn.run("whoami")
    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    commands = [c["cmd"] for c in read_records(log_path)[0]["commands"]]
    assert commands[:2] == ["login: root", "password: xc3511"]


@pytest.mark.asyncio
async def test_interactive_exit_produces_logout_reason(running_server):
    port, _, log_path = running_server

    conn = await connect(port)
    process = await conn.create_process(term_type="ansi")
    await asyncio.wait_for(process.stdout.readuntil("# "), timeout=5)

    process.stdin.write("exit\n")
    tail = await asyncio.wait_for(process.stdout.read(), timeout=5)
    assert "logout" in tail

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    record = read_records(log_path)[0]
    assert record["end_reason"] == "logout"
    assert [c["cmd"] for c in record["commands"]][-1] == "exit"


@pytest.mark.asyncio
async def test_client_disconnect_without_exit_produces_disconnect_reason(running_server):
    port, _, log_path = running_server

    conn = await connect(port)
    process = await conn.create_process(term_type="ansi")
    await asyncio.wait_for(process.stdout.readuntil("# "), timeout=5)

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    assert read_records(log_path)[0]["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_idle_session_times_out(running_server, monkeypatch):
    monkeypatch.setattr(ssh_server_module, "READ_TIMEOUT", 0.2)
    port, _, log_path = running_server

    conn = await connect(port)
    process = await conn.create_process(term_type="ansi")
    await asyncio.wait_for(process.stdout.readuntil("# "), timeout=5)

    tail = await asyncio.wait_for(process.stdout.read(), timeout=5)
    assert "timed out" in tail.lower()

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    assert read_records(log_path)[0]["end_reason"] == "timeout"


@pytest.mark.asyncio
async def test_non_interactive_exec_runs_one_command_without_a_shell_loop(running_server):
    """`ssh host "whoami"` (no PTY, no interactive shell) should still be
    served by the same fake-command engine, not just dropped."""
    port, _, log_path = running_server

    conn = await connect(port, username="admin", password="admin")
    result = await conn.run("whoami", check=True)
    assert "root" in result.stdout

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    record = read_records(log_path)[0]
    commands = [c["cmd"] for c in record["commands"]]
    assert commands == ["login: admin", "password: admin", "whoami"]
    assert record["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_two_clients_have_independent_shell_state(running_server):
    port, _, _ = running_server

    conn_a = await connect(port, username="a", password="a")
    conn_b = await connect(port, username="b", password="b")

    result_a = await conn_a.run("cat /etc/passwd", check=True)
    result_b = await conn_b.run("pwd", check=True)

    assert "root:x:0:0" in result_a.stdout
    assert "/home/admin" in result_b.stdout

    conn_a.close()
    conn_b.close()
    await conn_a.wait_closed()
    await conn_b.wait_closed()


@pytest.mark.asyncio
async def test_server_rejects_connections_over_the_global_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_server_module, "AUTH_DELAY_RANGE", (0.0, 0.0))
    listener = SSHListener(
        host="127.0.0.1",
        port=0,
        max_connections=1,
        host_key_path=str(tmp_path / "ssh_host_key"),
        session_logger=SessionLogger(str(tmp_path / "sessions.jsonl")),
    )
    task = asyncio.create_task(listener.start())
    for _ in range(100):
        if listener._acceptor is not None:
            break
        await asyncio.sleep(0.01)
    port = listener._acceptor.get_port()

    try:
        holder = await connect(port)

        # A second attempt should be refused at the TCP level before any SSH
        # handshake completes -- checked with a raw socket so a hung SSH
        # handshake against an aborted connection can't make this test hang.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        data = await asyncio.wait_for(reader.read(1), timeout=3)
        assert data == b""
        writer.close()

        holder.close()
        await holder.wait_closed()
    finally:
        await listener.shutdown()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_ten_concurrent_clients_complete_independently(running_server):
    """Real SSH handshakes are far more expensive than raw sockets --
    this stays modest in scale (unlike the old raw-TCP load tests) but
    still proves the listener handles genuine concurrency correctly."""
    port, _, _ = running_server

    async def one_client(n):
        conn = await connect(port, username=f"user{n}", password=f"pass{n}")
        result = await conn.run("whoami", check=True)
        assert "root" in result.stdout
        conn.close()
        await conn.wait_closed()

    await asyncio.wait_for(
        asyncio.gather(*(one_client(n) for n in range(10))),
        timeout=15,
    )
