import asyncio
import json
import shutil

import asyncssh
import pytest
import pytest_asyncio

import honeypot.logging.session_logger as session_logger_module
import honeypot.network.ssh_server as ssh_server_module
from honeypot.logging.session_logger import SessionLogger
from honeypot.network.ssh_keys import ensure_host_keys
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


@pytest.fixture(scope="session")
def shared_host_keys(tmp_path_factory):
    """Generate the host keys once; an RSA key takes a moment to make."""
    key_path = tmp_path_factory.mktemp("host_keys") / "ssh_host_key"
    ensure_host_keys(str(key_path))
    return key_path


@pytest_asyncio.fixture
async def running_server(tmp_path, monkeypatch, shared_host_keys):
    """Start a real SSHListener on an ephemeral localhost port."""
    monkeypatch.setattr(ssh_server_module, "AUTH_DELAY_RANGE", (0.0, 0.0))
    log_path = tmp_path / "sessions.jsonl"
    for source in shared_host_keys.parent.iterdir():
        shutil.copy2(source, tmp_path / source.name)

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
async def test_ssh_session_schedules_auto_classification_after_logging(
    running_server, monkeypatch
):
    """Every completed session should be handed to the auto-classification
    hook, not just written to JSONL -- otherwise the only classification an
    SSH session ever gets is the periodic, partial live-classifier pass;
    nothing runs a full classification once the session actually ends."""
    scheduled = []
    monkeypatch.setattr(
        session_logger_module, "schedule_auto_classification", scheduled.append
    )
    port, _, log_path = running_server

    scheduled = []
    scheduled_event = asyncio.Event()

    def capture(session):
        scheduled.append(session)
        scheduled_event.set()

    monkeypatch.setattr(
        session_logger_module, "schedule_auto_classification", capture
    )

    conn = await connect(port, username="op", password="operator")
    await conn.run("whoami")
    conn.close()
    await conn.wait_closed()
    await asyncio.wait_for(scheduled_event.wait(), timeout=5)

    assert len(scheduled) == 1
    assert str(scheduled[0].session_id) == read_records(log_path)[0]["session_id"]


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
async def test_output_before_exit_on_the_same_line_is_sent(running_server):
    port, _, log_path = running_server

    conn = await connect(port)
    process = await conn.create_process(term_type="ansi")
    await asyncio.wait_for(process.stdout.readuntil("# "), timeout=5)

    # Escaped, so "bye" can only come from the output, not the typed line
    process.stdin.write('echo -e "\\x62\\x79\\x65"; exit\n')
    tail = await asyncio.wait_for(process.stdout.read(), timeout=5)
    assert "bye" in tail
    assert "logout" in tail

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    assert read_records(log_path)[0]["end_reason"] == "logout"


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
    # Just the output: `ssh host cmd` never prints a shell prompt
    assert result.stdout == "root\n"

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    record = read_records(log_path)[0]
    commands = [c["cmd"] for c in record["commands"]]
    assert commands == ["login: admin", "password: admin", "whoami"]
    assert record["end_reason"] == "disconnect"


@pytest.mark.asyncio
async def test_program_file_header_reaches_the_client_as_raw_bytes(running_server):
    """Byte 0x8A isn't valid UTF-8 on its own; the client must still get
    exactly that byte, or a loader misreads the header."""
    port, _, _ = running_server

    conn = await connect(port, username="admin", password="admin")
    result = await conn.run("cat /bin/echo", encoding=None)

    assert result.stdout[:4] == b"\x7fELF"
    assert result.stdout[18] == 0x3E  # x86_64
    assert result.stdout[40:42] == b"\x38\x8a"  # section table offset

    conn.close()
    await conn.wait_closed()


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


# ---------------------------------------------------------------------------
# how far a connection got, and the client's version line
# ---------------------------------------------------------------------------


async def wait_for_record(log_path):
    for _ in range(150):
        if log_path.exists() and log_path.read_text(encoding="utf-8").strip():
            return read_records(log_path)[0]
        await asyncio.sleep(0.02)
    raise AssertionError("the session was not logged")


@pytest.mark.asyncio
async def test_a_shell_session_records_the_client_version(running_server):
    port, _, log_path = running_server

    conn = await connect(port)
    await conn.run("whoami")
    conn.close()
    await conn.wait_closed()

    record = await wait_for_record(log_path)
    assert record["end_stage"] == "shell"
    assert record["client_version"].startswith("SSH-2.0-AsyncSSH")
    assert "end_error" not in record


@pytest.mark.asyncio
async def test_closing_after_the_password_without_a_shell(running_server):
    port, _, log_path = running_server

    conn = await connect(port, username="root", password="admin")
    conn.close()
    await conn.wait_closed()

    record = await wait_for_record(log_path)
    assert record["end_stage"] == "after_password"
    assert record["end_reason"] == "disconnect"
    assert record["client_version"].startswith("SSH-2.0-AsyncSSH")
    assert [c["cmd"] for c in record["commands"]] == ["login: root", "password: admin"]


@pytest.mark.asyncio
async def test_closing_before_sending_a_version_line(running_server):
    port, _, log_path = running_server

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    banner = await asyncio.wait_for(reader.readline(), timeout=3)
    assert banner.startswith(b"SSH-2.0-")
    writer.close()
    await writer.wait_closed()

    record = await wait_for_record(log_path)
    assert record["end_stage"] == "no_version"
    assert record["end_reason"] == "disconnect"
    assert "client_version" not in record
    assert "end_error" not in record


@pytest.mark.asyncio
async def test_traffic_that_is_not_ssh(running_server):
    port, _, log_path = running_server

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
    await writer.drain()
    await asyncio.wait_for(reader.read(), timeout=3)
    writer.close()

    record = await wait_for_record(log_path)
    assert record["end_stage"] == "not_ssh"
    assert record["end_reason"] == "error"
    assert record["end_error"] == "Unsupported SSH version"


@pytest.mark.asyncio
async def test_a_host_key_mismatch_records_what_the_client_offered(running_server):
    port, _, log_path = running_server

    with pytest.raises((asyncssh.Error, OSError)):
        await asyncio.wait_for(
            asyncssh.connect(
                "127.0.0.1",
                port,
                username="root",
                password="admin",
                known_hosts=None,
                # SHA-1 RSA signatures, which OpenSSH 8.8 and later refuse
                server_host_key_algs=["ssh-rsa"],
            ),
            timeout=5,
        )

    record = await wait_for_record(log_path)
    assert record["end_stage"] == "key_exchange_failed"
    assert record["end_reason"] == "error"
    assert record["end_error"] == (
        "Unable to find compatible server host key; client offered ssh-rsa"
    )
    assert record["commands"] == []


@pytest.mark.asyncio
async def test_a_login_without_a_password(running_server):
    port, _, log_path = running_server

    with pytest.raises((asyncssh.Error, OSError)):
        await asyncio.wait_for(
            asyncssh.connect(
                "127.0.0.1",
                port,
                username="root",
                known_hosts=None,
                agent_path=None,
                client_keys=[asyncssh.generate_private_key("ssh-ed25519")],
                preferred_auth="publickey",
            ),
            timeout=5,
        )

    record = await wait_for_record(log_path)
    assert record["end_stage"] == "auth_without_password"
    assert record["end_reason"] == "disconnect"
    assert record["commands"] == []


def _server_with_session(**flags):
    from honeypot.core.session import SessionState

    server = ssh_server_module.HoneypotSSHServer(session_logger=SessionLogger("unused.jsonl"))
    server.session = SessionState(("198.51.100.7", 40000))
    for name, value in flags.items():
        setattr(server, name, value)
    return server


def test_closing_after_the_handshake_before_logging_in():
    server = _server_with_session()
    server.session.client_version = "SSH-2.0-Go"

    assert server._stage_at_close(None) == "before_auth"


@pytest.mark.parametrize(
    "exc, expected_reason",
    [
        (None, "disconnect"),
        (asyncssh.ConnectionLost("Connection lost"), "disconnect"),
        (asyncssh.ConnectionLost("Login timeout expired"), "timeout"),
        (asyncssh.PermissionDenied("No more authentication methods available"), "disconnect"),
        (asyncssh.ProtocolNotSupported("Unsupported SSH version"), "error"),
        (asyncssh.KeyExchangeFailed("Unable to find compatible server host key"), "error"),
        (RuntimeError("unexpected"), "error"),
    ],
)
def test_end_reason_when_the_connection_closes_before_a_shell(exc, expected_reason):
    assert _server_with_session()._end_reason_at_close(exc) == expected_reason


def test_close_detail_is_printable_and_bounded():
    detail = ssh_server_module._close_detail(asyncssh.ProtocolError("bad\x00" + "x" * 2000), None)

    assert detail.startswith("bad?x")
    assert len(detail) == 1000
    assert ssh_server_module._close_detail(asyncssh.ConnectionLost("Connection lost"), None) is None


# ---------------------------------------------------------------------------
# host keys and handshake lists that match the persona's OpenSSH version
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host_key_alg, key_type",
    [
        ("rsa-sha2-512", "ssh-rsa"),
        ("rsa-sha2-256", "ssh-rsa"),
        ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
        ("ssh-ed25519", "ssh-ed25519"),
    ],
)
async def test_clients_limited_to_one_host_key_type_can_log_in(running_server, host_key_alg, key_type):
    port, _, _ = running_server

    conn = await asyncio.wait_for(
        asyncssh.connect(
            "127.0.0.1",
            port,
            username="root",
            password="admin",
            known_hosts=None,
            server_host_key_algs=[host_key_alg],
        ),
        timeout=5,
    )
    result = await conn.run("whoami", check=True)

    assert "root" in result.stdout
    assert conn.get_server_host_key().get_algorithm() == key_type
    conn.close()
    await conn.wait_closed()


@pytest.mark.asyncio
async def test_the_handshake_offers_what_the_persona_openssh_version_offers(running_server):
    """generic_linux announces OpenSSH 8.9p1: RSA (SHA-2 only), ECDSA and
    Ed25519 host keys in sshd's order, and no "ext-info-s" marker, which
    OpenSSH servers only send from 9.6 on."""
    port, listener, _ = running_server

    conn = await connect(port)
    server_conn = next(iter(listener._active_connections))

    assert server_conn._server_host_key_algs == [
        b"rsa-sha2-512", b"rsa-sha2-256", b"ecdsa-sha2-nistp256", b"ssh-ed25519",
    ]
    assert server_conn._get_extra_kex_algs() == [b"kex-strict-s-v00@openssh.com"]
    assert conn.get_extra_info("send_cipher") in {
        "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
        "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    }
    conn.close()
    await conn.wait_closed()
