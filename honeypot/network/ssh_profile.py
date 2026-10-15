"""What the SSH decoy offers during the handshake, matched to its persona.

A client sees the server's key exchange, cipher, MAC, compression and host
key lists before it logs in, and scanners fingerprint servers by them. A
decoy announcing "OpenSSH_8.9p1 Ubuntu" while offering asyncssh's own lists
gives itself away, so for OpenSSH personas these follow the defaults of
the announced OpenSSH version (sshd with its default host keys: RSA, ECDSA
and Ed25519). Personas that aren't OpenSSH keep asyncssh's lists.

Names asyncssh doesn't support on this system (eg. sntrup761, which needs
liboqs, or umac, which needs nettle) are left out rather than failing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from asyncssh.compression import get_compression_algs
from asyncssh.encryption import get_encryption_algs
from asyncssh.kex import get_kex_algs
from asyncssh.mac import get_mac_algs

logger = logging.getLogger(__name__)

_OPENSSH_VERSION = re.compile(r"OpenSSH_(\d+)\.(\d+)")

_SNTRUP = "sntrup761x25519-sha512@openssh.com"
_ECDH_KEX = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
)
_DH_KEX = (
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
)
# OpenSSH 8.1 and earlier still offered the SHA-1 groups by default.
_DH_KEX_BEFORE_8_2 = (
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
)
_CIPHERS = (
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
)
_MACS = (
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
)
_COMPRESSION = ("none", "zlib@openssh.com")
# In sshd's order for its default keys (RSA, ECDSA, Ed25519). OpenSSH 8.8
# stopped offering SHA-1 RSA signatures ("ssh-rsa").
_HOST_KEY_ALGS = ("rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519")
_HOST_KEY_ALGS_BEFORE_8_8 = (
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ssh-ed25519",
)
_STRICT_KEX = b"kex-strict-s-v00@openssh.com"
_EXT_INFO = b"ext-info-s"

_warned_about_asyncssh = False


@dataclass(frozen=True)
class SshProfile:
    """The handshake lists one OpenSSH version offers."""

    kex_algs: tuple[str, ...]
    encryption_algs: tuple[str, ...]
    mac_algs: tuple[str, ...]
    compression_algs: tuple[str, ...]
    host_key_algs: tuple[str, ...]
    # OpenSSH servers list "ext-info-s" from 9.6 on; asyncssh always does.
    ext_info: bool

    def server_options(self) -> dict[str, list[str]]:
        """asyncssh create_server() keyword arguments, limited to what it supports."""
        return {
            "kex_algs": _supported(self.kex_algs, get_kex_algs()),
            "encryption_algs": _supported(self.encryption_algs, get_encryption_algs()),
            "mac_algs": _supported(self.mac_algs, get_mac_algs()),
            "compression_algs": _supported(self.compression_algs, get_compression_algs()),
        }

    def apply_to(self, conn) -> list[bytes] | None:
        """Set this connection's host key list and key exchange markers.

        asyncssh has no option for either on a server, so this sets its
        connection attributes before the handshake starts. Returns the host
        key types offered, or None if asyncssh no longer has those
        attributes (the connection then keeps asyncssh's lists).

        The strict key exchange marker stays even for versions that predate
        it: asyncssh turns strict mode on whenever the client asks for it,
        and a client that didn't see the marker would then fail the
        handshake.
        """
        global _warned_about_asyncssh
        try:
            available = conn._server_host_keys
            offered = [alg.encode() for alg in self.host_key_algs if alg.encode() in available]
            extras = ([_EXT_INFO] if self.ext_info else []) + [_STRICT_KEX]
            conn._server_host_key_algs = offered
            conn._get_extra_kex_algs = lambda: list(extras)
            return offered
        except AttributeError:
            if not _warned_about_asyncssh:
                _warned_about_asyncssh = True
                logger.warning(
                    "This asyncssh version doesn't allow setting the SSH host key list; "
                    "the decoy offers asyncssh's own"
                )
            return None


def _supported(names: tuple[str, ...], available: list[bytes]) -> list[str]:
    return [name for name in names if name.encode() in available]


def openssh_version(banner: str) -> tuple[int, int] | None:
    match = _OPENSSH_VERSION.search(banner)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def profile_for_banner(banner: str) -> SshProfile | None:
    """The handshake lists for the OpenSSH version in an SSH banner, or None."""
    version = openssh_version(banner)
    if version is None:
        return None

    if version >= (9, 0):
        kex = (_SNTRUP,) + _ECDH_KEX + _DH_KEX
    elif version >= (8, 5):
        kex = _ECDH_KEX + (_SNTRUP,) + _DH_KEX
    elif version >= (8, 2):
        kex = _ECDH_KEX + _DH_KEX
    else:
        kex = _ECDH_KEX + _DH_KEX_BEFORE_8_2

    return SshProfile(
        kex_algs=kex,
        encryption_algs=_CIPHERS,
        mac_algs=_MACS,
        compression_algs=_COMPRESSION,
        host_key_algs=_HOST_KEY_ALGS if version >= (8, 8) else _HOST_KEY_ALGS_BEFORE_8_8,
        ext_info=version >= (9, 6),
    )
