from asyncssh.compression import get_compression_algs
from asyncssh.encryption import get_encryption_algs
from asyncssh.kex import get_kex_algs
from asyncssh.mac import get_mac_algs

import pytest

from honeypot.core.persona import PRESET_PERSONAS
from honeypot.network.ssh_profile import openssh_version, profile_for_banner


@pytest.mark.parametrize(
    "banner, version",
    [
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", (8, 9)),
        ("SSH-2.0-OpenSSH_7.4", (7, 4)),
        ("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", (9, 2)),
        ("SSH-2.0-dropbear_2019.78", None),
    ],
)
def test_openssh_version_from_banner(banner, version):
    assert openssh_version(banner) == version


def test_dropbear_keeps_asyncssh_lists():
    assert profile_for_banner("SSH-2.0-dropbear_2019.78") is None


def test_openssh_8_9_offers_sha2_rsa_ecdsa_and_ed25519_without_ext_info():
    profile = profile_for_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

    assert profile.host_key_algs == ("rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519")
    assert profile.ext_info is False
    # sntrup761 is in the 8.5-8.9 default list after the ECDH methods
    assert profile.kex_algs.index("sntrup761x25519-sha512@openssh.com") == 5


def test_openssh_before_8_8_still_offers_sha1_rsa_signatures():
    assert "ssh-rsa" in profile_for_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5").host_key_algs


def test_openssh_9_puts_sntrup761_first():
    profile = profile_for_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2")

    assert profile.kex_algs[0] == "sntrup761x25519-sha512@openssh.com"


def test_openssh_before_8_2_offers_the_sha1_groups():
    kex = profile_for_banner("SSH-2.0-OpenSSH_7.4").kex_algs

    assert "diffie-hellman-group14-sha1" in kex
    assert "sntrup761x25519-sha512@openssh.com" not in kex


def test_openssh_9_6_lists_ext_info():
    assert profile_for_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13").ext_info is True


@pytest.mark.parametrize("persona_id", sorted(PRESET_PERSONAS))
def test_every_persona_gets_options_asyncssh_accepts(persona_id):
    profile = profile_for_banner(PRESET_PERSONAS[persona_id].ssh_banner)
    if profile is None:
        return

    options = profile.server_options()

    supported = {
        "kex_algs": get_kex_algs(),
        "encryption_algs": get_encryption_algs(),
        "mac_algs": get_mac_algs(),
        "compression_algs": get_compression_algs(),
    }
    for name, values in options.items():
        assert values, name
        assert all(value.encode() in supported[name] for value in values)
