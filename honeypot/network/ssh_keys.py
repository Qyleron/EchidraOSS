"""Persistent SSH host key for the asyncssh listener."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import asyncssh

logger = logging.getLogger(__name__)


# A default sshd has an RSA, an ECDSA and an Ed25519 host key. The Ed25519
# key keeps the original path, so installs from before the other two
# existed keep presenting the same key.
_HOST_KEY_TYPES = (
    ("ssh-rsa", ".rsa", {"key_size": 3072}),
    ("ecdsa-sha2-nistp256", ".ecdsa", {}),
    ("ssh-ed25519", "", {}),
)


def ensure_host_key(path: str) -> asyncssh.SSHKey:
    """Load the server's persistent Ed25519 SSH host key, generating one if missing.

    A honeypot that presents a different host key on every restart is a
    tell -- real servers keep the same key for years -- and breaks
    known_hosts pinning for anything that connected before. The key must
    survive process restarts, not just exist for the current one.
    """
    return _ensure_key(Path(path), "ssh-ed25519")


def ensure_host_keys(path: str) -> list[asyncssh.SSHKey]:
    """Load (or generate once) an RSA, an ECDSA and an Ed25519 host key.

    Every install generates its own keys; shared keys would let anyone who
    found one Echidra recognise every other by its key fingerprint.
    """
    return [
        _ensure_key(Path(path + suffix), algorithm, **options)
        for algorithm, suffix, options in _HOST_KEY_TYPES
    ]


def _ensure_key(key_path: Path, algorithm: str, **options) -> asyncssh.SSHKey:
    if key_path.exists():
        return asyncssh.read_private_key(key_path)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key(algorithm, **options)
    # Created owner-only, so the private key is never readable by others,
    # even for the moment between writing it and setting its mode.
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as key_file:
        key_file.write(key.export_private_key())
    key_path.chmod(0o600)
    logger.info("Generated new %s SSH host key at %s", algorithm, key_path)
    return key
