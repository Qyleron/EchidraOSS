"""Persistent SSH host key for the asyncssh listener."""

from __future__ import annotations

import logging
from pathlib import Path

import asyncssh

logger = logging.getLogger(__name__)


def ensure_host_key(path: str) -> asyncssh.SSHKey:
    """Load the server's persistent SSH host key, generating one if missing.

    A honeypot that presents a different host key on every restart is a
    tell -- real servers keep the same key for years -- and breaks
    known_hosts pinning for anything that connected before. The key must
    survive process restarts, not just exist for the current one.
    """
    key_path = Path(path)
    if key_path.exists():
        return asyncssh.read_private_key(key_path)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(key_path)
    key_path.chmod(0o600)
    logger.info("Generated new SSH host key at %s", key_path)
    return key
