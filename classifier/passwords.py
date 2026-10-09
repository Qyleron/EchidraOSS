"""Dashboard password rules and hashing.

Shared by the API (signup/login) and `echidra reset-password`, so both
enforce the same rules and produce hashes the other can verify.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

PASSWORD_HASH_ITERATIONS = 390_000
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def validate_password_format(value: str) -> None:
    """Raise ValueError with a user-facing message if value isn't acceptable."""
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if len(value) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
    if any(character.isspace() for character in value):
        raise ValueError("Password must not contain spaces.")
    if not re.search(r"[A-Za-z]", value):
        raise ValueError("Password must contain a letter.")
    if not re.search(r"\d", value):
        raise ValueError("Password must contain a number.")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, digest = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations),
        ).hex()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(candidate, digest)
