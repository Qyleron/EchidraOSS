"""Configuration helpers for classifier database storage."""

from __future__ import annotations

import os
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from dotenv import load_dotenv


load_dotenv()

DATABASE_URL_ENV = "ECHIDRA_DATABASE_URL"
PLACEHOLDER_DATABASE_VALUES = {
    "YOUR_DATABASE",
    "YOUR_DB",
    "YOUR_DB_NAME",
    "YOUR_HOST",
    "YOUR_PASSWORD",
    "YOUR_PORT",
    "YOUR_USER",
    "YOUR_USERNAME",
}
_PASSWORD_KEYWORD_RE = re.compile(
    r"(password\s*=\s*)(?:'[^']*'|\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)
_DATABASE_URI_RE = re.compile(r"postgres(?:ql)?://\S+", re.IGNORECASE)


def get_database_url() -> str | None:
    """Return the configured PostgreSQL URL, if one has been provided."""
    value = os.getenv(DATABASE_URL_ENV)
    if value is None or not value.strip():
        return None
    return value


def database_url_placeholder(value: str) -> str | None:
    """Return the first obvious template placeholder still present, if any."""
    parsed = urlsplit(value)
    candidates = [
        parsed.username,
        parsed.password,
        parsed.hostname,
    ]
    path_value = parsed.path.lstrip("/") if parsed.path else None
    if path_value:
        candidates.append(path_value)

    for candidate in candidates:
        if candidate is None:
            continue
        decoded_candidate = unquote(candidate)
        if decoded_candidate in PLACEHOLDER_DATABASE_VALUES:
            return decoded_candidate

    return None


def redact_database_url(value: str) -> str:
    """Return a display-safe PostgreSQL connection string."""
    return _DATABASE_URI_RE.sub(
        lambda match: _redact_database_uri(match.group(0)),
        _PASSWORD_KEYWORD_RE.sub(r"\1***", value),
    )


def _redact_database_uri(value: str) -> str:
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.password is None or "@" not in parsed.netloc:
            return value

        userinfo, hostinfo = parsed.netloc.rsplit("@", 1)
        username = userinfo.split(":", 1)[0]
        netloc = f"{username}:***@{hostinfo}"
        return urlunsplit(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )

    return value
