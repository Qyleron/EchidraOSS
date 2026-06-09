"""Command-line helpers for classifier storage setup."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from classifier.storage.config import (
    database_url_placeholder,
    get_database_url,
    redact_database_url,
)
from classifier.storage.repository import (
    DatabaseDriverMissingError,
    apply_schema,
)


DEFAULT_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def main(argv: list[str] | None = None) -> int:
    """Run storage setup commands and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init-db":
        return _init_db_command(args.schema_path)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m classifier.storage.cli",
        description="Set up Echidra classifier storage.",
    )
    subparsers = parser.add_subparsers(dest="command")

    init_db = subparsers.add_parser(
        "init-db",
        help="create or update PostgreSQL tables for classifier storage",
    )
    init_db.add_argument(
        "--schema",
        dest="schema_path",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="path to the schema.sql file",
    )

    return parser


def _init_db_command(schema_path: Path) -> int:
    database_url = get_database_url()
    if database_url is None:
        print(
            "error: ECHIDRA_DATABASE_URL is not set. "
            "Copy .env.example to .env and configure it first.",
            file=sys.stderr,
        )
        return 2

    placeholder = database_url_placeholder(database_url)
    if placeholder is not None:
        print(
            "error: ECHIDRA_DATABASE_URL still contains the placeholder "
            f"{placeholder}. Replace it with your local PostgreSQL value in .env.",
            file=sys.stderr,
        )
        return 2

    try:
        apply_schema(database_url, schema_path)
    except FileNotFoundError:
        print(f"error: schema file not found: {schema_path}", file=sys.stderr)
        return 2
    except DatabaseDriverMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        safe_message = redact_database_url(str(exc))
        print(f"error: failed to initialize database: {safe_message}", file=sys.stderr)
        return 2

    print("database initialized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
