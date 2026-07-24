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
from classifier.storage.issue_sync import (
    DEFAULT_ISSUE_PLAYBOOK_PATH,
    DEFAULT_MITRE_CATALOG_PATH,
    sync_issues_from_classifier_runs,
)
from classifier.storage.repository import (
    DatabaseDriverMissingError,
    apply_schema,
    seed_demo_issues,
)


DEFAULT_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def main(argv: list[str] | None = None) -> int:
    """Run storage setup commands and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init-db":
        return _init_db_command(args.schema_path, args.seed_demo_issues)
    if args.command == "sync-issues":
        return _sync_issues_command(args.playbook_path, args.mitre_catalog_path)

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
    init_db.add_argument(
        "--seed-demo-issues",
        action="store_true",
        help="insert demo intelligence issues after schema initialization",
    )

    sync_issues = subparsers.add_parser(
        "sync-issues",
        help="roll real classifier output up into persisted Intelligence issues",
    )
    sync_issues.add_argument(
        "--playbook",
        dest="playbook_path",
        type=Path,
        default=DEFAULT_ISSUE_PLAYBOOK_PATH,
        help="path to the issue playbook YAML file",
    )
    sync_issues.add_argument(
        "--mitre-catalog",
        dest="mitre_catalog_path",
        type=Path,
        default=DEFAULT_MITRE_CATALOG_PATH,
        help="path to the generated MITRE technique id -> name catalog",
    )

    return parser


def _init_db_command(schema_path: Path, seed_demo_issues_flag: bool) -> int:
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

    # Printed before connecting so a wrong host/user/dbname in .env is visible
    # immediately -- eg. if you reset a database with `dropdb`/`createdb` using
    # different default connection args than this URL uses.
    print(f"Connecting to {redact_database_url(database_url)} ...")

    try:
        apply_schema(database_url, schema_path)
        if seed_demo_issues_flag:
            seed_demo_issues(database_url)
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


def _sync_issues_command(playbook_path: Path, mitre_catalog_path: Path) -> int:
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
        issues = sync_issues_from_classifier_runs(
            database_url=database_url,
            playbook_path=playbook_path,
            mitre_catalog_path=mitre_catalog_path,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except DatabaseDriverMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        safe_message = redact_database_url(str(exc))
        print(f"error: failed to sync issues: {safe_message}", file=sys.stderr)
        return 2

    print(f"synced {len(issues)} issue(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
