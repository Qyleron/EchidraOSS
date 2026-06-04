"""Command-line entry points for Echidra classifier workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from classifier.pipeline import classify_session_jsonl


def main(argv: list[str] | None = None) -> int:
    """Run classifier CLI commands and return a process exit code.

    Raises SystemExit for invalid command-line arguments through argparse.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "classify-jsonl":
        try:
            _classify_jsonl_command(args.input_path, args.output_path)
            return 0
        except (OSError, ValueError, ValidationError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m classifier.cli",
        description="Classify Echidra session logs.",
    )
    subparsers = parser.add_subparsers(dest="command")

    classify_jsonl = subparsers.add_parser(
        "classify-jsonl",
        help="classify every session record in a JSONL log file",
    )
    classify_jsonl.add_argument(
        "input_path",
        type=Path,
        help="path to a JSONL file emitted by SessionLogger",
    )
    classify_jsonl.add_argument(
        "-o",
        "--output",
        dest="output_path",
        type=Path,
        help="optional path for JSONL classifier summaries; defaults to stdout",
    )

    return parser


def _classify_jsonl_command(input_path: Path, output_path: Path | None) -> None:
    """Write classifier summaries to stdout or the requested output file."""
    if output_path is None:
        _write_jsonl_summaries(input_path, sys.stdout)
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output:
        _write_jsonl_summaries(input_path, output)


def _write_jsonl_summaries(input_path: Path, output: TextIO) -> None:
    """Write one JSON classifier summary per input session line."""
    with input_path.open("r", encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue

            try:
                summary = classify_session_jsonl(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON on line {line_number}: {exc}"
                ) from exc
            except ValidationError as exc:
                raise ValueError(
                    f"invalid session record on line {line_number}: {exc}"
                ) from exc

            json.dump(json.loads(summary.json()), output, sort_keys=True)
            output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
