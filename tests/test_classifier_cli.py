import json

from classifier.cli import main
from tests.test_classifier_pipeline import make_record


def test_cli_classify_jsonl_writes_summary_lines(tmp_path, capsys):
    """The batch CLI should emit one classifier summary per session log line."""
    log_path = tmp_path / "sessions.jsonl"
    records = [
        make_record(),
        make_record(),
    ]
    log_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    exit_code = main(["classify-jsonl", str(log_path)])

    captured = capsys.readouterr()
    summaries = [
        json.loads(line)
        for line in captured.out.splitlines()
    ]
    assert exit_code == 0
    assert len(summaries) == 2
    assert [summary["intent"] for summary in summaries] == [
        "credential_theft",
        "credential_theft",
    ]
    assert summaries[0]["feature_summary"]["command_count"] == 4


def test_cli_classify_jsonl_can_write_summary_file(tmp_path, capsys):
    log_path = tmp_path / "sessions.jsonl"
    output_path = tmp_path / "reports" / "summaries.jsonl"
    records = [
        make_record(),
        make_record(),
    ]
    log_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    exit_code = main([
        "classify-jsonl",
        str(log_path),
        "--output",
        str(output_path),
    ])

    captured = capsys.readouterr()
    summaries = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    assert exit_code == 0
    assert captured.out == ""
    assert len(summaries) == 2
    assert summaries[0]["risk_level"] == "medium"


def test_cli_classify_jsonl_reports_malformed_line(tmp_path, capsys):
    log_path = tmp_path / "sessions.jsonl"
    log_path.write_text(
        json.dumps(make_record()) + "\n"
        '{"session_id": "truncated-no-closing\n',
        encoding="utf-8",
    )

    exit_code = main(["classify-jsonl", str(log_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "invalid JSON on line 2" in captured.err
    assert "Traceback" not in captured.err


def test_cli_without_command_prints_help(capsys):
    exit_code = main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "classify-jsonl" in captured.out
