"""The release build installs only hash-pinned tools (GitHub code scanning #31)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_build_installs_hash_pinned_tools_only():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert (
        "python -m pip install --require-hashes --only-binary :all: "
        "-r .github/release-requirements.txt"
    ) in workflow
    assert "python -m build --no-isolation" in workflow
    assert "pip install --upgrade build" not in workflow


def test_every_release_requirement_is_pinned_with_a_hash():
    lines = (ROOT / ".github/release-requirements.txt").read_text(encoding="utf-8").splitlines()
    pins = [line for line in lines if line and not line.startswith((" ", "#"))]

    assert {pin.split("==")[0] for pin in pins} == {"build", "packaging", "pyproject_hooks", "setuptools"}
    for index, line in enumerate(lines):
        if line in pins:
            assert "==" in line and line.endswith("\\")
            assert lines[index + 1].strip().startswith("--hash=sha256:")
            assert len(lines[index + 1].strip().removeprefix("--hash=sha256:")) == 64
