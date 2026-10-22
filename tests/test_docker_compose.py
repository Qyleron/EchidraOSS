"""Checks on docker-compose.yml that a misedit would otherwise only show in
production."""

from pathlib import Path

import yaml

COMPOSE_PATH = Path(__file__).resolve().parents[1] / "docker-compose.yml"


def test_every_service_rotates_its_container_logs():
    # Docker's default json-file driver never rotates: an unlimited log can
    # fill the disk.
    services = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))["services"]

    assert services
    for name, service in services.items():
        options = service.get("logging", {}).get("options", {})
        assert options.get("max-size"), f"{name} has no log size limit"
        assert options.get("max-file"), f"{name} keeps unlimited log files"
