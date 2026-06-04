"""FastAPI entry points for the Echidra classifier service."""

from classifier.api.app import app, create_app

__all__ = ["app", "create_app"]
