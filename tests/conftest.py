"""Shared test fixtures for the FOSSA MCP server test suite."""

import os
import sys

import pytest

# Add src to sys.path so the suite runs even when the editable install's .pth
# file is not honored. Concretely: iCloud Drive sets the macOS `hidden` flag on
# synced files and CPython 3.13+ skips hidden .pth files, so a `.venv` inside an
# iCloud folder yields an importable-nowhere package (see README).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fossa_mcp.config import Settings  # noqa: E402


class FakeRequestContext:
    """Minimal stand-in for `mcp.server.session.RequestContext`."""

    def __init__(self, client, settings):
        self.lifespan_context = {"client": client, "settings": settings}


class FakeContext:
    """Minimal stand-in for `mcp.server.fastmcp.Context` used in tool unit tests.

    Tool functions only ever read `ctx.request_context.lifespan_context`, so
    this avoids spinning up a full MCP session for tests that exercise tool
    logic directly against a respx-mocked `FossaClient`.
    """

    def __init__(self, client, settings):
        self.request_context = FakeRequestContext(client, settings)


@pytest.fixture
def settings() -> Settings:
    """Provide default settings for tests, with a token set for auth tests."""
    # `_env_file` is a genuine pydantic-settings per-instance override (not
    # reflected in its generated __init__ stub) that keeps tests from picking
    # up a real developer .env file.
    return Settings(fossa_api_token="test-token", _env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def make_context():
    """Factory fixture building a FakeContext from a client and settings."""
    return FakeContext
