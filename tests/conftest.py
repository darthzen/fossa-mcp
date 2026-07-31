"""Shared test fixtures for the FOSSA MCP server test suite."""

import os
import sys

import httpx
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


def raw_path_of(request: httpx.Request) -> str:
    """Return the path exactly as it went on the wire, percent-encoding intact.

    `raw_path` carries the query string too, so split it off; query values are
    asserted separately by each module's `_query_pairs`.
    """
    return request.url.raw_path.decode().split("?", 1)[0]


def _assert_raw_path(request: httpx.Request, expected: str, *, base: str = "/api") -> None:
    """Assert a FOSSA locator was percent-encoded into the path exactly once.

    **Letting the respx route match does not verify encoding.** Both respx's
    route matching and `httpx.Request.url.path` normalize before comparing, so a
    route registered as `/api/projects/pip%2Baiofile` also matches a request
    that put `pip+aiofile` on the wire unescaped — verified directly against
    respx 0.23.1. Any test that "asserts" encoding by registering an encoded
    route and checking `route.called` passes whether or not the code under test
    encodes anything.

    `url.raw_path` is the bytes actually sent, so it is the only view that
    distinguishes the two. This helper is the one place that comparison lives.
    """
    assert raw_path_of(request) == f"{base}{expected}"


@pytest.fixture
def assert_raw_path():
    """Provide `_assert_raw_path` to a test.

    Fixture rather than a plain import so it reads the same as `make_context`
    and needs no `sys.path` games in the test modules.
    """
    return _assert_raw_path
