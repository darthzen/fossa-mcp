"""Tests for `Settings` normalization."""

import pytest
from pydantic import ValidationError

from fossa_mcp.config import Settings


def _settings(**kwargs) -> Settings:
    return Settings(_env_file=None, **kwargs)  # type: ignore[call-arg]


def test_token_trailing_newline_is_stripped():
    # Kubernetes Secrets created with --from-file keep the file's newline.
    assert _settings(fossa_api_token="fossa-token-value\n").fossa_api_token == "fossa-token-value"


def test_blank_token_is_treated_as_absent():
    assert _settings(fossa_api_token="   ").fossa_api_token is None


def test_stripped_token_reaches_the_authorization_header():
    from fossa_mcp.client import FossaClient

    client = FossaClient(_settings(fossa_api_token="fossa-token-value\n"))
    assert client._client.headers["Authorization"] == "Bearer fossa-token-value"


def test_base_url_trailing_slash_stripped():
    assert _settings(fossa_base_url="https://app.fossa.com/api/").base_url == (
        "https://app.fossa.com/api"
    )


def test_invalid_log_level_rejected():
    with pytest.raises(ValidationError):
        _settings(fossa_log_level="CHATTY")
