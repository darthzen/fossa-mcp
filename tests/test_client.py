"""Tests for FOSSA client."""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

# Add src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings


@pytest.mark.asyncio
async def test_client_initialization():
    """Test FOSSA client initialization."""
    settings = Settings(fossa_api_token="test-token")

    # Mock transport to avoid real HTTP calls
    mock_transport = MagicMock()

    client = FossaClient(settings, transport=mock_transport)

    assert client.settings == settings
    await client.aclose()


@pytest.mark.asyncio
async def test_client_request_json():
    """Test FOSSA client JSON request."""
    settings = Settings(fossa_api_token="test-token")

    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"test": "data"}
    mock_response.elapsed.total_seconds.return_value = 0.1

    with patch('httpx.AsyncClient.request', return_value=mock_response):
        client = FossaClient(settings)

        # Test successful request
        result = await client.request_json("GET", "/test")
        assert result == {"test": "data"}

        await client.aclose()


@pytest.mark.asyncio
async def test_client_request_text():
    """Test FOSSA client text request."""
    settings = Settings(fossa_api_token="test-token")

    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "test content"
    mock_response.headers = {"content-type": "text/plain"}
    mock_response.elapsed.total_seconds.return_value = 0.1

    with patch('httpx.AsyncClient.request', return_value=mock_response):
        client = FossaClient(settings)

        # Test successful request
        result, content_type = await client.request_text("GET", "/test")
        assert result == "test content"
        assert content_type == "text/plain"

        await client.aclose()