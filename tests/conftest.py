"""Test configuration for FOSSA MCP server."""

import pytest
import sys
import os

# Add src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fossa_mcp.config import Settings


@pytest.fixture
def settings():
    """Provide default settings for tests."""
    return Settings()


@pytest.fixture
def sample_project_data():
    """Provide sample project data for testing."""
    return {
        "id": 1,
        "title": "Test Project",
        "locator": "git+github.com/test/project",
        "type": "container"
    }


@pytest.fixture
def sample_revision_data():
    """Provide sample revision data for testing."""
    return {
        "id": 1,
        "locator": "git+github.com/test/project$abc123",
        "branch": "main",
        "revision": "abc123"
    }