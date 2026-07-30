"""Tests for FOSSA query helpers."""

import os
import sys

# Add src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fossa_mcp.query import add_repeated, bool_to_str


def test_add_repeated():
    """Test add_repeated function."""
    params = []

    # Test with None values
    add_repeated(params, "test", None)
    assert params == []

    # Test with empty list
    add_repeated(params, "test", [])
    assert params == []

    # Test with values
    add_repeated(params, "test", ["value1", "value2"])
    assert params == [("test[]", "value1"), ("test[]", "value2")]


def test_bool_to_str():
    """Test bool_to_str function."""
    assert bool_to_str(True) == "true"
    assert bool_to_str(False) == "false"
