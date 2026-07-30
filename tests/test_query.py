"""Tests for FOSSA query helpers."""

import os
import sys

# Add src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fossa_mcp.query import add_repeated, bool_to_str, split_revision_locator


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


PROJECT = "git+github.com/acme/widget"
SHA = "7ac44a8de030f369b869cfd3548a13895b01f373"


def test_split_full_revision_locator():
    full, rev_id = split_revision_locator(PROJECT, f"{PROJECT}${SHA}")
    assert full == f"{PROJECT}${SHA}"
    assert rev_id == SHA


def test_split_accepts_bare_revision_id():
    full, rev_id = split_revision_locator(PROJECT, SHA)
    assert full == f"{PROJECT}${SHA}"
    assert rev_id == SHA


def test_split_is_idempotent_across_forms():
    """Both input forms must normalize to the same pair.

    FOSSA builds scope[id] + '$' + scope[revision] itself, so re-sending the
    full locator as scope[revision] produces `...widget$git+github...$sha` and a
    404. Normalizing here is what keeps one MCP argument usable for both the
    issue endpoints and the path-parameter endpoints.
    """
    assert split_revision_locator(PROJECT, f"{PROJECT}${SHA}") == split_revision_locator(
        PROJECT, SHA
    )


def test_split_preserves_dollar_inside_bare_revision():
    # A revision id is not always a bare sha; don't split on the last '$'.
    full, rev_id = split_revision_locator("npm+lodash", "4.17.21$build2")
    assert rev_id == "4.17.21$build2"
    assert full == "npm+lodash$4.17.21$build2"
