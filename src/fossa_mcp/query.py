"""Query parameter helpers for FOSSA MCP server."""

from collections.abc import Sequence


def add_repeated(
    params: list[tuple[str, str]],
    key: str,
    values: Sequence[str] | None,
) -> None:
    """
    Add repeated query parameters with bracketed syntax.

    For FOSSA API parameters like filter[severity][]=critical&filter[severity][]=high
    """
    if values is not None and len(values) > 0:
        for value in values:
            params.append((f"{key}[]", value))


def bool_to_str(value: bool) -> str:
    """Convert a boolean to lowercase string for FOSSA API."""
    return "true" if value else "false"
