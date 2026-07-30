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


def split_revision_locator(project_locator: str, revision_locator: str) -> tuple[str, str]:
    """Return `(full_locator, revision_id)` for a project revision.

    FOSSA wants two different forms of the same revision depending on the
    endpoint, which is not obvious and is worth stating plainly:

    * Path parameters (`/v2/revisions/{locator}/...`) want the **full** locator,
      `git+github.com/acme/widget$abc123`.
    * `scope[revision]` on the issue endpoints wants the **bare revision id**,
      `abc123`. The server builds `scope[id]` + `$` + `scope[revision]` itself,
      so passing the full locator there yields a doubled string and a 404:
      `...widget$git+github.com/acme/widget$abc123`.

    Callers therefore accept either form from the model — the scope wording tells
    it to use the full locator — and normalize here.
    """
    prefix = f"{project_locator}$"
    if revision_locator.startswith(prefix):
        return revision_locator, revision_locator[len(prefix) :]
    return f"{project_locator}${revision_locator}", revision_locator
