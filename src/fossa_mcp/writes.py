"""Write-tier gating shared by every tool that modifies FOSSA state.

The FOSSA write surface is 114 operations and they are not one risk. Assigning a
security policy, deleting every project matching a filter, and replacing an
organization's SAML configuration all "write", but an operator who wants the
first does not thereby want the third. So the gate is tiered, and each tier is
enabled independently:

* `WriteTier.WRITE` — create and update. `FOSSA_ALLOW_WRITES`.
* `WriteTier.DESTRUCTIVE` — deletes; writes that replace existing state
  wholesale rather than merging into it, where omitting a key erases it; and
  operations whose target set is unbounded (bulk endpoints that accept a filter
  rather than a list of ids). `FOSSA_ALLOW_DESTRUCTIVE`, **and**
  `FOSSA_ALLOW_WRITES`.
* `WriteTier.ADMIN` — identity, authentication, and access control: SAML, OIDC,
  roles, service accounts, team membership. `FOSSA_ALLOW_ADMIN`, **and**
  `FOSSA_ALLOW_WRITES`.

The higher tiers deliberately do not imply the lower one in either direction.
`FOSSA_ALLOW_DESTRUCTIVE=true` alone grants nothing; it is a qualifier on writes,
not a replacement for enabling them. This means the safe default survives a
half-configured deployment: a missing `FOSSA_ALLOW_WRITES` disables everything
regardless of what else is set.

Why this exists at all: under DECISIONS.md §2 the server authenticates no
callers and executes every request with one shared token. Anyone who reaches the
HTTP transport inherits whatever tiers are on. The gate is the only thing
between a misread tool call and an irreversible change, so it is checked in the
tool body before any request is constructed — never at registration time, and
never by the caller.
"""

from enum import Enum

from .config import Settings
from .errors import FossaWriteNotPermittedError


class WriteTier(Enum):
    """How much trust a write tool requires before it may run."""

    WRITE = "write"
    DESTRUCTIVE = "destructive"
    ADMIN = "admin"


_TIER_SETTING = {
    WriteTier.DESTRUCTIVE: ("fossa_allow_destructive", "FOSSA_ALLOW_DESTRUCTIVE"),
    WriteTier.ADMIN: ("fossa_allow_admin", "FOSSA_ALLOW_ADMIN"),
}

_TIER_RATIONALE = {
    WriteTier.DESTRUCTIVE: (
        "deletes FOSSA state, replaces it wholesale, or acts on an unbounded set of targets"
    ),
    WriteTier.ADMIN: "changes identity, authentication, or access control",
}


def require_tier(settings: Settings, tier: WriteTier, tool_name: str) -> None:
    """Refuse a write before any request is constructed.

    Raises:
        FossaWriteNotPermittedError: If the tool's tier is not enabled. The
            message names the tool, the reason it is gated, and the exact
            environment variable to set, so the refusal is actionable rather
            than a bare denial.
    """
    if not settings.fossa_allow_writes:
        raise FossaWriteNotPermittedError(
            f"{tool_name} modifies FOSSA state and FOSSA_ALLOW_WRITES is not enabled. "
            f"Set FOSSA_ALLOW_WRITES=true to permit it."
        )

    if tier is WriteTier.WRITE:
        return

    attribute, env_var = _TIER_SETTING[tier]
    if not getattr(settings, attribute):
        raise FossaWriteNotPermittedError(
            f"{tool_name} {_TIER_RATIONALE[tier]}, which requires the {tier.value} tier. "
            f"FOSSA_ALLOW_WRITES is enabled but {env_var} is not. "
            f"Set {env_var}=true to permit it."
        )


__all__ = ["WriteTier", "require_tier"]
