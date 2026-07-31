"""Organization settings and organization limits tools for the FOSSA MCP server.

These are the organization-wide defaults behind FOSSA's settings pages: which
policies new projects get, whether issue scanning and CI status checks are on,
the package registries and credentials scans use, and notification defaults.

The spec tags 59 operations `Organization Settings`. These four tools cover 57
of them. The other two — `PUT` and `DELETE /organizations/{id}/saml` — are
`fossa_update_saml_settings` and `fossa_delete_saml_settings` in
`tools/identity.py`, alongside OIDC, because replacing an organization's single
sign-on configuration deserves typed `cert` and `entry_point` arguments rather
than the free-form `values` dict a grouped section tool has to accept. Nothing
in this module can write or delete the SAML configuration; the `authentication`
section still *reports* it.

What FOSSA's API actually supports, which is what shapes these tools:

* The 57 operations are 55 across 22 near-identical sections that differ only by
  a path segment, plus the two organization limit reads, so the domain is
  grouped rather than one tool per endpoint (DECISIONS.md §7).
  `fossa_org_settings` reads, `fossa_update_org_settings` writes,
  `fossa_delete_org_setting` covers the one remaining delete, and
  `fossa_org_limits` reads the limits. The section names are a closed `Literal`
  derived from the spec — see `models/org_settings.py`.
* Every path is `/organizations/{id}/...`, so `FOSSA_ORG_ID` is required rather
  than optional here. `tools/policies.py` can degrade gracefully without it
  because the org lookup is one optional enrichment of a project read; for these
  tools the organization id *is* the resource, so its absence is a
  configuration error and is reported as one before any request is built.
* `PUT` replaces a section wholesale — it does not merge. Sending one key of a
  five-key section is how a section gets half-erased, so the sections whose spec
  marks keys required reject a partial body in the input model rather than
  passing it through.
* `PATCH` on a `projects-*` section is FOSSA's "apply to existing projects"
  switch: it pushes the named organization defaults down onto every project in
  the organization, overwriting whatever each project had. That is an unbounded
  target set from one tool call, so it is `DESTRUCTIVE` even though the verb is
  `PATCH` — tier follows blast radius, not HTTP method (API_PARITY_PLAN.md,
  "Write tiers"; DECISIONS.md §7).
* Most of these writes document no 2xx response at all, and
  `PUT /settings/integrations/custom-license-scans` documents a `204`. Every
  call here goes through `client.request_json_optional` for that reason. Two
  sections and all ten propagate endpoints also send a bare top-level JSON
  array rather than an object, which the client's `JsonBody` covers.

Undocumented integer scales such as
`projectDefaultStatusCheckFilterVulnerability` are carried through verbatim and
never interpreted (DECISIONS.md §6). Several documented `GET`s declare a
property-less `200`; the richer body a live organization returns is passed
through unchanged, because that is a gap in the vendored spec rather than an
unexpected response.
"""

from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..errors import FossaConfigurationError
from ..models.org_settings import (
    ORG_LIMIT_PATHS,
    ORG_SETTINGS_DELETE_PATHS,
    ORG_SETTINGS_GENERAL_ACCESS_CONTROL_KEYS,
    ORG_SETTINGS_READ_PATHS,
    ORG_SETTINGS_WRITE_SECTIONS,
    OrgLimit,
    OrgLimitsReadInput,
    OrgSettingsAction,
    OrgSettingsDeleteInput,
    OrgSettingsDeleteTarget,
    OrgSettingsReadInput,
    OrgSettingsSection,
    OrgSettingsUpdateInput,
    OrgSettingsWritableSection,
)
from ..writes import WriteTier, require_tier

# Sections whose write is an identity, authentication, or access-control change
# and therefore needs the ADMIN tier rather than plain WRITE.
#
# `authentication` owns the login subdomain and the invite switch. `general` is
# not listed because only two of its nine keys are access control — it escalates
# per call instead, in `_required_tiers`. The SAML configuration is not a
# section here at all; see `tools/identity.py`.
_ADMIN_SECTIONS: frozenset[str] = frozenset({"authentication"})


def _org_id(settings: Settings) -> int:
    """Return the configured organization id, or refuse with an actionable error.

    Every endpoint in this module is org-scoped, so there is no useful degraded
    mode: without the id there is no path to call.
    """
    if settings.fossa_org_id is None:
        raise FossaConfigurationError(
            "The organization settings tools address /organizations/{id}/... and "
            "FOSSA_ORG_ID is not set. Set FOSSA_ORG_ID to the numeric organization "
            "id shown in your FOSSA URL."
        )
    return settings.fossa_org_id


def _required_tiers(
    section: OrgSettingsWritableSection,
    action: OrgSettingsAction,
    values: dict[str, Any] | None,
) -> list[WriteTier]:
    """Decide which write tiers this particular call must satisfy.

    A grouped tool spans sections of different risk, so the tier is computed per
    call from the section and action rather than fixed at registration. Each
    returned tier is checked, and `require_tier` demands `FOSSA_ALLOW_WRITES`
    for all of them, so an ADMIN section is never reachable through a plain
    WRITE gate and a propagate is never reachable without the DESTRUCTIVE flag.
    """
    tiers: list[WriteTier] = []

    if section in _ADMIN_SECTIONS:
        tiers.append(WriteTier.ADMIN)
    elif section == "general" and values is not None:
        # Only escalate when the call actually touches the default role or the
        # built-in team roles; renaming the organization is not an ADMIN act.
        if ORG_SETTINGS_GENERAL_ACCESS_CONTROL_KEYS & set(values):
            tiers.append(WriteTier.ADMIN)

    if action == "propagate":
        tiers.append(WriteTier.DESTRUCTIVE)

    return tiers or [WriteTier.WRITE]


# --- reads -------------------------------------------------------------------


async def get_org_settings(
    ctx: Context,
    sections: list[OrgSettingsSection],
) -> dict[str, Any]:
    """
    Read one or more sections of a FOSSA organization's settings: the defaults
    new projects inherit, the package registries scans use, notification and
    privacy defaults, and the authentication configuration.

    Read-only. Requires FOSSA_ORG_ID. Each section is a separate FOSSA request,
    so ask only for what is needed. Sections are named after their endpoint:
    "authentication", "general", "integrations-custom-license-scans",
    "integrations-slack", the "languages-*" registry settings (bower, gem, git,
    mvn, npm, nuget, pip, pod), and the "projects-*" defaults
    (github-status-checks, hidden-snippet-urls, issues-container,
    issues-licensing, issues-quality, issues-security, notifications, privacy,
    quick-import-scan-methods, update-hooks). Credentials in the registry
    settings come back obfuscated by FOSSA.
    """
    validated = OrgSettingsReadInput(sections=sections)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    org_id = _org_id(settings)

    data: dict[str, Any] = {}
    for section in validated.sections:
        suffix = ORG_SETTINGS_READ_PATHS[section]
        data[section] = await client.request_json("GET", f"/organizations/{org_id}{suffix}")

    return {
        "ok": True,
        "endpoint": ", ".join(
            f"GET /organizations/{{id}}{ORG_SETTINGS_READ_PATHS[section]}"
            for section in validated.sections
        ),
        "data": data,
    }


async def get_org_limits(
    ctx: Context,
    limits: list[OrgLimit] | None = None,
) -> dict[str, Any]:
    """
    Read a FOSSA organization's plan limits and current usage for contributors
    and release groups.

    Read-only. Requires FOSSA_ORG_ID. Each limit reports `usage`, `max`, and
    `unlimited`. Defaults to both. Useful before creating a release group, which
    fails once the organization is at its limit.
    """
    validated = OrgLimitsReadInput(limits=limits or ["contributors", "release-groups"])

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    org_id = _org_id(settings)

    data: dict[str, Any] = {}
    for limit in validated.limits:
        suffix = ORG_LIMIT_PATHS[limit]
        data[limit] = await client.request_json("GET", f"/organizations/{org_id}{suffix}")

    return {
        "ok": True,
        "endpoint": ", ".join(
            f"GET /organizations/{{id}}{ORG_LIMIT_PATHS[limit]}" for limit in validated.limits
        ),
        "data": data,
    }


# --- writes ------------------------------------------------------------------


async def update_org_settings(
    ctx: Context,
    section: OrgSettingsWritableSection,
    action: OrgSettingsAction = "replace",
    values: dict[str, Any] | None = None,
    items: list[Any] | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """
    Write one section of a FOSSA organization's settings, or push a section's
    organization defaults down onto every existing project.

    WRITES TO FOSSA. Requires FOSSA_ORG_ID and FOSSA_ALLOW_WRITES=true. Some
    sections and actions require more; the tier is decided per call:

    * action="propagate" also requires FOSSA_ALLOW_DESTRUCTIVE=true. It
      overwrites the named setting on every project in the organization, and
      FOSSA offers no undo, so its target set is unbounded regardless of the
      HTTP verb.
    * section="authentication" also requires FOSSA_ALLOW_ADMIN=true, as does
      section="general" when `values` carries `defaultRoleId` or
      `disableNonCustomTeamUserRoles`.

    action="replace" (the default) sends the section's PUT. It REPLACES the
    section rather than merging, so pass the whole section, not just the key
    being changed; re-read it with fossa_org_settings first. `values` is the
    body, keyed by FOSSA's own field names, and unknown keys are rejected before
    any request is made. Two sections take a bare JSON array instead and use
    `items`: "languages-pod" (a list of source URLs) and
    "integrations-custom-license-scans" (objects with `name`, `matchCriteria`,
    and optionally `id`).

    action="propagate" sends the section's PATCH and takes `fields`, the
    organization defaults to push out. Only the ten "projects-*" sections
    support it, and each accepts its own field list.

    One writable section is not readable: "sbom-report-defaults" sets the author
    and supplier stamped into generated SBOMs. To replace the organization's SAML
    single sign-on configuration, use fossa_update_saml_settings — it is not a
    section here.
    """
    validated = OrgSettingsUpdateInput(
        section=section,
        action=action,
        values=values,
        items=items,
        fields=fields,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    for tier in _required_tiers(validated.section, validated.action, validated.values):
        require_tier(settings, tier, f"fossa_update_org_settings(section={validated.section!r})")

    org_id = _org_id(settings)

    suffix = ORG_SETTINGS_WRITE_SECTIONS[validated.section].path

    if validated.action == "propagate":
        method = "PATCH"
        payload: dict[str, Any] | list[Any] = list(validated.fields or [])
    else:
        method = "PUT"
        payload = validated.values if validated.values is not None else list(validated.items or [])

    result = await client.request_json_optional(
        method, f"/organizations/{org_id}{suffix}", json_body=payload
    )

    return {
        "ok": True,
        "endpoint": f"{method} /organizations/{{id}}{suffix}",
        "data": {
            "section": validated.section,
            "action": validated.action,
            "applied": payload,
            "settings": result,
        },
    }


async def delete_org_setting(
    ctx: Context,
    target: OrgSettingsDeleteTarget,
) -> dict[str, Any]:
    """
    Delete a FOSSA organization's logo.

    WRITES TO FOSSA. Requires FOSSA_ORG_ID, FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    target="logo" clears the organization's uploaded logo and nothing else. To
    remove the organization's SAML single sign-on configuration — the other
    organization-level delete in this part of the API — use
    fossa_delete_saml_settings.
    """
    validated = OrgSettingsDeleteInput(target=target)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(
        settings, WriteTier.DESTRUCTIVE, f"fossa_delete_org_setting(target={validated.target!r})"
    )

    org_id = _org_id(settings)
    suffix = ORG_SETTINGS_DELETE_PATHS[validated.target]

    result = await client.request_json_optional("DELETE", f"/organizations/{org_id}{suffix}")

    return {
        "ok": True,
        "endpoint": f"DELETE /organizations/{{id}}{suffix}",
        "data": {"target": validated.target, "deleted": True, "response": result},
    }


__all__ = [
    "delete_org_setting",
    "get_org_limits",
    "get_org_settings",
    "update_org_settings",
]
