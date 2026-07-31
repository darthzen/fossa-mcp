"""Label tools for the FOSSA MCP server.

Covers the twelve label operations that are not already reachable from another
domain's tools. `GET /projects/{locator}/labels` and `PUT /v2/projects/labels`
belong to the project surface and live in `tools/projects.py`
(`fossa_get_project_associations`, `fossa_apply_project_label`); they are not
duplicated here.

Two distinct resources share the word "label", and the tool names keep them
apart: an **organization label** tags projects, a **package label** tags a
package at a version within a scope. See `models/labels.py` for the input rules,
including why no tool in this module lets a blank package version reach FOSSA.

Tiers, and why each one sits where it does:

* `WRITE` — `create_package_labels`, `assign_package_labels`,
  `bulk_assign_package_label`, `create_organization_label`. All four only add.
* `DESTRUCTIVE` — `delete_package_labels`, `unassign_package_labels`,
  `delete_organization_label`, and `set_package_label_assignments`.

`set_package_label_assignments` is the one that is not obvious. It is a `PUT`
and it creates assignments, but `PUT /package-label-assignments` is a
reconcile: FOSSA removes every existing assignment for that package and scope
that the supplied map does not mention. Per DECISIONS.md §7 the tier follows
blast radius rather than the verb, and silent removal is blast radius.

`bulk_assign_package_label` is the opposite call. Its name suggests the
filter-addressed bulk case §7 gates at `DESTRUCTIVE`, but
`POST /package-label-assignments/bulk` has no filter mode at all — the target
set is `packageLocators`, an explicit non-empty list, and the operation only
adds assignments. It is a loop over `assign_package_labels` that FOSSA runs
server-side, so it stays at `WRITE`. The filter-addressed label endpoint in
FOSSA is `PUT /v2/projects/labels`, and the tool covering it already refuses to
address its targets by filter.

The `apply_to_all_versions` flag on both assign tools does widen the blast
radius — one named package becomes all of its versions — but the set of
*packages* stays explicit and enumerated, and nothing is removed, so it is a
`WRITE` that names what it is doing rather than a destructive one.
"""

from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models.labels import (
    OrganizationLabelCreateInput,
    OrganizationLabelDeleteInput,
    OrganizationLabelReadInput,
    PackageLabelAssignInput,
    PackageLabelAssignmentListInput,
    PackageLabelBulkAssignInput,
    PackageLabelCreateInput,
    PackageLabelDeleteInput,
    PackageLabelListInput,
    PackageLabelReconcileInput,
    PackageLabelScope,
    PackageLabelUnassignInput,
)
from ..query import bool_to_str
from ..writes import WriteTier, require_tier

# --- package label definitions ------------------------------------------------


async def list_package_labels(ctx: Context) -> dict[str, Any]:
    """
    List every package label defined in the organization.

    Read-only. Package labels tag dependencies, not projects — use
    fossa_list_organization_labels for the labels that tag projects. The numeric
    `id` of each label here is what the assignment tools take as `label_id`.
    FOSSA answers 402 or 403 for organizations on the Free plan.
    """
    PackageLabelListInput()

    client: FossaClient = ctx.request_context.lifespan_context["client"]
    result = await client.request_json("GET", "/package-labels")

    return {"ok": True, "endpoint": "GET /package-labels", "data": result}


async def create_package_labels(
    ctx: Context,
    labels: list[str],
) -> dict[str, Any]:
    """
    Create one or more package labels in the organization.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This creates label definitions only; nothing is tagged until
    fossa_assign_package_labels or fossa_bulk_assign_package_label binds one to
    a package. FOSSA answers with the labels it created, including the ids the
    assignment tools need.
    """
    validated = PackageLabelCreateInput(labels=labels)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_create_package_labels")

    payload: dict[str, Any] = {"labels": validated.labels}
    result = await client.request_json("POST", "/package-labels", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /package-labels",
        "data": {"requested": validated.labels, "created": result},
    }


async def delete_package_labels(
    ctx: Context,
    label_ids: list[int],
) -> dict[str, Any]:
    """
    Permanently delete one or more package label definitions.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    Deleting a definition removes it everywhere it is assigned, across every
    package, project, and revision in the organization — the blast radius is
    much larger than the id list suggests. To remove a label from one package
    without destroying the label, use fossa_unassign_package_labels instead.
    """
    validated = PackageLabelDeleteInput(label_ids=label_ids)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_package_labels")

    payload: dict[str, Any] = {"ids": validated.label_ids}
    # 204 with an empty body: request_json would fail parsing it.
    body, _ = await client.request_text("DELETE", "/package-labels", json_body=payload)

    return {
        "ok": True,
        "endpoint": "DELETE /package-labels",
        "data": {"deleted": validated.label_ids, "response": body or None},
    }


# --- package label assignments ------------------------------------------------


async def list_package_label_assignments(
    ctx: Context,
    package_id: str | None = None,
    package_version: str | None = None,
    scope: PackageLabelScope | None = None,
    scope_id: str | None = None,
    include_package_wide_labels: bool | None = None,
    include_revision_scoped_labels: bool | None = None,
) -> dict[str, Any]:
    """
    List which package labels are assigned to which packages.

    Read-only. Every filter is optional; with none supplied FOSSA returns every
    assignment in the organization. `include_package_wide_labels` adds the
    labels assigned to all versions of the package when filtering by one
    version, and `include_revision_scoped_labels` adds revision-scoped labels
    under a project scope. The `id` of each assignment is what
    fossa_unassign_package_labels removes.
    """
    validated = PackageLabelAssignmentListInput(
        package_id=package_id,
        package_version=package_version,
        scope=scope,
        scope_id=scope_id,
        include_package_wide_labels=include_package_wide_labels,
        include_revision_scoped_labels=include_revision_scoped_labels,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    # These are `filters[name]`, not the `filters[name][]` array convention used
    # elsewhere: every one of them is a single scalar value.
    params: list[tuple[str, str]] = []
    if validated.package_id is not None:
        params.append(("filters[packageId]", validated.package_id))
    if validated.package_version is not None:
        params.append(("filters[packageVersion]", validated.package_version))
    if validated.scope is not None:
        params.append(("filters[scope]", validated.scope))
    if validated.scope_id is not None:
        params.append(("filters[scopeId]", validated.scope_id))
    if validated.include_package_wide_labels is not None:
        params.append(
            (
                "filters[shouldIncludePackageWideLabels]",
                bool_to_str(validated.include_package_wide_labels),
            )
        )
    if validated.include_revision_scoped_labels is not None:
        params.append(
            (
                "filters[shouldIncludeRevisionScopedLabels]",
                bool_to_str(validated.include_revision_scoped_labels),
            )
        )

    result = await client.request_json("GET", "/package-label-assignments", params=params)

    return {"ok": True, "endpoint": "GET /package-label-assignments", "data": result}


async def assign_package_labels(
    ctx: Context,
    package_id: str,
    scope: PackageLabelScope,
    label_ids: list[int],
    package_version: str | None = None,
    apply_to_all_versions: bool = False,
    scope_id: str | None = None,
) -> dict[str, Any]:
    """
    Assign one or more existing package labels to a single package.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Additive: existing assignments are left alone and duplicates are ignored.
    Exactly one of `package_version` and `apply_to_all_versions` must be given —
    FOSSA reads a missing version as "every version of this package", so the
    wide form has to be asked for by name. `scope_id` identifies the project or
    revision and must be omitted for `org` scope.
    """
    validated = PackageLabelAssignInput(
        package_id=package_id,
        scope=scope,
        label_ids=label_ids,
        package_version=package_version,
        apply_to_all_versions=apply_to_all_versions,
        scope_id=scope_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_assign_package_labels")

    payload: dict[str, Any] = {
        "packageId": validated.package_id,
        "scope": validated.scope,
        "labelIds": validated.label_ids,
    }
    # Omitted rather than sent empty: FOSSA's all-versions assignment is the one
    # with no version on it, and an absent key is the unambiguous spelling.
    if validated.package_version is not None:
        payload["packageVersion"] = validated.package_version
    if validated.scope_id is not None:
        payload["scopeId"] = validated.scope_id

    result = await client.request_json("POST", "/package-label-assignments", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /package-label-assignments",
        "data": {
            "applied": payload,
            "applies_to_all_versions": validated.apply_to_all_versions,
            "assignments": result,
        },
    }


async def bulk_assign_package_label(
    ctx: Context,
    label_id: int,
    package_locators: list[str],
    scope: PackageLabelScope,
    scope_id: str | None = None,
    apply_to_all_versions: bool = False,
) -> dict[str, Any]:
    """
    Assign one package label to many packages in a single call.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Additive, and every target is named: this endpoint has no "all packages
    matching a filter" mode, so the label reaches exactly the locators listed.
    Each locator must include its version, as in `npm+lodash$4.17.21`. With
    `apply_to_all_versions=true` the version part is ignored and the label is
    assigned to every version of each named package instead.
    """
    validated = PackageLabelBulkAssignInput(
        label_id=label_id,
        package_locators=package_locators,
        scope=scope,
        scope_id=scope_id,
        apply_to_all_versions=apply_to_all_versions,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_bulk_assign_package_label")

    payload: dict[str, Any] = {
        "packageLocators": validated.package_locators,
        "labelId": validated.label_id,
        "scope": validated.scope,
        # Sent explicitly rather than left to FOSSA's documented default, so the
        # version behavior of a call is visible in the request it made.
        "shouldUseSpecificVersion": not validated.apply_to_all_versions,
    }
    if validated.scope_id is not None:
        payload["scopeId"] = validated.scope_id

    result = await client.request_json("POST", "/package-label-assignments/bulk", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /package-label-assignments/bulk",
        "data": {"applied": payload, "assignments": result},
    }


async def set_package_label_assignments(
    ctx: Context,
    package_id: str,
    scope: PackageLabelScope,
    new_label_ids: dict[str, list[int]],
    scope_id: str | None = None,
) -> dict[str, Any]:
    """
    Replace a package's label assignments at one scope with an exact desired
    state.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    This is a reconcile, not an addition: FOSSA removes every existing
    assignment for this package and scope that `new_label_ids` does not mention.
    Read the current state with fossa_list_package_label_assignments first, or
    labels applied by someone else will disappear. `new_label_ids` maps a
    package version — or the literal `all` for assignments covering every
    version — to the list of label ids that should be assigned for it; an empty
    list clears that version. Use fossa_assign_package_labels when the intent is
    to add without removing.
    """
    validated = PackageLabelReconcileInput(
        package_id=package_id,
        scope=scope,
        new_label_ids=new_label_ids,
        scope_id=scope_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_set_package_label_assignments")

    payload: dict[str, Any] = {
        "packageId": validated.package_id,
        "scope": validated.scope,
        "newLabelIds": validated.new_label_ids,
    }
    if validated.scope_id is not None:
        payload["scopeId"] = validated.scope_id

    result = await client.request_json("PUT", "/package-label-assignments", json_body=payload)

    return {
        "ok": True,
        "endpoint": "PUT /package-label-assignments",
        "data": {"applied": payload, "assignments": result},
    }


async def unassign_package_labels(
    ctx: Context,
    assignment_ids: list[int],
) -> dict[str, Any]:
    """
    Remove specific package label assignments.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    `assignment_ids` are the `id` values from
    fossa_list_package_label_assignments — the id of the assignment, not of the
    label. The label definitions themselves are untouched; only these bindings
    go away.
    """
    validated = PackageLabelUnassignInput(assignment_ids=assignment_ids)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_unassign_package_labels")

    payload: dict[str, Any] = {"assignmentIds": validated.assignment_ids}
    # Documented as a 200 with no body, so it goes through request_text.
    body, _ = await client.request_text("DELETE", "/package-label-assignments", json_body=payload)

    return {
        "ok": True,
        "endpoint": "DELETE /package-label-assignments",
        "data": {"removed": validated.assignment_ids, "response": body or None},
    }


# --- organization labels ------------------------------------------------------


async def list_organization_labels(
    ctx: Context,
    label_id: int | None = None,
) -> dict[str, Any]:
    """
    List the organization's project labels, or read one by id.

    Read-only. These are the labels that tag projects — the ones
    fossa_apply_project_label applies and that fossa_list_projects and
    fossa_list_issues filter by. Package labels are a separate resource; see
    fossa_list_package_labels. With `label_id` the response includes the
    locators of the projects carrying that label.
    """
    validated = OrganizationLabelReadInput(label_id=label_id)

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    if validated.label_id is None:
        result = await client.request_json("GET", "/organizations/labels")
        endpoint = "GET /organizations/labels"
    else:
        result = await client.request_json("GET", f"/organizations/labels/{validated.label_id}")
        endpoint = "GET /organizations/labels/{id}"

    return {"ok": True, "endpoint": endpoint, "data": result}


async def create_organization_label(
    ctx: Context,
    label: str,
) -> dict[str, Any]:
    """
    Create a new organization label for tagging projects.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    The label is created unattached; fossa_apply_project_label puts it on
    projects. FOSSA restricts this endpoint to premium plans and answers 403
    otherwise. The response carries the new numeric id.
    """
    validated = OrganizationLabelCreateInput(label=label)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_create_organization_label")

    payload: dict[str, Any] = {"label": validated.label}
    result = await client.request_json("POST", "/organizations/labels", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /organizations/labels",
        "data": {"applied": payload, "created": result},
    }


async def delete_organization_label(
    ctx: Context,
    label_id: int,
) -> dict[str, Any]:
    """
    Permanently delete an organization label.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    The label is removed from every project carrying it. Check
    fossa_list_organization_labels with this id first: its response lists those
    projects, which is the only warning of how wide the change is. FOSSA
    restricts this endpoint to premium plans. Projects themselves are not
    affected beyond losing the tag.
    """
    validated = OrganizationLabelDeleteInput(label_id=label_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_organization_label")

    # 204 with an empty body.
    body, _ = await client.request_text("DELETE", f"/organizations/labels/{validated.label_id}")

    return {
        "ok": True,
        "endpoint": "DELETE /organizations/labels/{id}",
        "data": {"deleted": validated.label_id, "response": body or None},
    }
