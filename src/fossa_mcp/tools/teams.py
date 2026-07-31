"""Team, team group, role, and user tools for the FOSSA MCP server.

This is FOSSA's access-control surface: which people are in which team, what a
team can see, and what a role lets its holders do. Every write here is
`WriteTier.ADMIN` — the tier exists for exactly this domain — and needs
`FOSSA_ALLOW_WRITES=true` *and* `FOSSA_ALLOW_ADMIN=true`. Reads are ungated.

What FOSSA's API actually supports, which is what shapes these tools:

* **Everything is addressed by a numeric id.** Teams, team groups, roles, and
  users all have integer ids and no slug. Nothing in this domain takes a project
  locator as a path segment, so unlike the projects and revisions tools nothing
  here needs percent encoding. Locators appear only inside request and response
  bodies.
* **There are two generations of list endpoint.** `GET /v2/teams` and
  `GET /v2/users` are paginated with `page` / `pageSize` / `search`; the older
  `GET /teams` and `GET /users` are marked deprecated by FOSSA. The deprecated
  ones are still reachable — `GET /teams` is the only call that returns every
  team's membership in one response — but behind an explicit flag rather than as
  the default.
* **Membership is expressed as an action over a list**, not as a diff. `add`,
  `remove`, and `replace` share one endpoint per collection, so one tool covers
  the collection rather than three. `replace` sets the assignment to exactly
  what is named and removes everything else.
* **A team group is not a team.** It is a container that owns teams and has its
  own default role, under `/teams/groups`. Deleting one removes the grouping and
  leaves the teams themselves alone.
* **Roles are FOSSA's permission model.** A custom role is a scope plus a list
  of `(resourceType, action)` pairs drawn from `GET /roles/all-permissions`.
  Built-in roles cannot be edited or deleted, and neither can a role that is
  still assigned to somebody.

Two API-shape notes that affect the code rather than the caller:

* **Several deletes answer with no body.** `DELETE /teams/{id}`,
  `DELETE /teams/groups/{id}`, and `DELETE /roles/{id}` document a `200` with no
  content, and `DELETE /teams/groups/{id}/teams/{teamId}` a `204`.
  `client.request_json` calls `.json()` on every 2xx and so reports an empty body
  as an error; `_request_tolerating_empty_body` translates that back into a
  success, the same workaround `tools/issues.py` uses.
* **`DELETE /teams/{id}/release-groups` carries a JSON request body**, which is
  unusual for a delete and is why it does not go through `request_text` like the
  body-less ones.
"""

from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..errors import FossaApiError
from ..models.teams import (
    AddableTeamTarget,
    AddableTeamTargetsInput,
    AssignmentAction,
    RoleAction,
    RoleListInput,
    RoleManageInput,
    RolePermission,
    RoleScope,
    RoleSection,
    ServiceAccountCreateInput,
    SortOrder,
    TeamAssignmentInput,
    TeamAssignmentTarget,
    TeamCreateInput,
    TeamDeleteInput,
    TeamGroupAction,
    TeamGroupAssignmentInput,
    TeamGroupAssignmentTarget,
    TeamGroupManageInput,
    TeamGroupReadInput,
    TeamListInput,
    TeamProjectFilters,
    TeamReadInput,
    TeamSection,
    TeamUpdateInput,
    UserAssignment,
    UserListInput,
    UserSort,
    dump_users,
)
from ..writes import WriteTier, require_tier

# Section name -> the path it reads. `team` is served by the v2 endpoint, which
# is the only one carrying the member and project counts; the rest hang off the
# v1 team path.
_TEAM_SECTION_PATH: dict[str, str] = {
    "team": "/v2/teams/{id}",
    "members": "/teams/{id}/members",
    "projects": "/teams/{id}/projects",
    "release_groups": "/teams/{id}/release-groups",
}

_ADDABLE_TARGET_PATH: dict[str, str] = {
    "users": "/teams/{id}/members/addable",
    "projects_and_release_groups": "/teams/{id}/addable-projects-and-release-groups",
    "release_group_projects": "/teams/{id}/release-groups/{releaseGroupId}/addable-projects",
}

_ROLE_SECTION_PATH: dict[str, str] = {
    "roles": "/roles",
    "permissions": "/roles/all-permissions",
    "assignable": "/roles/assignable",
}


async def _request_tolerating_empty_body(
    client: FossaClient,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any] | list[Any] | None:
    """Call FOSSA where a successful response may carry no body.

    Every delete in this domain answers with an empty body — a `204` for
    `DELETE /teams/groups/{id}/teams/{teamId}` and a documented content-free
    `200` for the rest. `request_json` reports an unparseable body as a
    `FossaApiError` regardless of status, so translate that back into a success
    with no data when the status was in the 2xx range. Anything else propagates
    unchanged.
    """
    try:
        _, body = await client.request_json_with_status(method, path, json_body=json_body)
    except FossaApiError as exc:
        if 200 <= exc.status_code < 300:
            return None
        raise
    return body


def _page_params(page: int, page_size: int, search: str | None) -> list[tuple[str, str]]:
    """Build FOSSA's `page` / `pageSize` / `search` trio for a paginated read."""
    params: list[tuple[str, str]] = [("page", str(page)), ("pageSize", str(page_size))]
    if search is not None:
        params.append(("search", search))
    return params


# --- team reads --------------------------------------------------------------


async def list_teams(
    ctx: Context,
    page: int = 1,
    page_size: int = 10,
    search: str | None = None,
    include_all_with_members: bool = False,
) -> dict[str, Any]:
    """
    List the teams in the FOSSA organization.

    Read-only. Paginated: FOSSA caps `page_size` at 50, and `search` filters by
    team name. Each result carries the team's default role, its member count, and
    how many projects and release groups it owns.

    Setting `include_all_with_members` switches to FOSSA's older unpaginated
    endpoint, which returns every team **with its full member list inline**. That
    is the only call that answers "who is in which team" in one request, but
    FOSSA marks it deprecated and it accepts no paging or search, so it is not
    the default.
    """
    validated = TeamListInput(
        page=page,
        page_size=page_size,
        search=search,
        include_all_with_members=include_all_with_members,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    if validated.include_all_with_members:
        result = await client.request_json("GET", "/teams")
        return {"ok": True, "endpoint": "GET /teams", "data": result}

    params = _page_params(validated.page, validated.page_size, validated.search)
    result = await client.request_json("GET", "/v2/teams", params=params)

    return {"ok": True, "endpoint": "GET /v2/teams", "data": result}


async def get_team(
    ctx: Context,
    team_id: int,
    sections: list[TeamSection] | None = None,
    page: int = 1,
    page_size: int = 10,
    search: str | None = None,
    sort: SortOrder | None = None,
) -> dict[str, Any]:
    """
    Get a FOSSA team by its numeric id, and any of its member, project, and
    release group listings.

    Read-only. Sections: "team" is the team record and its counts, "members" is
    the users in it with their team role, "projects" is the project locators
    assigned to it, "release_groups" is the release groups assigned to it.
    Defaults to "team" alone. Each section costs one FOSSA request, so ask only
    for what is needed.

    `page`, `page_size`, and `search` apply to the three list sections and are
    shared across them; `sort` orders "projects" and "release_groups" by title
    and is rejected if neither is requested.
    """
    validated = TeamReadInput(
        team_id=team_id,
        sections=sections or ["team"],
        page=page,
        page_size=page_size,
        search=search,
        sort=sort,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    data: dict[str, Any] = {}
    endpoints: list[str] = []
    for section in validated.sections:
        template = _TEAM_SECTION_PATH[section]
        path = template.format(id=validated.team_id)

        params: list[tuple[str, str]] | None = None
        if section != "team":
            params = _page_params(validated.page, validated.page_size, validated.search)
            if validated.sort is not None and section in ("projects", "release_groups"):
                params.append(("sort", validated.sort))

        data[section] = await client.request_json("GET", path, params=params)
        endpoints.append(f"GET {template}")

    return {"ok": True, "endpoint": ", ".join(endpoints), "data": data}


async def list_addable_team_targets(
    ctx: Context,
    team_id: int,
    target: AddableTeamTarget,
    release_group_id: int | None = None,
    page: int = 1,
    page_size: int = 10,
    search: str | None = None,
) -> dict[str, Any]:
    """
    List what could still be added to a FOSSA team: the users, projects, and
    release groups that are not in it yet.

    Read-only. Targets: "users" is the organization's users who are not members,
    "projects_and_release_groups" is everything assignable to the team with a
    `type` discriminator on each entry, and "release_group_projects" narrows that
    to the projects inside one release group — FOSSA requires every project of a
    release group to be on the team before the release group itself can be added,
    so that target answers "what is still missing". It takes `release_group_id`
    and, unlike the other two, returns the whole set with no paging.
    """
    validated = AddableTeamTargetsInput(
        team_id=team_id,
        target=target,
        release_group_id=release_group_id,
        page=page,
        page_size=page_size,
        search=search,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    template = _ADDABLE_TARGET_PATH[validated.target]
    if validated.target == "release_group_projects":
        path = template.format(id=validated.team_id, releaseGroupId=validated.release_group_id)
        params: list[tuple[str, str]] | None = None
    else:
        path = template.format(id=validated.team_id)
        params = _page_params(validated.page, validated.page_size, validated.search)

    result = await client.request_json("GET", path, params=params)

    return {"ok": True, "endpoint": f"GET {template}", "data": result}


# --- team writes -------------------------------------------------------------


async def create_team(
    ctx: Context,
    name: str,
    default_role_id: int,
    auto_add_users: bool = False,
    unique_identifier: str | None = None,
    team_group_ids: list[int] | None = None,
) -> dict[str, Any]:
    """
    Create a FOSSA team.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    `default_role_id` is the team role new members receive; list the available
    ids with fossa_list_roles. `auto_add_users` puts every new organization user
    into this team automatically, which widens access without another call, so it
    defaults to false. `unique_identifier` is an external key FOSSA stores for
    SCIM and SSO mapping. `team_group_ids` places the new team into existing team
    groups and requires the team groups feature to be enabled.
    """
    validated = TeamCreateInput(
        name=name,
        default_role_id=default_role_id,
        auto_add_users=auto_add_users,
        unique_identifier=unique_identifier,
        team_group_ids=team_group_ids,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_create_team")

    payload: dict[str, Any] = {
        "name": validated.name,
        "defaultRoleId": validated.default_role_id,
        "autoAddUsers": validated.auto_add_users,
    }
    if validated.unique_identifier is not None:
        payload["uniqueIdentifier"] = validated.unique_identifier
    if validated.team_group_ids is not None:
        payload["teamGroupIds"] = validated.team_group_ids

    result = await client.request_json("POST", "/teams", json_body=payload)

    return {"ok": True, "endpoint": "POST /teams", "data": {"applied": payload, "team": result}}


async def update_team(
    ctx: Context,
    team_id: int,
    name: str | None = None,
    default_role_id: int | None = None,
    auto_add_users: bool | None = None,
    unique_identifier: str | None = None,
    clear_unique_identifier: bool = False,
) -> dict[str, Any]:
    """
    Update a FOSSA team's name, default role, auto-add setting, or external
    identifier.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    Only the fields passed are sent; anything omitted is left as FOSSA has it.
    Because an omitted argument and an explicit null look the same in a tool call,
    unsetting the nullable `uniqueIdentifier` is a separate switch:
    `clear_unique_identifier` sends null for it. Changing `default_role_id`
    affects members added afterwards, not the roles already assigned — use
    fossa_update_team_assignments with action "replace" to re-role existing
    members. This tool does not change membership.
    """
    validated = TeamUpdateInput(
        team_id=team_id,
        name=name,
        default_role_id=default_role_id,
        auto_add_users=auto_add_users,
        unique_identifier=unique_identifier,
        clear_unique_identifier=clear_unique_identifier,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_update_team")

    payload: dict[str, Any] = {}
    if validated.name is not None:
        payload["name"] = validated.name
    if validated.default_role_id is not None:
        payload["defaultRoleId"] = validated.default_role_id
    if validated.auto_add_users is not None:
        payload["autoAddUsers"] = validated.auto_add_users
    if validated.unique_identifier is not None:
        payload["uniqueIdentifier"] = validated.unique_identifier
    if validated.clear_unique_identifier:
        payload["uniqueIdentifier"] = None

    result = await client.request_json("PUT", f"/teams/{validated.team_id}", json_body=payload)

    return {
        "ok": True,
        "endpoint": "PUT /teams/{id}",
        "data": {"applied": payload, "team": result},
    }


async def delete_team(
    ctx: Context,
    team_id: int,
) -> dict[str, Any]:
    """
    Delete a FOSSA team.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    This removes the team from every team group it belongs to and drops all of
    its associations: its members lose the access the team granted them, and its
    projects and release groups lose that team assignment. The users, projects,
    and release groups themselves survive; the team does not, and FOSSA offers no
    undo.
    """
    validated = TeamDeleteInput(team_id=team_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_delete_team")

    await _request_tolerating_empty_body(client, "DELETE", f"/teams/{validated.team_id}")

    return {
        "ok": True,
        "endpoint": "DELETE /teams/{id}",
        "data": {"team_id": validated.team_id, "deleted": True},
    }


async def update_team_assignments(
    ctx: Context,
    team_id: int,
    target: TeamAssignmentTarget,
    action: AssignmentAction,
    users: list[dict[str, int]] | None = None,
    projects: list[str] | None = None,
    all_projects: bool = False,
    project_filters: dict[str, Any] | None = None,
    release_group_ids: list[int] | None = None,
) -> dict[str, Any]:
    """
    Change what is assigned to a FOSSA team: its members, its projects, or its
    release groups.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    `target` picks the collection and decides which of the remaining arguments
    apply; passing one that belongs to a different target is rejected before any
    request is made.

    * "users" takes `users`, a list of objects with the keys `id` and, for the
      add and replace actions, `roleId`.
    * "projects" takes exactly one of `projects` (a list of project locators),
      `all_projects`, or `project_filters` (an object with any of `title`,
      `labels`, `type`, `lastRevisionWithin`, `isPublic`).
    * "release_groups" takes `release_group_ids`, and supports only add and
      remove. Every project in a release group must already be on the team before
      the release group can be added.

    `action` "replace" sets the collection to exactly what is named and removes
    everything else, so replacing the user list with one entry leaves a team of
    one. **`all_projects` and `project_filters` address an unbounded set**:
    FOSSA resolves them server-side, so the number of projects affected is not
    known before the call. `all_projects` with action "add" hands the team every
    project in the organization; with "remove" it strips the team of all of them.
    """
    validated = TeamAssignmentInput(
        team_id=team_id,
        target=target,
        action=action,
        users=[UserAssignment.model_validate(user) for user in users]
        if users is not None
        else None,
        projects=projects,
        all_projects=all_projects,
        project_filters=(
            TeamProjectFilters.model_validate(project_filters)
            if project_filters is not None
            else None
        ),
        release_group_ids=release_group_ids,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_update_team_assignments")

    if validated.target == "users":
        payload: dict[str, Any] = {
            "action": validated.action,
            "users": dump_users(validated.users or []),
        }
        endpoint = "PUT /teams/{id}/users"
        result = await client.request_json(
            "PUT", f"/teams/{validated.team_id}/users", json_body=payload
        )

    elif validated.target == "projects":
        payload = {"action": validated.action}
        if validated.all_projects:
            payload["projects"] = "all"
        elif validated.projects is not None:
            payload["projects"] = validated.projects
        else:
            filters = validated.project_filters
            payload["filters"] = filters.model_dump(exclude_none=True) if filters else {}
        endpoint = "PUT /teams/{id}/projects"
        result = await client.request_json(
            "PUT", f"/teams/{validated.team_id}/projects", json_body=payload
        )

    else:
        payload = {"ids": validated.release_group_ids or []}
        method = "POST" if validated.action == "add" else "DELETE"
        endpoint = f"{method} /teams/{{id}}/release-groups"
        # The remove side is the one delete in this domain that carries a
        # request body, so it cannot go through the body-less text path.
        body = await _request_tolerating_empty_body(
            client, method, f"/teams/{validated.team_id}/release-groups", json_body=payload
        )
        result = body if body is not None else {}

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {
            "team_id": validated.team_id,
            "target": validated.target,
            "action": validated.action,
            "applied": payload,
            "team": result,
        },
    }


# --- team groups -------------------------------------------------------------


async def get_team_groups(
    ctx: Context,
    team_group_id: int | None = None,
) -> dict[str, Any]:
    """
    Get FOSSA team groups — every one in the organization, or a single group by
    its numeric id.

    Read-only. A team group is a container that owns teams and carries its own
    default role; it is not itself a team. Both responses list the group's teams
    with their project counts and its members with their role ids; asking for one
    group by id additionally resolves each member's username and email. Neither
    endpoint is paginated.
    """
    validated = TeamGroupReadInput(team_group_id=team_group_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    if validated.team_group_id is None:
        result = await client.request_json("GET", "/teams/groups")
        return {"ok": True, "endpoint": "GET /teams/groups", "data": result}

    result = await client.request_json("GET", f"/teams/groups/{validated.team_group_id}")

    return {"ok": True, "endpoint": "GET /teams/groups/{id}", "data": result}


async def manage_team_group(
    ctx: Context,
    action: TeamGroupAction,
    team_group_id: int | None = None,
    name: str | None = None,
    default_role_id: int | None = None,
) -> dict[str, Any]:
    """
    Create, rename, or delete a FOSSA team group.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    A team group has only two editable fields, so one tool covers all three
    actions rather than three near-identical ones. "create" needs `name` and
    `default_role_id`; "update" needs `team_group_id` plus both of them, because
    FOSSA's update endpoint replaces both rather than patching either; "delete"
    needs only `team_group_id`.

    Deleting a team group removes its team associations and its own membership
    list. **The teams inside it are not deleted** and keep their own members,
    projects, and release groups. FOSSA offers no undo. To change which teams are
    in a group, use fossa_update_team_group_assignments.
    """
    validated = TeamGroupManageInput(
        action=action,
        team_group_id=team_group_id,
        name=name,
        default_role_id=default_role_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_manage_team_group")

    if validated.action == "delete":
        await _request_tolerating_empty_body(
            client, "DELETE", f"/teams/groups/{validated.team_group_id}"
        )
        return {
            "ok": True,
            "endpoint": "DELETE /teams/groups/{id}",
            "data": {"team_group_id": validated.team_group_id, "deleted": True},
        }

    payload: dict[str, Any] = {"name": validated.name, "defaultRoleId": validated.default_role_id}

    if validated.action == "create":
        result = await client.request_json("POST", "/teams/groups", json_body=payload)
        endpoint = "POST /teams/groups"
    else:
        result = await client.request_json(
            "PUT", f"/teams/groups/{validated.team_group_id}", json_body=payload
        )
        endpoint = "PUT /teams/groups/{id}"

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {"applied": payload, "team_group": result},
    }


async def update_team_group_assignments(
    ctx: Context,
    team_group_id: int,
    target: TeamGroupAssignmentTarget,
    action: AssignmentAction,
    team_ids: list[int] | None = None,
    users: list[dict[str, int]] | None = None,
) -> dict[str, Any]:
    """
    Change what is assigned to a FOSSA team group: the teams it contains, or its
    members.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    * "teams" takes `team_ids` and supports add and remove. FOSSA removes teams
      one at a time, so a remove naming several teams issues one request per
      team and is **not atomic**: an error partway through leaves the earlier
      removals applied. The ids that succeeded are reported back.
    * "users" takes `users`, a list of objects with the keys `id` and, for the
      add and replace actions, `roleId`, and supports all three actions.

    Removing a team from a group does not delete the team. Action "replace" on
    users sets the group's membership to exactly what is named and removes
    everyone else.
    """
    validated = TeamGroupAssignmentInput(
        team_group_id=team_group_id,
        target=target,
        action=action,
        team_ids=team_ids,
        users=[UserAssignment.model_validate(user) for user in users]
        if users is not None
        else None,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_update_team_group_assignments")

    if validated.target == "users":
        payload: dict[str, Any] = {
            "action": validated.action,
            "users": dump_users(validated.users or []),
        }
        result = await client.request_json(
            "PUT", f"/teams/groups/{validated.team_group_id}/users", json_body=payload
        )
        return {
            "ok": True,
            "endpoint": "PUT /teams/groups/{id}/users",
            "data": {
                "team_group_id": validated.team_group_id,
                "action": validated.action,
                "applied": payload,
                "team_group": result,
            },
        }

    target_ids = validated.team_ids or []

    if validated.action == "add":
        payload = {"teamIds": target_ids}
        result = await client.request_json(
            "POST", f"/teams/groups/{validated.team_group_id}/teams", json_body=payload
        )
        return {
            "ok": True,
            "endpoint": "POST /teams/groups/{id}/teams",
            "data": {
                "team_group_id": validated.team_group_id,
                "action": "add",
                "applied": payload,
                "team_group": result,
            },
        }

    removed: list[int] = []
    for team_id in target_ids:
        await _request_tolerating_empty_body(
            client, "DELETE", f"/teams/groups/{validated.team_group_id}/teams/{team_id}"
        )
        removed.append(team_id)

    return {
        "ok": True,
        "endpoint": "DELETE /teams/groups/{id}/teams/{teamId}",
        "data": {
            "team_group_id": validated.team_group_id,
            "action": "remove",
            "removed_team_ids": removed,
        },
    }


# --- roles -------------------------------------------------------------------


async def list_roles(
    ctx: Context,
    sections: list[RoleSection] | None = None,
) -> dict[str, Any]:
    """
    List the roles in the FOSSA organization, the permission catalog they are
    built from, and which of them the calling token may hand out.

    Read-only. Sections: "roles" is every role with its scope and permission
    list, "permissions" is the catalog of `(resourceType, action)` pairs a custom
    role can be assembled from, "assignable" is the subset of role ids this API
    token is allowed to assign — FOSSA only lets a caller grant permissions it
    already holds, so a role missing from "assignable" will be refused when used
    in a team or service account write. Defaults to "roles" alone. Each section
    costs one FOSSA request. None of these endpoints is paginated.
    """
    validated = RoleListInput(sections=sections or ["roles"])

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    data: dict[str, Any] = {}
    endpoints: list[str] = []
    for section in validated.sections:
        path = _ROLE_SECTION_PATH[section]
        data[section] = await client.request_json("GET", path)
        endpoints.append(f"GET {path}")

    return {"ok": True, "endpoint": ", ".join(endpoints), "data": data}


async def manage_role(
    ctx: Context,
    action: RoleAction,
    role_id: int | None = None,
    scope: RoleScope | None = None,
    name: str | None = None,
    description: str | None = None,
    permissions: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """
    Create, update, or delete a custom FOSSA role.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    A role is a scope plus a permission list, so the three actions share one
    shape and one tool. "create" needs `scope` ("organization" or "team"),
    `name`, and `description`; "update" needs `role_id` and at least one of
    `name`, `description`, or `permissions`; "delete" needs only `role_id`.

    Each entry in `permissions` is an object with the keys `resourceType` and
    `action`, both drawn from fossa_list_roles section "permissions" — FOSSA
    rejects a pair that is not in that catalog. **Passing `permissions` on an
    update replaces the role's entire permission list**, so send the full set,
    not a delta; omit it to leave the permissions alone. A role's scope cannot be
    changed after creation.

    Only custom roles can be edited or deleted. FOSSA refuses to delete a
    built-in role, and refuses to delete any role still assigned to a user, so a
    delete cannot silently strip someone's access.
    """
    validated = RoleManageInput(
        action=action,
        role_id=role_id,
        scope=scope,
        name=name,
        description=description,
        permissions=(
            [RolePermission.model_validate(permission) for permission in permissions]
            if permissions is not None
            else None
        ),
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_manage_role")

    if validated.action == "delete":
        await _request_tolerating_empty_body(client, "DELETE", f"/roles/{validated.role_id}")
        return {
            "ok": True,
            "endpoint": "DELETE /roles/{id}",
            "data": {"role_id": validated.role_id, "deleted": True},
        }

    payload: dict[str, Any] = {}
    if validated.scope is not None:
        payload["scope"] = validated.scope
    if validated.name is not None:
        payload["name"] = validated.name
    if validated.description is not None:
        payload["description"] = validated.description
    if validated.permissions is not None:
        payload["permissions"] = [permission.model_dump() for permission in validated.permissions]

    if validated.action == "create":
        result = await client.request_json("POST", "/roles", json_body=payload)
        endpoint = "POST /roles"
    else:
        result = await client.request_json("PUT", f"/roles/{validated.role_id}", json_body=payload)
        endpoint = "PUT /roles/{id}"

    return {"ok": True, "endpoint": endpoint, "data": {"applied": payload, "role": result}}


# --- users -------------------------------------------------------------------


async def list_users(
    ctx: Context,
    user_id: int | None = None,
    page: int = 1,
    page_size: int = 10,
    search: str | None = None,
    sort: UserSort | None = None,
    include_all: bool = False,
) -> dict[str, Any]:
    """
    List the users in the FOSSA organization, or fetch one user by numeric id.

    Read-only. The default is FOSSA's paginated user list: `page_size` is capped
    at 50, `search` matches username, email, or full name, and `sort` takes a
    `field_asc` / `field_desc` pair. Passing `user_id` fetches that single user
    instead, with their organization role, team memberships, and API token
    metadata — token names and ids, never token values.

    Setting `include_all` switches to FOSSA's older unpaginated endpoint, which
    returns every user in one response. FOSSA marks it deprecated and it supports
    neither search nor sort, so it is not the default.

    Service accounts appear in these listings alongside people, flagged by
    `isServiceAccount`.
    """
    validated = UserListInput(
        user_id=user_id,
        page=page,
        page_size=page_size,
        search=search,
        sort=sort,
        include_all=include_all,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    if validated.user_id is not None:
        result = await client.request_json("GET", f"/users/{validated.user_id}")
        return {"ok": True, "endpoint": "GET /users/{id}", "data": result}

    if validated.include_all:
        # The deprecated endpoint names its page size `count`, not `pageSize`.
        params: list[tuple[str, str]] = [
            ("page", str(validated.page)),
            ("count", str(validated.page_size)),
        ]
        result = await client.request_json("GET", "/users", params=params)
        return {"ok": True, "endpoint": "GET /users", "data": result}

    params = _page_params(validated.page, validated.page_size, validated.search)
    if validated.sort is not None:
        params.append(("sort", validated.sort))

    result = await client.request_json("GET", "/v2/users", params=params)

    return {"ok": True, "endpoint": "GET /v2/users", "data": result}


async def create_service_account(
    ctx: Context,
    username: str,
    email: str | None = None,
    full_name: str | None = None,
    org_role_id: int | None = None,
    team_id: int | None = None,
    team_role_id: int | None = None,
    has_push_only_api_token: bool = False,
    has_full_api_token: bool = False,
) -> dict[str, Any]:
    """
    Create a FOSSA service account, optionally with API tokens.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    A service account is a non-human user that has to be able to do something, so
    FOSSA requires an organization role (`org_role_id`), a team assignment
    (`team_id` with `team_role_id`), or both. List the available role ids with
    fossa_list_roles.

    **Requesting a token returns its secret value in the response, once.** FOSSA
    does not show it again, and a full-access token carries the same authority as
    the role it is attached to. Leave both token switches off unless the token is
    actually needed, and treat the result as a credential: it will appear in this
    conversation's transcript and in any log that records tool output.
    """
    validated = ServiceAccountCreateInput(
        username=username,
        email=email,
        full_name=full_name,
        org_role_id=org_role_id,
        team_id=team_id,
        team_role_id=team_role_id,
        has_push_only_api_token=has_push_only_api_token,
        has_full_api_token=has_full_api_token,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_create_service_account")

    payload: dict[str, Any] = {
        "username": validated.username,
        "hasPushOnlyApiToken": validated.has_push_only_api_token,
        "hasFullApiToken": validated.has_full_api_token,
    }
    if validated.email is not None:
        payload["email"] = validated.email
    if validated.full_name is not None:
        payload["fullName"] = validated.full_name
    if validated.org_role_id is not None:
        payload["orgRoleId"] = validated.org_role_id
    if validated.team_id is not None:
        payload["team"] = {"id": validated.team_id, "roleId": validated.team_role_id}

    result = await client.request_json("POST", "/users/service-accounts", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /users/service-accounts",
        "data": {
            "applied": payload,
            "returned_api_token": (
                validated.has_full_api_token or validated.has_push_only_api_token
            ),
            "service_account": result,
        },
    }
