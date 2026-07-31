"""Endpoint contract tests for the team, team group, role, and user tools.

Covers the HTTP shape of every operation in FOSSA's access-control surface: the
paths the sectioned reads fan out to, the exact query pairs each paginated read
receives, the exact JSON body each write sends, and the refusal path that must
fire before any request leaves the process when a tool's write tier is off.

Every write in this domain is `WriteTier.ADMIN`, so each one has two refusal
cases rather than one: writes off entirely, and writes on with admin off. Both
must make zero HTTP calls.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import teams

BASE = "https://app.fossa.com/api"
TEAM_ID = 7
TEAM_GROUP_ID = 3
ROLE_ID = 11
USER_ID = 123
RELEASE_GROUP_ID = 42

TEAM_BODY = {"id": TEAM_ID, "name": "Engineering", "defaultRoleId": 2, "organizationId": 1000}
PAGE_BODY = {"results": [], "page": 1, "pageSize": 10, "totalCount": 0}

DEFAULT_PAGE_PAIRS = [("page", "1"), ("pageSize", "10")]


@pytest.fixture
def writable_settings() -> Settings:
    """Writes on, admin off — the tier that must still refuse everything here."""
    return Settings(fossa_api_token="test-token", fossa_allow_writes=True, _env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def admin_settings() -> Settings:
    return Settings(
        fossa_api_token="test-token",
        fossa_allow_writes=True,
        fossa_allow_admin=True,
        _env_file=None,  # type: ignore[call-arg]
    )


def _query_pairs(request: httpx.Request) -> list[tuple[str, str]]:
    return httpx.QueryParams(request.url.query.decode()).multi_items()


def _body(request: httpx.Request) -> dict:
    return json.loads(request.content)


# --- team reads --------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_teams_uses_the_paginated_v2_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/teams").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )

    client = FossaClient(settings)
    result = await teams.list_teams(make_context(client, settings), page=2, page_size=50)
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert route.calls.last.request.method == "GET"
    assert _query_pairs(route.calls.last.request) == [("page", "2"), ("pageSize", "50")]
    assert result["endpoint"] == "GET /v2/teams"
    assert result["data"] == PAGE_BODY


@pytest.mark.asyncio
async def test_list_teams_sends_search_when_given(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/teams").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )

    client = FossaClient(settings)
    await teams.list_teams(make_context(client, settings), search="eng")
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [*DEFAULT_PAGE_PAIRS, ("search", "eng")]


@pytest.mark.asyncio
async def test_list_teams_can_use_the_deprecated_unpaginated_endpoint(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/teams").mock(return_value=httpx.Response(200, json=[TEAM_BODY]))

    client = FossaClient(settings)
    result = await teams.list_teams(make_context(client, settings), include_all_with_members=True)
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /teams"
    assert result["data"] == [TEAM_BODY]


@pytest.mark.asyncio
async def test_list_teams_rejects_paging_arguments_with_the_unpaginated_endpoint(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await teams.list_teams(
            make_context(client, settings), search="eng", include_all_with_members=True
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_get_team_defaults_to_the_team_record_alone(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/teams/{TEAM_ID}").mock(
        return_value=httpx.Response(200, json=TEAM_BODY)
    )

    client = FossaClient(settings)
    result = await teams.get_team(make_context(client, settings), TEAM_ID)
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /v2/teams/{id}"
    assert result["data"] == {"team": TEAM_BODY}


@pytest.mark.asyncio
async def test_get_team_sections_are_deduped_ordered_and_parameterized(
    settings, respx_mock, make_context
):
    team = respx_mock.get(f"{BASE}/v2/teams/{TEAM_ID}").mock(
        return_value=httpx.Response(200, json=TEAM_BODY)
    )
    members = respx_mock.get(f"{BASE}/teams/{TEAM_ID}/members").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )
    projects = respx_mock.get(f"{BASE}/teams/{TEAM_ID}/projects").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )
    release_groups = respx_mock.get(f"{BASE}/teams/{TEAM_ID}/release-groups").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )

    client = FossaClient(settings)
    result = await teams.get_team(
        make_context(client, settings),
        TEAM_ID,
        sections=["release_groups", "members", "team", "members"],
        search="widget",
        sort="desc",
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 3
    assert team.called and members.called and release_groups.called
    assert not projects.called

    assert _query_pairs(members.calls.last.request) == [
        *DEFAULT_PAGE_PAIRS,
        ("search", "widget"),
    ]
    assert _query_pairs(release_groups.calls.last.request) == [
        *DEFAULT_PAGE_PAIRS,
        ("search", "widget"),
        ("sort", "desc"),
    ]
    assert result["endpoint"] == (
        "GET /v2/teams/{id}, GET /teams/{id}/members, GET /teams/{id}/release-groups"
    )
    assert list(result["data"]) == ["team", "members", "release_groups"]


@pytest.mark.asyncio
async def test_get_team_rejects_sort_without_a_sortable_section(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await teams.get_team(
            make_context(client, settings), TEAM_ID, sections=["members"], sort="asc"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_list_addable_team_targets_users(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/teams/{TEAM_ID}/members/addable").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )

    client = FossaClient(settings)
    result = await teams.list_addable_team_targets(
        make_context(client, settings), TEAM_ID, "users", search="dana"
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [*DEFAULT_PAGE_PAIRS, ("search", "dana")]
    assert result["endpoint"] == "GET /teams/{id}/members/addable"


@pytest.mark.asyncio
async def test_list_addable_team_targets_projects_and_release_groups(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/teams/{TEAM_ID}/addable-projects-and-release-groups").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )

    client = FossaClient(settings)
    result = await teams.list_addable_team_targets(
        make_context(client, settings), TEAM_ID, "projects_and_release_groups"
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == DEFAULT_PAGE_PAIRS
    assert result["endpoint"] == "GET /teams/{id}/addable-projects-and-release-groups"


@pytest.mark.asyncio
async def test_list_addable_team_targets_release_group_projects_sends_no_query(
    settings, respx_mock, make_context
):
    route = respx_mock.get(
        f"{BASE}/teams/{TEAM_ID}/release-groups/{RELEASE_GROUP_ID}/addable-projects"
    ).mock(return_value=httpx.Response(200, json={"results": []}))

    client = FossaClient(settings)
    result = await teams.list_addable_team_targets(
        make_context(client, settings),
        TEAM_ID,
        "release_group_projects",
        release_group_id=RELEASE_GROUP_ID,
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == (
        "GET /teams/{id}/release-groups/{releaseGroupId}/addable-projects"
    )


@pytest.mark.asyncio
async def test_list_addable_team_targets_requires_a_release_group_id(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await teams.list_addable_team_targets(
            make_context(client, settings), TEAM_ID, "release_group_projects"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- team writes -------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_team_sends_the_documented_body(admin_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/teams").mock(return_value=httpx.Response(200, json=TEAM_BODY))

    client = FossaClient(admin_settings)
    result = await teams.create_team(
        make_context(client, admin_settings),
        name="Engineering",
        default_role_id=2,
        auto_add_users=True,
        unique_identifier="eng-001",
        team_group_ids=[3, 4],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "name": "Engineering",
        "defaultRoleId": 2,
        "autoAddUsers": True,
        "uniqueIdentifier": "eng-001",
        "teamGroupIds": [3, 4],
    }
    assert result["endpoint"] == "POST /teams"


@pytest.mark.asyncio
async def test_update_team_sends_only_the_named_fields(admin_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}").mock(
        return_value=httpx.Response(200, json=TEAM_BODY)
    )

    client = FossaClient(admin_settings)
    await teams.update_team(
        make_context(client, admin_settings), TEAM_ID, name="Platform", auto_add_users=False
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"name": "Platform", "autoAddUsers": False}


@pytest.mark.asyncio
async def test_update_team_clears_the_unique_identifier_with_an_explicit_null(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}").mock(
        return_value=httpx.Response(200, json=TEAM_BODY)
    )

    client = FossaClient(admin_settings)
    await teams.update_team(
        make_context(client, admin_settings), TEAM_ID, clear_unique_identifier=True
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"uniqueIdentifier": None}


@pytest.mark.asyncio
async def test_update_team_rejects_setting_and_clearing_the_same_field(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.update_team(
            make_context(client, admin_settings),
            TEAM_ID,
            unique_identifier="eng-001",
            clear_unique_identifier=True,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_team_tolerates_an_empty_success_body(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/teams/{TEAM_ID}").mock(return_value=httpx.Response(200))

    client = FossaClient(admin_settings)
    result = await teams.delete_team(make_context(client, admin_settings), TEAM_ID)
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "DELETE /teams/{id}"
    assert result["data"] == {"team_id": TEAM_ID, "deleted": True}


@pytest.mark.asyncio
async def test_update_team_assignments_users(admin_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}/users").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "users": []})
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_assignments(
        make_context(client, admin_settings),
        TEAM_ID,
        "users",
        "add",
        users=[{"id": USER_ID, "roleId": 2}],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "action": "add",
        "users": [{"id": USER_ID, "roleId": 2}],
    }
    assert result["endpoint"] == "PUT /teams/{id}/users"


@pytest.mark.asyncio
async def test_update_team_assignments_users_omits_role_id_on_remove(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}/users").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "users": []})
    )

    client = FossaClient(admin_settings)
    await teams.update_team_assignments(
        make_context(client, admin_settings), TEAM_ID, "users", "remove", users=[{"id": USER_ID}]
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"action": "remove", "users": [{"id": USER_ID}]}


@pytest.mark.asyncio
async def test_update_team_assignments_users_requires_a_role_id_to_add(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.update_team_assignments(
            make_context(client, admin_settings),
            TEAM_ID,
            "users",
            "add",
            users=[{"id": USER_ID}],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_team_assignments_projects_by_locator(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}/projects").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "projects": []})
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_assignments(
        make_context(client, admin_settings),
        TEAM_ID,
        "projects",
        "add",
        projects=["git+github.com/acme/widget"],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "action": "add",
        "projects": ["git+github.com/acme/widget"],
    }
    assert result["endpoint"] == "PUT /teams/{id}/projects"


@pytest.mark.asyncio
async def test_update_team_assignments_projects_all_sends_the_literal_string(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}/projects").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "projects": []})
    )

    client = FossaClient(admin_settings)
    await teams.update_team_assignments(
        make_context(client, admin_settings), TEAM_ID, "projects", "add", all_projects=True
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"action": "add", "projects": "all"}


@pytest.mark.asyncio
async def test_update_team_assignments_projects_by_filter(admin_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/teams/{TEAM_ID}/projects").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "projects": []})
    )

    client = FossaClient(admin_settings)
    await teams.update_team_assignments(
        make_context(client, admin_settings),
        TEAM_ID,
        "projects",
        "replace",
        project_filters={"title": "frontend", "labels": [1, 2]},
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "action": "replace",
        "filters": {"title": "frontend", "labels": [1, 2]},
    }


@pytest.mark.asyncio
async def test_update_team_assignments_projects_needs_exactly_one_selector(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.update_team_assignments(
            make_context(client, admin_settings),
            TEAM_ID,
            "projects",
            "add",
            projects=["git+github.com/acme/widget"],
            all_projects=True,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_team_assignments_rejects_fields_from_another_target(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.update_team_assignments(
            make_context(client, admin_settings),
            TEAM_ID,
            "users",
            "add",
            users=[{"id": USER_ID, "roleId": 2}],
            release_group_ids=[RELEASE_GROUP_ID],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_team_assignments_release_groups_add_posts(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/teams/{TEAM_ID}/release-groups").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "releaseGroups": [RELEASE_GROUP_ID]})
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_assignments(
        make_context(client, admin_settings),
        TEAM_ID,
        "release_groups",
        "add",
        release_group_ids=[RELEASE_GROUP_ID],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"ids": [RELEASE_GROUP_ID]}
    assert result["endpoint"] == "POST /teams/{id}/release-groups"


@pytest.mark.asyncio
async def test_update_team_assignments_release_groups_remove_deletes_with_a_body(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/teams/{TEAM_ID}/release-groups").mock(
        return_value=httpx.Response(200, json={"id": TEAM_ID, "releaseGroups": []})
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_assignments(
        make_context(client, admin_settings),
        TEAM_ID,
        "release_groups",
        "remove",
        release_group_ids=[RELEASE_GROUP_ID],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"ids": [RELEASE_GROUP_ID]}
    assert result["endpoint"] == "DELETE /teams/{id}/release-groups"


@pytest.mark.asyncio
async def test_update_team_assignments_release_groups_rejects_replace(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.update_team_assignments(
            make_context(client, admin_settings),
            TEAM_ID,
            "release_groups",
            "replace",
            release_group_ids=[RELEASE_GROUP_ID],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- team groups -------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_team_groups_lists_them_all_without_an_id(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/teams/groups").mock(
        return_value=httpx.Response(200, json=[{"id": TEAM_GROUP_ID, "name": "Platform"}])
    )

    client = FossaClient(settings)
    result = await teams.get_team_groups(make_context(client, settings))
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /teams/groups"


@pytest.mark.asyncio
async def test_get_team_groups_fetches_one_by_id(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/teams/groups/{TEAM_GROUP_ID}").mock(
        return_value=httpx.Response(200, json={"id": TEAM_GROUP_ID, "name": "Platform"})
    )

    client = FossaClient(settings)
    result = await teams.get_team_groups(make_context(client, settings), TEAM_GROUP_ID)
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /teams/groups/{id}"


@pytest.mark.asyncio
async def test_manage_team_group_create(admin_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/teams/groups").mock(
        return_value=httpx.Response(200, json={"id": TEAM_GROUP_ID})
    )

    client = FossaClient(admin_settings)
    result = await teams.manage_team_group(
        make_context(client, admin_settings), "create", name="Platform", default_role_id=2
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"name": "Platform", "defaultRoleId": 2}
    assert result["endpoint"] == "POST /teams/groups"


@pytest.mark.asyncio
async def test_manage_team_group_update_sends_both_fields(admin_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/teams/groups/{TEAM_GROUP_ID}").mock(
        return_value=httpx.Response(200, json={"id": TEAM_GROUP_ID})
    )

    client = FossaClient(admin_settings)
    result = await teams.manage_team_group(
        make_context(client, admin_settings),
        "update",
        team_group_id=TEAM_GROUP_ID,
        name="Platform",
        default_role_id=3,
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"name": "Platform", "defaultRoleId": 3}
    assert result["endpoint"] == "PUT /teams/groups/{id}"


@pytest.mark.asyncio
async def test_manage_team_group_update_requires_both_fields(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.manage_team_group(
            make_context(client, admin_settings),
            "update",
            team_group_id=TEAM_GROUP_ID,
            name="Platform",
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_manage_team_group_delete_tolerates_an_empty_body(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/teams/groups/{TEAM_GROUP_ID}").mock(
        return_value=httpx.Response(200)
    )

    client = FossaClient(admin_settings)
    result = await teams.manage_team_group(
        make_context(client, admin_settings), "delete", team_group_id=TEAM_GROUP_ID
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "DELETE /teams/groups/{id}"
    assert result["data"] == {"team_group_id": TEAM_GROUP_ID, "deleted": True}


@pytest.mark.asyncio
async def test_update_team_group_assignments_adds_teams(admin_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/teams/groups/{TEAM_GROUP_ID}/teams").mock(
        return_value=httpx.Response(200, json={"id": TEAM_GROUP_ID, "teams": []})
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_group_assignments(
        make_context(client, admin_settings),
        TEAM_GROUP_ID,
        "teams",
        "add",
        team_ids=[TEAM_ID, 8],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"teamIds": [TEAM_ID, 8]}
    assert result["endpoint"] == "POST /teams/groups/{id}/teams"


@pytest.mark.asyncio
async def test_update_team_group_assignments_removes_teams_one_request_each(
    admin_settings, respx_mock, make_context
):
    first = respx_mock.delete(f"{BASE}/teams/groups/{TEAM_GROUP_ID}/teams/{TEAM_ID}").mock(
        return_value=httpx.Response(204)
    )
    second = respx_mock.delete(f"{BASE}/teams/groups/{TEAM_GROUP_ID}/teams/8").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_group_assignments(
        make_context(client, admin_settings),
        TEAM_GROUP_ID,
        "teams",
        "remove",
        team_ids=[TEAM_ID, 8],
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 2
    assert first.called and second.called
    assert result["endpoint"] == "DELETE /teams/groups/{id}/teams/{teamId}"
    assert result["data"]["removed_team_ids"] == [TEAM_ID, 8]


@pytest.mark.asyncio
async def test_update_team_group_assignments_replaces_users(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/teams/groups/{TEAM_GROUP_ID}/users").mock(
        return_value=httpx.Response(200, json={"id": TEAM_GROUP_ID, "users": []})
    )

    client = FossaClient(admin_settings)
    result = await teams.update_team_group_assignments(
        make_context(client, admin_settings),
        TEAM_GROUP_ID,
        "users",
        "replace",
        users=[{"id": USER_ID, "roleId": 2}],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "action": "replace",
        "users": [{"id": USER_ID, "roleId": 2}],
    }
    assert result["endpoint"] == "PUT /teams/groups/{id}/users"


# --- roles -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_roles_defaults_to_the_role_list(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/roles").mock(
        return_value=httpx.Response(200, json=[{"id": ROLE_ID, "name": "Admin"}])
    )

    client = FossaClient(settings)
    result = await teams.list_roles(make_context(client, settings))
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert route.called
    assert result["endpoint"] == "GET /roles"
    assert list(result["data"]) == ["roles"]


@pytest.mark.asyncio
async def test_list_roles_fans_out_over_every_section(settings, respx_mock, make_context):
    roles = respx_mock.get(f"{BASE}/roles").mock(return_value=httpx.Response(200, json=[]))
    permissions = respx_mock.get(f"{BASE}/roles/all-permissions").mock(
        return_value=httpx.Response(200, json=[])
    )
    assignable = respx_mock.get(f"{BASE}/roles/assignable").mock(
        return_value=httpx.Response(200, json={"assignableOrgRoles": []})
    )

    client = FossaClient(settings)
    result = await teams.list_roles(
        make_context(client, settings), sections=["assignable", "permissions", "roles"]
    )
    await client.aclose()

    assert roles.called and permissions.called and assignable.called
    assert result["endpoint"] == "GET /roles, GET /roles/all-permissions, GET /roles/assignable"
    assert list(result["data"]) == ["roles", "permissions", "assignable"]


@pytest.mark.asyncio
async def test_manage_role_create(admin_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/roles").mock(
        return_value=httpx.Response(200, json={"id": ROLE_ID})
    )

    client = FossaClient(admin_settings)
    result = await teams.manage_role(
        make_context(client, admin_settings),
        "create",
        scope="organization",
        name="Auditor",
        description="Read-only auditor",
        permissions=[{"resourceType": "project_any", "action": "view"}],
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "scope": "organization",
        "name": "Auditor",
        "description": "Read-only auditor",
        "permissions": [{"resourceType": "project_any", "action": "view"}],
    }
    assert result["endpoint"] == "POST /roles"


@pytest.mark.asyncio
async def test_manage_role_update_omits_the_scope(admin_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/roles/{ROLE_ID}").mock(
        return_value=httpx.Response(200, json={"id": ROLE_ID})
    )

    client = FossaClient(admin_settings)
    result = await teams.manage_role(
        make_context(client, admin_settings), "update", role_id=ROLE_ID, description="Updated"
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"description": "Updated"}
    assert result["endpoint"] == "PUT /roles/{id}"


@pytest.mark.asyncio
async def test_manage_role_update_rejects_a_scope_change(admin_settings, respx_mock, make_context):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.manage_role(
            make_context(client, admin_settings), "update", role_id=ROLE_ID, scope="team"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_manage_role_delete_tolerates_an_empty_body(admin_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{BASE}/roles/{ROLE_ID}").mock(return_value=httpx.Response(200))

    client = FossaClient(admin_settings)
    result = await teams.manage_role(
        make_context(client, admin_settings), "delete", role_id=ROLE_ID
    )
    await client.aclose()

    assert route.called
    assert result["data"] == {"role_id": ROLE_ID, "deleted": True}


# --- users -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_uses_the_paginated_v2_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/users").mock(
        return_value=httpx.Response(200, json=PAGE_BODY)
    )

    client = FossaClient(settings)
    result = await teams.list_users(
        make_context(client, settings), search="dana", sort="username_asc"
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        *DEFAULT_PAGE_PAIRS,
        ("search", "dana"),
        ("sort", "username_asc"),
    ]
    assert result["endpoint"] == "GET /v2/users"


@pytest.mark.asyncio
async def test_list_users_fetches_one_user_by_id(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/users/{USER_ID}").mock(
        return_value=httpx.Response(200, json={"id": USER_ID, "username": "dana"})
    )

    client = FossaClient(settings)
    result = await teams.list_users(make_context(client, settings), user_id=USER_ID)
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /users/{id}"


@pytest.mark.asyncio
async def test_list_users_deprecated_endpoint_names_its_page_size_count(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/users").mock(return_value=httpx.Response(200, json=[]))

    client = FossaClient(settings)
    result = await teams.list_users(
        make_context(client, settings), page=2, page_size=25, include_all=True
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("page", "2"), ("count", "25")]
    assert result["endpoint"] == "GET /users"


@pytest.mark.asyncio
async def test_list_users_rejects_listing_arguments_alongside_a_user_id(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await teams.list_users(make_context(client, settings), user_id=USER_ID, search="dana")
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_create_service_account_nests_the_team_assignment(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/users/service-accounts").mock(
        return_value=httpx.Response(201, json={"id": 999, "username": "ci-bot"})
    )

    client = FossaClient(admin_settings)
    result = await teams.create_service_account(
        make_context(client, admin_settings),
        username="ci-bot",
        email="ci@acme.test",
        full_name="CI robot",
        org_role_id=3,
        team_id=TEAM_ID,
        team_role_id=6,
        has_push_only_api_token=True,
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "username": "ci-bot",
        "hasPushOnlyApiToken": True,
        "hasFullApiToken": False,
        "email": "ci@acme.test",
        "fullName": "CI robot",
        "orgRoleId": 3,
        "team": {"id": TEAM_ID, "roleId": 6},
    }
    assert result["endpoint"] == "POST /users/service-accounts"
    assert result["data"]["returned_api_token"] is True


@pytest.mark.asyncio
async def test_create_service_account_requires_a_role_or_a_team(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    with pytest.raises(ValueError):
        await teams.create_service_account(make_context(client, admin_settings), username="ci-bot")
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- refusals ----------------------------------------------------------------
#
# Every write in this domain is ADMIN, so each one is refused twice: once with
# writes off entirely, and once with writes on but admin off. Neither may make
# an HTTP call.


def _write_calls(ctx):
    """The eight gated tools, each already bound to a minimally valid argument set."""
    return [
        lambda: teams.create_team(ctx, name="Engineering", default_role_id=2),
        lambda: teams.update_team(ctx, TEAM_ID, name="Platform"),
        lambda: teams.delete_team(ctx, TEAM_ID),
        lambda: teams.update_team_assignments(
            ctx, TEAM_ID, "users", "add", users=[{"id": USER_ID, "roleId": 2}]
        ),
        lambda: teams.manage_team_group(ctx, "create", name="Platform", default_role_id=2),
        lambda: teams.update_team_group_assignments(
            ctx, TEAM_GROUP_ID, "teams", "add", team_ids=[TEAM_ID]
        ),
        lambda: teams.manage_role(
            ctx, "create", scope="organization", name="Auditor", description="Read-only"
        ),
        lambda: teams.create_service_account(ctx, username="ci-bot", org_role_id=3),
    ]


@pytest.mark.asyncio
async def test_every_write_refuses_when_writes_are_off(settings, respx_mock, make_context):
    client = FossaClient(settings)
    calls = _write_calls(make_context(client, settings))

    for call in calls:
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
            await call()

    await client.aclose()

    assert len(calls) == 8
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_every_write_refuses_when_admin_is_off(writable_settings, respx_mock, make_context):
    client = FossaClient(writable_settings)
    calls = _write_calls(make_context(client, writable_settings))

    for call in calls:
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_ADMIN"):
            await call()

    await client.aclose()

    assert len(calls) == 8
    assert respx_mock.calls.call_count == 0
