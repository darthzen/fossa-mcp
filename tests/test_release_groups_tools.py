"""Endpoint contract tests for the release group tools.

Covers the HTTP shape of every release group operation the server exposes: the
paths the sectioned reads fan out to, the exact query pairs the two attribution
endpoints receive, the exact JSON body each write sends, and the refusal path
that must fire before any request leaves the process when the tool's write tier
is off.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import release_groups

BASE = "https://app.fossa.com/api"
GROUP_ID = 7
RELEASE_ID = 42

PROJECT = "git+github.com/acme/widget"
OTHER_PROJECT = "git+github.com/acme/gadget"

GROUP_BODY = {"id": GROUP_ID, "title": "Platform", "organizationId": 1000}
RELEASE_BODY = {"id": RELEASE_ID, "title": "2026.1", "projectGroupId": GROUP_ID}

# The report content switches, in the order the tools send them. Both attribution
# tools share this block; only what surrounds it differs.
DEFAULT_OPTION_PAIRS = [
    ("includeDeepDependencies", "true"),
    ("includeDirectDependencies", "true"),
    ("includeFOSSADependencies", "false"),
    ("includeLicenseList", "true"),
    ("includeLicenseScan", "false"),
    ("includeProjectLicense", "true"),
    ("includeCopyrightList", "false"),
    ("includeFileMatches", "false"),
    ("includeOpenVulnerabilities", "false"),
    ("includeClosedVulnerabilities", "false"),
    ("includeDependencySummary", "true"),
    ("includeLicenseHeaders", "false"),
]


@pytest.fixture
def writable_settings() -> Settings:
    return Settings(fossa_api_token="test-token", fossa_allow_writes=True, _env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def destructive_settings() -> Settings:
    return Settings(
        fossa_api_token="test-token",
        fossa_allow_writes=True,
        fossa_allow_destructive=True,
        _env_file=None,  # type: ignore[call-arg]
    )


def _query_pairs(request: httpx.Request) -> list[tuple[str, str]]:
    return httpx.QueryParams(request.url.query.decode()).multi_items()


# --- sectioned reads ---------------------------------------------------------


@pytest.mark.asyncio
async def test_get_release_group_defaults_to_the_group_alone(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP_BODY)
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group(make_context(client, settings), GROUP_ID)
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert route.calls.last.request.method == "GET"
    assert result["endpoint"] == "GET /project_group/{groupId}"
    assert result["data"] == {"group": GROUP_BODY}


@pytest.mark.asyncio
async def test_get_release_group_sections_are_deduped_and_ordered(
    settings, respx_mock, make_context
):
    group = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP_BODY)
    )
    teams = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/teams").mock(
        return_value=httpx.Response(200, json={"totalCount": 1, "teams": [{"id": 1}]})
    )
    projects = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/all_projects").mock(
        return_value=httpx.Response(200, json=[PROJECT])
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group(
        make_context(client, settings),
        GROUP_ID,
        sections=["projects", "teams", "group", "teams"],
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 3
    assert group.called and teams.called and projects.called
    assert result["endpoint"] == (
        "GET /project_group/{groupId}, "
        "GET /project_group/{groupId}/teams, "
        "GET /project_group/{groupId}/all_projects"
    )
    assert list(result["data"]) == ["group", "teams", "projects"]
    assert result["data"]["projects"] == [PROJECT]


@pytest.mark.asyncio
async def test_get_release_group_rejects_a_non_positive_id(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await release_groups.get_release_group(make_context(client, settings), 0)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_get_release_group_release_defaults_to_release_and_summary(
    settings, respx_mock, make_context
):
    release = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}").mock(
        return_value=httpx.Response(200, json=RELEASE_BODY)
    )
    summary = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/summary").mock(
        return_value=httpx.Response(200, json={"dependency_count": 50})
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group_release(
        make_context(client, settings), GROUP_ID, RELEASE_ID
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 2
    assert release.called and summary.called
    assert result["endpoint"] == (
        "GET /project_group/{groupId}/release/{releaseId}, "
        "GET /project_group/{groupId}/release/{releaseId}/summary"
    )
    assert result["data"]["summary"]["dependency_count"] == 50


@pytest.mark.asyncio
async def test_get_release_group_release_fetches_only_the_named_sections(
    settings, respx_mock, make_context
):
    licenses = respx_mock.get(
        f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/licenses"
    ).mock(return_value=httpx.Response(200, json={"MIT": {"licenseId": "MIT"}}))
    obligations = respx_mock.get(
        f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/obligations"
    ).mock(return_value=httpx.Response(200, json={"MIT": []}))

    client = FossaClient(settings)
    result = await release_groups.get_release_group_release(
        make_context(client, settings),
        GROUP_ID,
        RELEASE_ID,
        sections=["obligations", "licenses"],
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 2
    assert licenses.called and obligations.called
    assert list(result["data"]) == ["licenses", "obligations"]


@pytest.mark.asyncio
async def test_get_release_group_release_covers_revisions_and_scans(
    settings, respx_mock, make_context
):
    revisions = respx_mock.get(
        f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/revisions"
    ).mock(return_value=httpx.Response(200, json=[{"locator": f"{PROJECT}$abc"}]))
    scans = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/scans").mock(
        return_value=httpx.Response(200, json=[{"id": 1}])
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group_release(
        make_context(client, settings), GROUP_ID, RELEASE_ID, sections=["revisions", "scans"]
    )
    await client.aclose()

    assert revisions.called and scans.called
    assert result["endpoint"] == (
        "GET /project_group/{groupId}/release/{releaseId}/revisions, "
        "GET /project_group/{groupId}/release/{releaseId}/scans"
    )


# --- paginated release listing ----------------------------------------------


@pytest.mark.asyncio
async def test_list_release_group_releases_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/releases").mock(
        return_value=httpx.Response(200, json={"releases": [RELEASE_BODY], "totalCount": 1})
    )

    client = FossaClient(settings)
    result = await release_groups.list_release_group_releases(
        make_context(client, settings), GROUP_ID, page=2, count=25, search="2026"
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [("page", "2"), ("count", "25"), ("search", "2026")]
    assert result["endpoint"] == "GET /project_group/{groupId}/releases"
    assert result["data"]["totalCount"] == 1


@pytest.mark.asyncio
async def test_list_release_group_releases_omits_an_absent_search(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/project_group/{GROUP_ID}/releases").mock(
        return_value=httpx.Response(200, json={"releases": []})
    )

    client = FossaClient(settings)
    await release_groups.list_release_group_releases(make_context(client, settings), GROUP_ID)
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("page", "1"), ("count", "10")]


@pytest.mark.asyncio
async def test_list_release_group_releases_rejects_a_count_over_fossas_cap(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await release_groups.list_release_group_releases(
            make_context(client, settings), GROUP_ID, count=51
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_list_release_group_releases_respects_a_lower_server_page_size(
    settings, respx_mock, make_context
):
    settings = settings.model_copy(update={"fossa_max_page_size": 5})

    client = FossaClient(settings)
    with pytest.raises(ValueError, match="between 1 and 5"):
        await release_groups.list_release_group_releases(
            make_context(client, settings), GROUP_ID, count=10
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- attribution reads -------------------------------------------------------


@pytest.mark.asyncio
async def test_attribution_report_downloads_synchronously(settings, respx_mock, make_context):
    route = respx_mock.get(
        f"{BASE}/v2/project_group/{GROUP_ID}/release/{RELEASE_ID}/attribution/MD"
    ).mock(
        return_value=httpx.Response(
            200, text="# Attribution", headers={"content-type": "text/markdown"}
        )
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group_attribution_report(
        make_context(client, settings), GROUP_ID, RELEASE_ID
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == (
        [("preview", "false"), ("download", "true")]
        + DEFAULT_OPTION_PAIRS
        + [("includePackageLabels", "false")]
    )
    assert result["content"] == "# Attribution"
    assert result["format"] == "MD"
    assert result["truncated"] is False
    assert result["endpoint"] == (
        "GET /v2/project_group/{groupId}/release/{releaseId}/attribution/{format}"
    )


@pytest.mark.asyncio
async def test_attribution_report_sends_titles_options_and_label_exclusions(
    settings, respx_mock, make_context
):
    route = respx_mock.get(
        f"{BASE}/v2/project_group/{GROUP_ID}/release/{RELEASE_ID}/attribution/CSV"
    ).mock(return_value=httpx.Response(200, text="a,b"))

    client = FossaClient(settings)
    await release_groups.get_release_group_attribution_report(
        make_context(client, settings),
        GROUP_ID,
        RELEASE_ID,
        format="CSV",
        preview=True,
        include_package_labels=True,
        dependency_info_options=["Library", "ConcludedLicense"],
        exclude_package_labels=["internal", "vendored"],
        release_group_title="Platform",
        release_title="2026.1",
        release_group_url="https://example.invalid/platform",
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("preview", "true") in pairs
    assert ("download", "false") in pairs
    assert ("includePackageLabels", "true") in pairs
    assert ("projectGroupTitle", "Platform") in pairs
    assert ("projectGroupReleaseTitle", "2026.1") in pairs
    assert ("projectGroupUrl", "https://example.invalid/platform") in pairs
    assert ("dependencyInfoOptions[]", "Library") in pairs
    assert ("dependencyInfoOptions[]", "ConcludedLicense") in pairs
    # FOSSA parses this with `qs`, so the array is indexed, not repeated.
    assert ("excludeFields[packageLabels][0]", "internal") in pairs
    assert ("excludeFields[packageLabels][1]", "vendored") in pairs


@pytest.mark.asyncio
async def test_attribution_report_parses_a_json_format(settings, respx_mock, make_context):
    respx_mock.get(
        f"{BASE}/v2/project_group/{GROUP_ID}/release/{RELEASE_ID}/attribution/SPDX_JSON"
    ).mock(return_value=httpx.Response(200, text=json.dumps({"spdxVersion": "SPDX-2.3"})))

    client = FossaClient(settings)
    result = await release_groups.get_release_group_attribution_report(
        make_context(client, settings), GROUP_ID, RELEASE_ID, format="SPDX_JSON"
    )
    await client.aclose()

    assert result["content"] == {"spdxVersion": "SPDX-2.3"}
    assert "json_parse_error" not in result


@pytest.mark.asyncio
async def test_attribution_report_truncates_oversized_content(settings, respx_mock, make_context):
    settings = settings.model_copy(update={"fossa_report_max_chars": 1000})
    respx_mock.get(f"{BASE}/v2/project_group/{GROUP_ID}/release/{RELEASE_ID}/attribution/TXT").mock(
        return_value=httpx.Response(200, text="x" * 1500)
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group_attribution_report(
        make_context(client, settings), GROUP_ID, RELEASE_ID, format="TXT"
    )
    await client.aclose()

    assert result["truncated"] is True
    assert result["original_char_count"] == 1500
    assert len(result["content"]) == 1000


@pytest.mark.asyncio
async def test_attribution_status_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/project_group/attribution/99").mock(
        return_value=httpx.Response(200, json={"taskId": 99, "status": "SUCCEEDED", "url": "u"})
    )

    client = FossaClient(settings)
    result = await release_groups.get_release_group_attribution_status(
        make_context(client, settings), 99
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["endpoint"] == "GET /project_group/attribution/{taskId}"
    assert result["data"]["status"] == "SUCCEEDED"


# --- write gate --------------------------------------------------------------


@pytest.mark.asyncio
async def test_creates_and_updates_refuse_when_writes_disabled(settings, respx_mock, make_context):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.create_release_group(
            ctx, "Platform", "2026.1", [{"projectId": PROJECT}]
        )

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.update_release_group(ctx, GROUP_ID, title="Renamed")

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.create_release_group_release(
            ctx, GROUP_ID, "2026.2", [{"projectId": PROJECT}]
        )

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.update_release_group_release(ctx, GROUP_ID, RELEASE_ID, "2026.2")

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.queue_release_group_attribution_report(ctx, GROUP_ID, RELEASE_ID)

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_deletes_refuse_when_writes_disabled(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.delete_release_group(ctx, GROUP_ID)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await release_groups.delete_release_group_release(ctx, GROUP_ID, RELEASE_ID)

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_deletes_refuse_when_only_the_write_tier_is_enabled(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await release_groups.delete_release_group(ctx, GROUP_ID)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await release_groups.delete_release_group_release(ctx, GROUP_ID, RELEASE_ID)

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- writes ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_release_group_sends_expected_body(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/project_group").mock(
        return_value=httpx.Response(200, json=GROUP_BODY)
    )

    client = FossaClient(writable_settings)
    result = await release_groups.create_release_group(
        make_context(client, writable_settings),
        "Platform",
        "2026.1",
        [
            {"projectId": PROJECT, "branch": "main", "revisionId": "abc123"},
            {"projectId": OTHER_PROJECT},
        ],
        licensing_policy_id=1,
        security_policy_id=2,
        public_on_portal=True,
        team_ids=[101, 102],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "title": "Platform",
        "release": {
            "title": "2026.1",
            "projects": [
                {"projectId": PROJECT, "branch": "main", "revisionId": "abc123"},
                {"projectId": OTHER_PROJECT},
            ],
        },
        "licensingPolicyId": 1,
        "securityPolicyId": 2,
        "publicOnPortal": True,
        "teams": [101, 102],
    }
    assert result["endpoint"] == "POST /project_group"
    assert result["data"]["release_group"] == GROUP_BODY


@pytest.mark.asyncio
async def test_create_release_group_rejects_unknown_project_keys(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError):
        await release_groups.create_release_group(
            ctx, "Platform", "2026.1", [{"projectId": PROJECT, "revision": "abc123"}]
        )

    with pytest.raises(ValueError):
        await release_groups.create_release_group(ctx, "Platform", "2026.1", [])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_release_group_sends_only_named_fields(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/project_group/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP_BODY)
    )

    client = FossaClient(writable_settings)
    await release_groups.update_release_group(
        make_context(client, writable_settings), GROUP_ID, title="Renamed", security_policy_id=9
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "title": "Renamed",
        "securityPolicyId": 9,
    }


@pytest.mark.asyncio
async def test_update_release_group_clears_nullable_fields_explicitly(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/project_group/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP_BODY)
    )

    client = FossaClient(writable_settings)
    await release_groups.update_release_group(
        make_context(client, writable_settings),
        GROUP_ID,
        title="Renamed",
        clear_fields=["licensingPolicyId", "reportCustomText"],
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "title": "Renamed",
        "licensingPolicyId": None,
        "reportCustomText": None,
    }


@pytest.mark.asyncio
async def test_update_release_group_rejects_a_no_op_and_a_set_clear_conflict(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError, match="at least one field"):
        await release_groups.update_release_group(ctx, GROUP_ID)

    with pytest.raises(ValueError, match="set and clear"):
        await release_groups.update_release_group(
            ctx, GROUP_ID, security_policy_id=9, clear_fields=["securityPolicyId"]
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_release_group_tolerates_an_empty_response_body(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/project_group/{GROUP_ID}").mock(
        return_value=httpx.Response(200)
    )

    client = FossaClient(destructive_settings)
    result = await release_groups.delete_release_group(
        make_context(client, destructive_settings), GROUP_ID
    )
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /project_group/{groupId}"
    assert result["data"] == {"release_group_id": GROUP_ID, "deleted": True}


@pytest.mark.asyncio
async def test_create_release_group_release_sends_expected_body(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/project_group/{GROUP_ID}/release").mock(
        return_value=httpx.Response(200, json=RELEASE_BODY)
    )

    client = FossaClient(writable_settings)
    result = await release_groups.create_release_group_release(
        make_context(client, writable_settings),
        GROUP_ID,
        "2026.2",
        [{"projectId": PROJECT, "branch": "main", "revisionId": "abc123"}],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "title": "2026.2",
        "projects": [{"projectId": PROJECT, "branch": "main", "revisionId": "abc123"}],
    }
    assert result["endpoint"] == "POST /project_group/{groupId}/release"


@pytest.mark.asyncio
async def test_update_release_group_release_sends_expected_body(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}").mock(
        return_value=httpx.Response(200, json=RELEASE_BODY)
    )

    client = FossaClient(writable_settings)
    result = await release_groups.update_release_group_release(
        make_context(client, writable_settings),
        GROUP_ID,
        RELEASE_ID,
        "2026.2",
        projects=[{"projectId": PROJECT, "revisionId": "def456"}],
        projects_to_delete=[OTHER_PROJECT],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert json.loads(request.content) == {
        "title": "2026.2",
        "projects": [{"projectId": PROJECT, "revisionId": "def456"}],
        "projectsToDelete": [OTHER_PROJECT],
    }
    assert result["endpoint"] == "PUT /project_group/{groupId}/release/{projectGroupReleaseId}"


@pytest.mark.asyncio
async def test_update_release_group_release_sends_title_alone_when_that_is_all(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}").mock(
        return_value=httpx.Response(200, json=RELEASE_BODY)
    )

    client = FossaClient(writable_settings)
    await release_groups.update_release_group_release(
        make_context(client, writable_settings), GROUP_ID, RELEASE_ID, "2026.2"
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {"title": "2026.2"}


@pytest.mark.asyncio
async def test_update_release_group_release_rejects_adding_and_removing_one_project(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)

    with pytest.raises(ValueError, match="added and removed"):
        await release_groups.update_release_group_release(
            make_context(client, writable_settings),
            GROUP_ID,
            RELEASE_ID,
            "2026.2",
            projects=[{"projectId": PROJECT}],
            projects_to_delete=[PROJECT],
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_release_group_release_endpoint(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}").mock(
        return_value=httpx.Response(200)
    )

    client = FossaClient(destructive_settings)
    result = await release_groups.delete_release_group_release(
        make_context(client, destructive_settings), GROUP_ID, RELEASE_ID
    )
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["data"] == {
        "release_group_id": GROUP_ID,
        "release_id": RELEASE_ID,
        "deleted": True,
    }


@pytest.mark.asyncio
async def test_queue_attribution_report_query_and_method(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(
        f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/attribution/PDF"
    ).mock(return_value=httpx.Response(200, json={"taskId": 99}))

    client = FossaClient(writable_settings)
    result = await release_groups.queue_release_group_attribution_report(
        make_context(client, writable_settings),
        GROUP_ID,
        RELEASE_ID,
        format="PDF",
        is_publishing=True,
        dependency_info_options=["Library", "License"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _query_pairs(request) == (
        DEFAULT_OPTION_PAIRS
        + [
            ("isPublishing", "true"),
            ("dependencyInfoOptions[]", "Library"),
            ("dependencyInfoOptions[]", "License"),
        ]
    )
    # A queued report carries no request body; every option travels in the query.
    assert request.content == b""
    assert result["data"]["task"] == {"taskId": 99}
    assert result["data"]["is_publishing"] is True
    assert result["endpoint"] == (
        "POST /project_group/{groupId}/release/{releaseId}/attribution/{format}"
    )


@pytest.mark.asyncio
async def test_queue_attribution_report_defaults_to_not_publishing(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(
        f"{BASE}/project_group/{GROUP_ID}/release/{RELEASE_ID}/attribution/MD"
    ).mock(return_value=httpx.Response(200, json={"taskId": 1}))

    client = FossaClient(writable_settings)
    await release_groups.queue_release_group_attribution_report(
        make_context(client, writable_settings), GROUP_ID, RELEASE_ID
    )
    await client.aclose()

    assert ("isPublishing", "false") in _query_pairs(route.calls.last.request)
