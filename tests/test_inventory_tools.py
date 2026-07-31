"""Endpoint contract tests for the inventory long-tail tools.

Every read asserts the method, the exact path, and the exact query pairs; every
write asserts the exact JSON body.

**Percent-encoding is asserted against `request.url.raw_path`, not by letting
the respx route match.** Both `httpx.Request.url.path` and respx's own route
matching normalize the URL before comparing, so a route written with an encoded
locator matches a request that never escaped one — verified against respx 0.22.
`raw_path` is the only view that keeps the bytes actually put on the wire.
"""

import json
from datetime import date, datetime

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaApiError, FossaWriteNotPermittedError
from fossa_mcp.tools import inventory

API = "https://app.fossa.com/api"

PROJECT = "git+github.com/acme/widget"
ENCODED_PROJECT = "git%2Bgithub.com%2Facme%2Fwidget"
REVISION = f"{PROJECT}$abc123"
ENCODED_REVISION = f"{ENCODED_PROJECT}%24abc123"
DEPENDENCY = "npm+lodash$4.17.21"
ENCODED_DEPENDENCY = "npm%2Blodash%244.17.21"


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


def _assert_raw_path(request: httpx.Request, expected: str) -> None:
    """Assert the path as it was sent, percent-encoding intact.

    `raw_path` carries the query string too, so split it off; the query is
    asserted separately by `_query_pairs`.
    """
    raw_path = request.url.raw_path.decode().split("?", 1)[0]
    assert raw_path == f"/api{expected}"


# --- binary decomposition ----------------------------------------------------


@pytest.mark.asyncio
async def test_binary_components_revision_count(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/binary/revision/{ENCODED_REVISION}/components/count").mock(
        return_value=httpx.Response(200, json={"count": 42})
    )

    client = FossaClient(settings)
    result = await inventory.binary_components(
        make_context(client, settings), scope="revision", revision_locator=REVISION
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    _assert_raw_path(
        route.calls.last.request,
        f"/binary/revision/{ENCODED_REVISION}/components/count",
    )
    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /binary/revision/{revisionLocator}/components/count"
    assert result["data"]["count"] == 42


@pytest.mark.asyncio
async def test_binary_components_revision_paths_filters(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/binary/revision/{ENCODED_REVISION}/components/paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    client = FossaClient(settings)
    await inventory.binary_components(
        make_context(client, settings),
        scope="revision",
        view="paths",
        revision_locator=REVISION,
        path="/usr/lib",
        search="ssl",
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("path", "/usr/lib"), ("search", "ssl")]


@pytest.mark.asyncio
async def test_binary_components_release_scope(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/binary/release-group/7/release/9/components/paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    client = FossaClient(settings)
    result = await inventory.binary_components(
        make_context(client, settings),
        scope="release",
        view="paths",
        release_group_id=7,
        release_id=9,
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == (
        "GET /binary/release-group/{releaseGroupId}/release/{releaseId}/components/paths"
    )


@pytest.mark.asyncio
async def test_binary_components_rejects_mismatched_scope_arguments(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(ValueError, match="revision_locator is required"):
        await inventory.binary_components(ctx, scope="revision")

    with pytest.raises(ValueError, match="release_group_id and release_id are both required"):
        await inventory.binary_components(ctx, scope="release", release_group_id=7)

    with pytest.raises(ValueError, match="must be None for the release scope"):
        await inventory.binary_components(
            ctx, scope="release", release_group_id=7, release_id=9, revision_locator=REVISION
        )

    with pytest.raises(ValueError, match="only apply to the paths view"):
        await inventory.binary_components(
            ctx, scope="revision", view="count", revision_locator=REVISION, search="ssl"
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_binary_dependency_confidence_revision_all(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/binary/{ENCODED_REVISION}/dependency-confidence").mock(
        return_value=httpx.Response(200, json={"confidences": {DEPENDENCY: "High"}})
    )

    client = FossaClient(settings)
    result = await inventory.binary_dependency_confidence(
        make_context(client, settings), scope="revision", revision_locator=REVISION
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    _assert_raw_path(route.calls.last.request, f"/binary/{ENCODED_REVISION}/dependency-confidence")
    assert result["endpoint"] == "GET /binary/{revisionLocator}/dependency-confidence"
    assert result["data"]["confidences"][DEPENDENCY] == "High"


@pytest.mark.asyncio
async def test_binary_dependency_confidence_single_release_dependency(
    settings, respx_mock, make_context
):
    route = respx_mock.get(
        f"{API}/binary/release/9/dependency-confidence/{ENCODED_DEPENDENCY}"
    ).mock(return_value=httpx.Response(200, json={"confidences": {DEPENDENCY: "Low"}}))

    client = FossaClient(settings)
    result = await inventory.binary_dependency_confidence(
        make_context(client, settings),
        scope="release",
        release_id=9,
        dependency_locator=DEPENDENCY,
    )
    await client.aclose()

    _assert_raw_path(
        route.calls.last.request,
        f"/binary/release/9/dependency-confidence/{ENCODED_DEPENDENCY}",
    )
    assert result["endpoint"] == (
        "GET /binary/release/{releaseId}/dependency-confidence/{dependencyLocator}"
    )


@pytest.mark.asyncio
async def test_binary_revision_detail_component_matches(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/binary/{ENCODED_REVISION}/comp-1/matches").mock(
        return_value=httpx.Response(200, json={"results": [], "totalCount": 0})
    )

    client = FossaClient(settings)
    result = await inventory.binary_revision_detail(
        make_context(client, settings),
        view="component_matches",
        revision_locator=REVISION,
        component_id="comp-1",
        page=2,
        page_size=50,
    )
    await client.aclose()

    _assert_raw_path(route.calls.last.request, f"/binary/{ENCODED_REVISION}/comp-1/matches")
    assert _query_pairs(route.calls.last.request) == [("page", "2"), ("pageSize", "50")]
    assert result["endpoint"] == "GET /binary/{revisionLocator}/{componentId}/matches"


@pytest.mark.asyncio
async def test_binary_revision_detail_dependency_components(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/binary/{ENCODED_REVISION}/{ENCODED_DEPENDENCY}/components").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    client = FossaClient(settings)
    await inventory.binary_revision_detail(
        make_context(client, settings),
        view="dependency_components",
        revision_locator=REVISION,
        dependency_locator=DEPENDENCY,
    )
    await client.aclose()

    _assert_raw_path(
        route.calls.last.request,
        f"/binary/{ENCODED_REVISION}/{ENCODED_DEPENDENCY}/components",
    )
    assert _query_pairs(route.calls.last.request) == [("page", "1"), ("pageSize", "10")]


@pytest.mark.asyncio
async def test_binary_revision_detail_rejects_wrong_identifier(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(ValueError, match="component_id is required"):
        await inventory.binary_revision_detail(
            ctx, view="component_matches", revision_locator=REVISION
        )

    with pytest.raises(ValueError, match="component_id must be None"):
        await inventory.binary_revision_detail(
            ctx,
            view="dependency_components",
            revision_locator=REVISION,
            dependency_locator=DEPENDENCY,
            component_id="comp-1",
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- package observability ---------------------------------------------------


@pytest.mark.asyncio
async def test_list_packages_uses_indexed_array_filters(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/packages").mock(
        return_value=httpx.Response(200, json={"data": [], "count": 0})
    )

    client = FossaClient(settings)
    await inventory.list_packages(
        make_context(client, settings),
        fetchers=["npm", "apk"],
        package_name="lodash",
        depth=["direct"],
        severities=["critical"],
        team_ids=[3, 4],
        locators=["npm+lodash"],
        page=2,
        count=50,
        sort="usage",
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("fetchers[0]", "npm"),
        ("fetchers[1]", "apk"),
        ("packageName", "lodash"),
        ("depth[0]", "direct"),
        ("severities[0]", "critical"),
        ("teamIds[0]", "3"),
        ("teamIds[1]", "4"),
        ("locators[0]", "npm+lodash"),
        ("page", "2"),
        ("count", "50"),
        ("sort", "usage"),
    ]


@pytest.mark.asyncio
async def test_list_packages_rejects_count_above_fossa_limit(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await inventory.list_packages(make_context(client, settings), count=51)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_package_observability_sections(settings, respx_mock, make_context):
    summary = respx_mock.get(f"{API}/packages/package-summary").mock(
        return_value=httpx.Response(200, json={"count": 100})
    )
    managers = respx_mock.get(f"{API}/packages/package-managers").mock(
        return_value=httpx.Response(200, json=["npm"])
    )
    locators = respx_mock.get(f"{API}/packages/package-locators").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    client = FossaClient(settings)
    ctx = make_context(client, settings)

    summary_result = await inventory.package_observability(ctx, section="summary")
    await inventory.package_observability(ctx, section="package_managers")
    await inventory.package_observability(
        ctx, section="locators", package_locator="npm+lo", count=5
    )
    await client.aclose()

    assert summary.called and managers.called
    assert summary_result["endpoint"] == "GET /packages/package-summary"
    assert _query_pairs(locators.calls.last.request) == [
        ("packageLocator", "npm+lo"),
        ("count", "5"),
    ]


@pytest.mark.asyncio
async def test_package_observability_rejects_locator_args_on_other_sections(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="only apply to the locators section"):
        await inventory.package_observability(
            make_context(client, settings), section="summary", count=5
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_export_package_index_sends_filters_without_pagination(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{API}/packages/report").mock(
        return_value=httpx.Response(201, json={"task": {"jobToken": "t"}, "target": "a@b.c"})
    )

    client = FossaClient(settings)
    result = await inventory.export_package_index(
        make_context(client, settings), fetchers=["pip"], block_types=["has_blocked_packages"]
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("fetchers[0]", "pip"),
        ("blockTypes[0]", "has_blocked_packages"),
    ]
    assert result["endpoint"] == "GET /packages/report"


# --- components --------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_component_upload_url_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/components/signed_url").mock(
        return_value=httpx.Response(200, json={"signedUrl": "https://example.com/blob"})
    )

    client = FossaClient(settings)
    result = await inventory.get_component_upload_url(
        make_context(client, settings),
        package_spec="fossa-mcp",
        revision="1.0.0",
        file_type="sbom",
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("packageSpec", "fossa-mcp"),
        ("revision", "1.0.0"),
        ("fileType", "sbom"),
    ]
    assert result["data"]["signedUrl"] == "https://example.com/blob"


@pytest.mark.asyncio
async def test_resolve_purls_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await inventory.resolve_purls(make_context(client, settings), ["pkg:npm/lodash@4.17.21"])
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_resolve_purls_sends_expected_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{API}/components/resolve-purls").mock(
        return_value=httpx.Response(200, json={"results": {}})
    )

    client = FossaClient(writable_settings)
    await inventory.resolve_purls(
        make_context(client, writable_settings), ["pkg:npm/lodash@4.17.21"]
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {"purls": ["pkg:npm/lodash@4.17.21"]}


@pytest.mark.asyncio
async def test_resolve_purls_rejects_empty_and_oversized_lists(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError):
        await inventory.resolve_purls(ctx, [])
    with pytest.raises(ValueError):
        await inventory.resolve_purls(ctx, [f"pkg:npm/p{i}@1" for i in range(101)])
    with pytest.raises(ValueError, match="blank"):
        await inventory.resolve_purls(ctx, ["  "])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_build_component_refuses_when_writes_disabled(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(FossaWriteNotPermittedError):
        await inventory.build_component(
            make_context(client, settings), package_spec="widget", revision="1.0.0"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_build_component_query_and_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{API}/components/build").mock(return_value=httpx.Response(201))

    client = FossaClient(writable_settings)
    result = await inventory.build_component(
        make_context(client, writable_settings),
        package_spec="widget",
        revision="1.0.0",
        file_type="sbom",
        dependency=True,
        description="a widget",
        project_url="https://example.com/widget",
        policy_id=4,
        labels=["team-a", "team-b"],
        selected_team_ids=[1],
        selected_team_names=["Platform"],
        force_rebuild=True,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _query_pairs(request) == [
        ("packageSpec", "widget"),
        ("revision", "1.0.0"),
        ("dependency", "true"),
        ("description", "a widget"),
        ("fileType", "sbom"),
        ("projectURL", "https://example.com/widget"),
        ("policyId", "4"),
        ("labels", "team-a"),
        ("labels", "team-b"),
    ]
    assert json.loads(request.content) == {
        "archives": {
            "packageSpec": "widget",
            "revision": "1.0.0",
            "description": "a widget",
            "projectURL": "https://example.com/widget",
        },
        "selectedTeams": [{"id": 1}, {"name": "Platform"}],
        "forceRebuild": True,
    }
    # The documented 201 carries no body; that must read as success, not as an
    # invalid-JSON error.
    assert result["ok"] is True
    assert result["data"]["result"] is None


# --- audit logs --------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_audit_logs_list_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/audit_logs").mock(return_value=httpx.Response(200, json=[]))

    client = FossaClient(settings)
    await inventory.get_audit_logs(
        make_context(client, settings),
        offset=10,
        limit=25,
        sort_by="createdAt",
        sort_dir="ASC",
        start_date=datetime(2026, 1, 1),
        end_date=datetime(2026, 2, 1),
        acting_user_ids=["7"],
        actions=["update"],
        topics=["project"],
        topic_actions=["project.update"],
        starting_after="12345",
        ending_before="99999",
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("offset", "10"),
        ("limit", "25"),
        ("sortBy", "createdAt"),
        ("sortDir", "ASC"),
        ("startDate", "2026-01-01T00:00:00"),
        ("endDate", "2026-02-01T00:00:00"),
        ("actingUserIds[]", "7"),
        ("actions[]", "update"),
        ("topics[]", "project"),
        ("topicActions[]", "project.update"),
        ("startingAfter", "12345"),
        ("endingBefore", "99999"),
    ]


@pytest.mark.asyncio
async def test_get_audit_logs_count_view_uses_count_path(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/count/audit_logs").mock(
        return_value=httpx.Response(200, json={"count": 3})
    )

    client = FossaClient(settings)
    result = await inventory.get_audit_logs(make_context(client, settings), view="count")
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /count/audit_logs"


@pytest.mark.asyncio
async def test_export_audit_logs_refuses_when_writes_disabled(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(FossaWriteNotPermittedError):
        await inventory.export_audit_logs(
            make_context(client, settings), date(2026, 1, 1), date(2026, 2, 1)
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_export_audit_logs_sends_expected_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{API}/audit_logs/export").mock(
        return_value=httpx.Response(201, json={"task": {"jobToken": "t"}, "target": "a@b.c"})
    )

    client = FossaClient(writable_settings)
    await inventory.export_audit_logs(
        make_context(client, writable_settings),
        date(2026, 1, 1),
        date(2026, 2, 1),
        topics=["project"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "startDate": "2026-01-01",
        "endDate": "2026-02-01",
        "topics": ["project"],
    }


@pytest.mark.asyncio
async def test_export_audit_logs_rejects_inverted_range(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="earlier than start_date"):
        await inventory.export_audit_logs(
            make_context(client, writable_settings), date(2026, 2, 1), date(2026, 1, 1)
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- SBOM sharing ------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_sbom_sharing_sections(settings, respx_mock, make_context):
    share_requests = respx_mock.get(f"{API}/v1/share-requests").mock(
        return_value=httpx.Response(200, json={"shareRequests": []})
    )
    linked = respx_mock.get(f"{API}/v1/shared-organizations").mock(
        return_value=httpx.Response(200, json={"organizationsToShareWith": []})
    )

    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await inventory.get_sbom_sharing(ctx, project_locator=PROJECT)
    result = await inventory.get_sbom_sharing(ctx, section="linked_organizations")
    await client.aclose()

    assert _query_pairs(share_requests.calls.last.request) == [("projectLocator", PROJECT)]
    assert linked.called
    assert result["endpoint"] == "GET /v1/shared-organizations"


@pytest.mark.asyncio
async def test_get_sbom_sharing_rejects_locator_on_linked_organizations(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="only applies to the share_requests section"):
        await inventory.get_sbom_sharing(
            make_context(client, settings),
            section="linked_organizations",
            project_locator=PROJECT,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_share_sbom_revision_refuses_when_writes_disabled(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(FossaWriteNotPermittedError):
        await inventory.share_sbom_revision(make_context(client, settings), REVISION, 5)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_share_sbom_revision_sends_expected_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{API}/v1/share-requests").mock(
        return_value=httpx.Response(201, json={"task": {"jobToken": "t"}})
    )

    client = FossaClient(writable_settings)
    await inventory.share_sbom_revision(make_context(client, writable_settings), REVISION, 5)
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "revisionId": REVISION,
        "sharedOrganizationId": 5,
    }


# --- license conclusions -----------------------------------------------------


@pytest.mark.asyncio
async def test_license_conclusion_refuses_when_writes_disabled(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await inventory.set_license_conclusion(
            make_context(client, settings),
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="project",
            license_id="MIT",
            project_locator=PROJECT,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_conclude_project_scope_sends_expected_body(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{API}/license-conclusions/conclude").mock(
        return_value=httpx.Response(201, json={"concludedLicenses": ["MIT"]})
    )

    client = FossaClient(writable_settings)
    result = await inventory.set_license_conclusion(
        make_context(client, writable_settings),
        action="conclude",
        dependency_revision_locator=DEPENDENCY,
        scope="project",
        license_id="MIT",
        project_locator=PROJECT,
        origin_id=REVISION,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert json.loads(request.content) == {
        "dependencyRevisionLocator": DEPENDENCY,
        "scope": {"scope": "project", "projectLocator": PROJECT},
        "licenseId": "MIT",
        "originId": REVISION,
    }
    assert result["data"]["tier"] == "write"


@pytest.mark.asyncio
async def test_conclude_revision_scope_sends_both_locators(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{API}/license-conclusions/conclude").mock(
        return_value=httpx.Response(201, json={})
    )

    client = FossaClient(writable_settings)
    await inventory.set_license_conclusion(
        make_context(client, writable_settings),
        action="conclude",
        dependency_revision_locator=DEPENDENCY,
        scope="revision",
        license_id="MIT",
        project_locator=PROJECT,
        revision_locator=REVISION,
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content)["scope"] == {
        "scope": "revision",
        "projectLocator": PROJECT,
        "revisionLocator": REVISION,
    }


@pytest.mark.asyncio
async def test_unconclude_requires_destructive_tier(writable_settings, respx_mock, make_context):
    """Removing a conclusion is a delete, so writes alone are not enough."""
    client = FossaClient(writable_settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await inventory.set_license_conclusion(
            make_context(client, writable_settings),
            action="unconclude",
            dependency_revision_locator=DEPENDENCY,
            scope="project",
            license_id="MIT",
            project_locator=PROJECT,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unconclude_hits_the_unconclude_path(destructive_settings, respx_mock, make_context):
    route = respx_mock.put(f"{API}/license-conclusions/unconclude").mock(
        return_value=httpx.Response(201, json={"concludedLicenses": []})
    )

    client = FossaClient(destructive_settings)
    result = await inventory.set_license_conclusion(
        make_context(client, destructive_settings),
        action="unconclude",
        dependency_revision_locator=DEPENDENCY,
        scope="project",
        license_id="MIT",
        project_locator=PROJECT,
    )
    await client.aclose()

    assert route.calls.last.request.method == "PUT"
    assert result["endpoint"] == "PUT /license-conclusions/unconclude"
    assert result["data"]["tier"] == "destructive"


@pytest.mark.asyncio
async def test_org_wide_conclude_requires_destructive_tier(
    writable_settings, respx_mock, make_context
):
    """An organization- or global-scoped conclusion re-licenses every project."""
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="organization",
            license_id="MIT",
            organization_id=42,
        )

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="global",
            license_id="MIT",
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_global_scope_sends_only_the_discriminator(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{API}/license-conclusions/conclude").mock(
        return_value=httpx.Response(201, json={})
    )

    client = FossaClient(destructive_settings)
    await inventory.set_license_conclusion(
        make_context(client, destructive_settings),
        action="conclude",
        dependency_revision_locator=DEPENDENCY,
        scope="global",
        license_id="MIT",
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content)["scope"] == {"scope": "global"}


@pytest.mark.asyncio
async def test_license_conclusion_scope_never_defaults_to_org_wide(
    destructive_settings, respx_mock, make_context
):
    """Each branch of the oneOf requires its own ids and rejects the others'."""
    client = FossaClient(destructive_settings)
    ctx = make_context(client, destructive_settings)

    with pytest.raises(ValueError, match="project_locator is required"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="project",
            license_id="MIT",
        )

    with pytest.raises(ValueError, match="revision_locator is required"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="revision",
            license_id="MIT",
            project_locator=PROJECT,
        )

    with pytest.raises(ValueError, match="release_id is required"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="release",
            license_id="MIT",
            release_group_id=7,
        )

    with pytest.raises(ValueError, match="organization_id is required"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="organization",
            license_id="MIT",
        )

    # A project locator alongside a global scope is rejected rather than
    # silently dropped, which would widen the conclusion to the whole corpus.
    with pytest.raises(ValueError, match="project_locator must be None"):
        await inventory.set_license_conclusion(
            ctx,
            action="conclude",
            dependency_revision_locator=DEPENDENCY,
            scope="global",
            license_id="MIT",
            project_locator=PROJECT,
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- builds ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_builds_list_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/builds").mock(return_value=httpx.Response(200, json=[]))

    client = FossaClient(settings)
    await inventory.get_builds(
        make_context(client, settings),
        locator=REVISION,
        project_id=PROJECT,
        start_date=datetime(2026, 1, 1),
        end_date=datetime(2026, 2, 1),
        page=2,
        page_size=10,
        sort="-createdAt,id",
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("locator", REVISION),
        ("projectId", PROJECT),
        ("startDate", "2026-01-01T00:00:00"),
        ("endDate", "2026-02-01T00:00:00"),
        ("pageSize", "10"),
        ("page", "2"),
        ("sort", "-createdAt,id"),
    ]


@pytest.mark.asyncio
async def test_get_builds_count_view_returns_bare_number(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/counts/builds").mock(return_value=httpx.Response(200, json=4))

    client = FossaClient(settings)
    result = await inventory.get_builds(
        make_context(client, settings), view="count", locator=REVISION
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /counts/builds"
    assert result["data"] == 4


# --- vulnerabilities ---------------------------------------------------------


@pytest.mark.asyncio
async def test_search_cves_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/vulns/cve-list").mock(
        return_value=httpx.Response(200, json=[{"cve": "CVE-2021-44228"}])
    )

    client = FossaClient(settings)
    result = await inventory.search_cves(make_context(client, settings), "log4j")
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("query", "log4j")]
    assert result["data"][0]["cve"] == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_get_vulnerability_remediation_encodes_both_path_segments(
    settings, respx_mock, make_context
):
    route = respx_mock.get(
        f"{API}/vulns/CVE-2021-44228_mvn%2Blog4j/revisions/{ENCODED_REVISION}/remediation-guidance"
    ).mock(
        return_value=httpx.Response(
            200, json={"completeFix": "2.17.1", "completeFixDistance": "MINOR"}
        )
    )

    client = FossaClient(settings)
    result = await inventory.get_vulnerability_remediation(
        make_context(client, settings), "CVE-2021-44228_mvn+log4j", REVISION
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    _assert_raw_path(
        route.calls.last.request,
        f"/vulns/CVE-2021-44228_mvn%2Blog4j/revisions/{ENCODED_REVISION}/remediation-guidance",
    )
    assert result["data"]["completeFixDistance"] == "MINOR"


# --- organization capabilities -----------------------------------------------


@pytest.mark.asyncio
async def test_get_cli_organization(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/cli/organization").mock(
        return_value=httpx.Response(200, json={"organizationId": 1, "subscription": "Premium"})
    )

    client = FossaClient(settings)
    result = await inventory.get_cli_organization(make_context(client, settings))
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["data"]["subscription"] == "Premium"


@pytest.mark.asyncio
async def test_github_app_installation_url_reads_the_redirect_location(
    settings, respx_mock, make_context
):
    """The endpoint documents no 2xx at all; the payload is the Location header."""
    target = "https://github.com/apps/fossa/installations/new"
    route = respx_mock.get(f"{API}/services/github-app/installation-url").mock(
        return_value=httpx.Response(302, headers={"location": target})
    )

    client = FossaClient(settings)
    result = await inventory.get_github_app_installation_url(make_context(client, settings))
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["ok"] is True
    assert result["data"]["installation_url"] == target
    assert result["data"]["status_code"] == 302


@pytest.mark.asyncio
async def test_github_app_installation_url_surfaces_errors(settings, respx_mock, make_context):
    respx_mock.get(f"{API}/services/github-app/installation-url").mock(
        return_value=httpx.Response(
            404, json={"message": "GitHub App not configured", "name": "NotFoundError"}
        )
    )

    client = FossaClient(settings)
    with pytest.raises(FossaApiError, match="GitHub App not configured"):
        await inventory.get_github_app_installation_url(make_context(client, settings))
    await client.aclose()
