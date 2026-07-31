"""Endpoint contract tests for the project tools.

Covers the HTTP shape of every project operation the server exposes, the exact
body sent by `update_project`, and the refusal path that must fire before any
request leaves the process when a tool's write tier is off.

`tests/test_tools.py` already covers the two original read tools
(`list_projects`, `get_project`) in their pre-parity form; this module tests the
behavior added on top of them.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import projects

PROJECT = "git+github.com/acme/widget"
ENCODED_PROJECT = "git%2Bgithub.com%2Facme%2Fwidget"
OTHER_PROJECT = "git+github.com/acme/gadget"
BASE = "https://app.fossa.com/api"


@pytest.fixture
def writable_settings() -> Settings:
    """Writes enabled, destructive operations still refused."""
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


# --- reads -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_projects_switches_to_post_for_an_oversized_locator_filter(
    settings, respx_mock, make_context
):
    locators = [f"git+github.com/acme/service-number-{index:03d}" for index in range(60)]
    route = respx_mock.post(f"{BASE}/v2/projects").mock(
        return_value=httpx.Response(200, json={"projects": [], "total": 0})
    )

    client = FossaClient(settings)
    result = await projects.list_projects(
        make_context(client, settings), locators=locators, types=["container"], count=50
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert request.url.query == b""
    assert json.loads(request.content) == {
        "page": 1,
        "count": 50,
        "type": ["container"],
        "locators": locators,
    }
    assert result["endpoint"] == "POST /v2/projects"


@pytest.mark.asyncio
async def test_list_projects_stays_on_get_for_a_short_filter(settings, respx_mock, make_context):
    """A single locator goes over the wire as `locators[]`, not plain `locators`.

    `GET /v2/projects` rejects one plain `locators=<x>` with a `400`; it parses
    as a string and the endpoint's schema wants an array.
    """
    route = respx_mock.get(f"{BASE}/v2/projects").mock(
        return_value=httpx.Response(200, json={"projects": []})
    )

    client = FossaClient(settings)
    result = await projects.list_projects(make_context(client, settings), locators=[PROJECT])
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert route.calls.last.request.method == "GET"
    assert ("locators[]", PROJECT) in pairs
    assert ("locators", PROJECT) not in pairs
    assert result["endpoint"] == "GET /v2/projects"


@pytest.mark.asyncio
async def test_get_projects_summary_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/projects/summary").mock(
        return_value=httpx.Response(200, json={"summary": {"projects": 12, "releaseGroups": 3}})
    )

    client = FossaClient(settings)
    result = await projects.get_projects_summary(make_context(client, settings))
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.query == b""
    assert result["endpoint"] == "GET /v2/projects/summary"
    assert result["data"]["summary"]["projects"] == 12


@pytest.mark.asyncio
async def test_get_project_associations_fetches_all_three_sections(
    settings, respx_mock, make_context
):
    labels = respx_mock.get(f"{BASE}/projects/{ENCODED_PROJECT}/labels").mock(
        return_value=httpx.Response(200, json=[{"id": 4, "label": "tier-1"}])
    )
    groups = respx_mock.get(f"{BASE}/v2/projects/{ENCODED_PROJECT}/release-groups").mock(
        return_value=httpx.Response(200, json={"releaseGroups": [{"releaseGroupId": 9}]})
    )
    published = respx_mock.get(f"{BASE}/projects/{ENCODED_PROJECT}/last-published").mock(
        return_value=httpx.Response(200, json="2026-07-30T12:00:00Z")
    )

    client = FossaClient(settings)
    result = await projects.get_project_associations(make_context(client, settings), PROJECT)
    await client.aclose()

    # Matching these routes is the assertion that the locator was encoded once;
    # httpx re-decodes `url.path`.
    assert labels.called and groups.called and published.called
    assert respx_mock.calls.call_count == 3
    assert result["data"]["labels"][0]["label"] == "tier-1"
    assert result["data"]["release_groups"]["releaseGroups"][0]["releaseGroupId"] == 9
    assert result["data"]["last_published"] == "2026-07-30T12:00:00Z"
    assert result["endpoint"] == (
        "GET /projects/{locator}/labels + GET /v2/projects/{locator}/release-groups"
        " + GET /projects/{locator}/last-published"
    )


@pytest.mark.asyncio
async def test_get_project_associations_honors_a_narrowed_section_list(
    settings, respx_mock, make_context
):
    labels = respx_mock.get(f"{BASE}/projects/{ENCODED_PROJECT}/labels").mock(
        return_value=httpx.Response(200, json=[])
    )

    client = FossaClient(settings)
    result = await projects.get_project_associations(
        make_context(client, settings), PROJECT, sections=["labels", "labels"]
    )
    await client.aclose()

    assert labels.call_count == 1
    assert respx_mock.calls.call_count == 1
    assert set(result["data"]) == {"labels"}
    assert result["endpoint"] == "GET /projects/{locator}/labels"


@pytest.mark.asyncio
async def test_export_project_issues_json_path_and_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/projects/{ENCODED_PROJECT}/export-issues/json").mock(
        return_value=httpx.Response(200, json={"Package License Issues": []})
    )

    client = FossaClient(settings)
    result = await projects.export_project_issues(
        make_context(client, settings),
        PROJECT,
        revision_id="abc123",
        status="ignored",
        ref="release/2.0",
        ref_type="tag",
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("revisionId", "abc123"),
        ("status", "ignored"),
        ("ref", "release/2.0"),
        ("ref_type", "tag"),
    ]
    assert result["endpoint"] == "GET /projects/{locator}/export-issues/json"
    assert "Package License Issues" in result["data"]


@pytest.mark.asyncio
async def test_export_project_issues_csv_returns_raw_text(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/projects/{ENCODED_PROJECT}/export-issues/csv").mock(
        return_value=httpx.Response(
            200, text="Dependency,License\nnpm+lodash,MIT\n", headers={"content-type": "text/csv"}
        )
    )

    client = FossaClient(settings)
    result = await projects.export_project_issues(
        make_context(client, settings), PROJECT, format="csv"
    )
    await client.aclose()

    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == "GET /projects/{locator}/export-issues/csv"
    assert result["data"]["content_type"] == "text/csv"
    assert result["data"]["content"].startswith("Dependency,License")


@pytest.mark.asyncio
async def test_export_project_issues_rejects_ref_type_without_ref(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="ref_type"):
        await projects.export_project_issues(
            make_context(client, settings), PROJECT, ref_type="tag"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- write gate --------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_tools_refuse_and_send_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await projects.update_project(ctx, PROJECT, title="renamed")

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await projects.apply_project_label(ctx, 4, [PROJECT])

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await projects.generate_project_attribution_slug(ctx, PROJECT)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await projects.delete_project_attribution_slug(ctx, PROJECT)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await projects.delete_project(ctx, PROJECT)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await projects.delete_projects(ctx, [PROJECT])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_deletes_refuse_when_only_the_write_tier_is_enabled(
    writable_settings, respx_mock, make_context
):
    assert writable_settings.fossa_allow_destructive is False
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    for call in (
        projects.delete_project(ctx, PROJECT),
        projects.delete_projects(ctx, [PROJECT]),
        projects.delete_project_attribution_slug(ctx, PROJECT),
    ):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- writes ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_project_sends_only_the_named_fields(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json={"locator": PROJECT, "title": "widget-core"})
    )

    client = FossaClient(writable_settings)
    result = await projects.update_project(
        make_context(client, writable_settings),
        PROJECT,
        title="widget-core",
        public=False,
        security_policy_id=9,
        security_issue_scanning_enabled=True,
        tracking_branches=["main", "develop"],
        label_ids=[3, 7],
        report_custom_text="Contact legal@acme.example",
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert json.loads(request.content) == {
        "title": "widget-core",
        "public": False,
        "securityPolicyId": 9,
        "securityIssueScanningEnabled": True,
        "tracking_branches": ["main", "develop"],
        "labels": [3, 7],
        "reportCustomText": "Contact legal@acme.example",
    }
    assert result["endpoint"] == "PUT /projects/{locator}"
    assert result["data"]["project"]["title"] == "widget-core"


@pytest.mark.asyncio
async def test_update_project_requires_at_least_one_field(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="at least one project field"):
        await projects.update_project(make_context(client, writable_settings), PROJECT)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_project_rejects_a_branch_in_both_lists(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="mutually exclusive"):
        await projects.update_project(
            make_context(client, writable_settings),
            PROJECT,
            tracking_branches=["main"],
            hidden_branches=["main"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_apply_project_label_query_and_partial_failure(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/v2/projects/labels").mock(
        return_value=httpx.Response(200, json={OTHER_PROJECT: "Insufficient permissions"})
    )

    client = FossaClient(writable_settings)
    result = await projects.apply_project_label(
        make_context(client, writable_settings), 4, [PROJECT, OTHER_PROJECT]
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert _query_pairs(request) == [
        ("labelId", "4"),
        ("locators[]", PROJECT),
        ("locators[]", OTHER_PROJECT),
    ]
    assert result["data"]["succeeded"] == [PROJECT]
    assert result["data"]["failures"] == {OTHER_PROJECT: "Insufficient permissions"}


@pytest.mark.asyncio
async def test_apply_project_label_brackets_a_single_locator(
    writable_settings, respx_mock, make_context
):
    """One locator is the case the plain `locators` form got wrong.

    FOSSA parses the query string with `qs`: a single plain `locators=<x>`
    arrives as a string and the endpoint's schema rejects it with
    `400 "expected array, received string"`. Two or more plain occurrences parse
    as an array and work, which is why the bug stayed hidden. `locators[]` is an
    array at every length.
    """
    route = respx_mock.put(f"{BASE}/v2/projects/labels").mock(
        return_value=httpx.Response(200, json={})
    )

    client = FossaClient(writable_settings)
    await projects.apply_project_label(make_context(client, writable_settings), 4, [PROJECT])
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("labelId", "4"),
        ("locators[]", PROJECT),
    ]


@pytest.mark.asyncio
async def test_apply_project_label_rejects_the_wildcard(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="wildcard"):
        await projects.apply_project_label(
            make_context(client, writable_settings), 4, [PROJECT, "all"]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_generate_attribution_slug_endpoint(writable_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/projects/{ENCODED_PROJECT}/generate_attribution_slug").mock(
        return_value=httpx.Response(200, json="00000-1111-2222-333333333333")
    )

    client = FossaClient(writable_settings)
    result = await projects.generate_project_attribution_slug(
        make_context(client, writable_settings), PROJECT
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert request.content == b""
    assert result["endpoint"] == "PUT /projects/{locator}/generate_attribution_slug"
    assert result["data"]["slug"] == "00000-1111-2222-333333333333"


@pytest.mark.asyncio
async def test_delete_attribution_slug_accepts_an_empty_204(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/projects/{ENCODED_PROJECT}/generate_attribution_slug").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(destructive_settings)
    result = await projects.delete_project_attribution_slug(
        make_context(client, destructive_settings), PROJECT
    )
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /projects/{locator}/generate_attribution_slug"
    assert result["data"] == {"project_locator": PROJECT, "response": None}


@pytest.mark.asyncio
async def test_delete_project_endpoint(destructive_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{BASE}/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200)
    )

    client = FossaClient(destructive_settings)
    result = await projects.delete_project(make_context(client, destructive_settings), PROJECT)
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "DELETE"
    assert request.url.query == b""
    assert result["endpoint"] == "DELETE /projects/{locator}"
    assert result["data"]["deleted"] == [PROJECT]


@pytest.mark.asyncio
async def test_delete_projects_sends_only_explicit_locators(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/v2/projects").mock(return_value=httpx.Response(200))

    client = FossaClient(destructive_settings)
    result = await projects.delete_projects(
        make_context(client, destructive_settings), [PROJECT, OTHER_PROJECT]
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "DELETE"
    # No filter parameter may accompany a bulk delete: with the locator list
    # gone the request would degrade into a filter-wide delete.
    assert _query_pairs(request) == [
        ("locators[]", PROJECT),
        ("locators[]", OTHER_PROJECT),
    ]
    assert result["endpoint"] == "DELETE /v2/projects"
    assert result["data"]["deleted"] == [PROJECT, OTHER_PROJECT]


@pytest.mark.asyncio
async def test_delete_projects_brackets_a_single_locator(
    destructive_settings, respx_mock, make_context
):
    """A one-project delete must still send an array-shaped parameter."""
    route = respx_mock.delete(f"{BASE}/v2/projects").mock(return_value=httpx.Response(200))

    client = FossaClient(destructive_settings)
    await projects.delete_projects(make_context(client, destructive_settings), [PROJECT])
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("locators[]", PROJECT)]


@pytest.mark.asyncio
async def test_delete_projects_rejects_the_wildcard_and_empty_lists(
    destructive_settings, respx_mock, make_context
):
    client = FossaClient(destructive_settings)
    ctx = make_context(client, destructive_settings)

    with pytest.raises(ValueError, match="at least one project"):
        await projects.delete_projects(ctx, [])

    with pytest.raises(ValueError, match="wildcard"):
        await projects.delete_projects(ctx, ["all"])

    with pytest.raises(ValueError, match="blank"):
        await projects.delete_projects(ctx, [PROJECT, "   "])

    await client.aclose()
    assert respx_mock.calls.call_count == 0
