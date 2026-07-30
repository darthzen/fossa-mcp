"""Endpoint contract tests for the direct (non-composite) FOSSA MCP tools.

For each tool, verify HTTP method, exact URL path, exact query keys/values
(including repeated bracketed params and omission of unset/empty filters),
the standard result envelope, and that raw FOSSA response fields survive
untouched.
"""

from datetime import datetime

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.tools import dependencies, issues, projects, revisions


def _query_pairs(request: httpx.Request) -> list[tuple[str, str]]:
    return httpx.QueryParams(request.url.query.decode()).multi_items()


@pytest.mark.asyncio
async def test_list_projects_endpoint_and_query(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(200, json={"projects": [{"id": 1, "extraField": "keep-me"}]})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await projects.list_projects(
        ctx, types=["container", "sbom"], sort="issues-security_desc", page=2, count=5
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert route.calls.last.request.url.path == "/api/v2/projects"
    pairs = _query_pairs(route.calls.last.request)
    assert ("type[]", "container") in pairs
    assert ("type[]", "sbom") in pairs
    assert ("sort", "issues-security_desc") in pairs
    assert ("page", "2") in pairs
    assert ("count", "5") in pairs

    assert result["ok"] is True
    assert result["endpoint"] == "GET /v2/projects"
    assert result["data"]["projects"][0]["extraField"] == "keep-me"


@pytest.mark.asyncio
async def test_list_projects_omits_empty_and_none_filters(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(200, json={"projects": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await projects.list_projects(ctx, types=[], labels=None)
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    keys = {k for k, _ in pairs}
    assert "type[]" not in keys
    assert "labels[]" not in keys


@pytest.mark.asyncio
async def test_list_projects_rejects_count_over_max_page_size_before_request(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(ValueError):
        await projects.list_projects(ctx, count=settings.fossa_max_page_size + 1)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_get_project_encodes_locator_once(settings, respx_mock, make_context):
    locator = "git+github.com/acme/widget"
    route = respx_mock.get(
        "https://app.fossa.com/api/projects/git%2Bgithub.com%2Facme%2Fwidget"
    ).mock(return_value=httpx.Response(200, json={"title": "widget"}))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await projects.get_project(ctx, project_locator=locator)
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["data"]["title"] == "widget"


@pytest.mark.asyncio
async def test_get_project_sends_snake_case_ref_type(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/projects/proj").mock(
        return_value=httpx.Response(200, json={"title": "widget"})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await projects.get_project(ctx, project_locator="proj", ref="v1.2", ref_type="tag")
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    # getProject documents `ref_type`; `refType` is silently ignored by FOSSA,
    # which would resolve a tag ref as a branch.
    assert ("ref", "v1.2") in pairs
    assert ("ref_type", "tag") in pairs
    assert "refType" not in {k for k, _ in pairs}


@pytest.mark.asyncio
async def test_get_project_omits_ref_params_when_ref_unset(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/projects/proj").mock(
        return_value=httpx.Response(200, json={"title": "widget"})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await projects.get_project(ctx, project_locator="proj")
    await client.aclose()

    keys = {k for k, _ in _query_pairs(route.calls.last.request)}
    assert "ref" not in keys
    assert "ref_type" not in keys


@pytest.mark.asyncio
async def test_get_project_blank_locator_rejected(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)
    with pytest.raises(ValueError):
        await projects.get_project(ctx, project_locator="")
    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_list_project_revisions_refs_repeated(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/projects/proj/revisions").mock(
        return_value=httpx.Response(200, json={"revisions": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await revisions.list_project_revisions(ctx, project_locator="proj", refs=["main", "develop"])
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("refs[]", "main") in pairs
    assert ("refs[]", "develop") in pairs
    assert ("resolved", "true") in pairs
    assert ("isMinimal", "true") in pairs


@pytest.mark.asyncio
async def test_list_dependencies_endpoint_and_defaults(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/revisions/rev/dependencies").mock(
        return_value=httpx.Response(200, json={"dependencies": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await dependencies.list_dependencies(ctx, revision_locator="rev")
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("includeLicenseText", "false") in pairs
    assert ("includeResolutionNotes", "false") in pairs
    assert ("page", "1") in pairs
    assert ("count", "20") in pairs


@pytest.mark.asyncio
async def test_get_dependency_encodes_both_locators(settings, respx_mock, make_context):
    route = respx_mock.get(
        "https://app.fossa.com/api/v2/revisions/rev%241/dependencies/dep%242"
    ).mock(return_value=httpx.Response(200, json={"title": "dep"}))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await dependencies.get_dependency(
        ctx, revision_locator="rev$1", dependency_revision_locator="dep$2"
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["data"]["title"] == "dep"


@pytest.mark.asyncio
async def test_list_issues_severity_repeated_and_scope(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": [{"id": 1}]})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await issues.list_issues(
        ctx,
        category="vulnerability",
        scope_type="project",
        project_locator="p",
        revision_locator="r",
        severity=["critical", "high"],
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("filter[severity][]", "critical") in pairs
    assert ("filter[severity][]", "high") in pairs
    assert ("scope[type]", "project") in pairs
    assert ("scope[id]", "p") in pairs
    assert ("scope[revision]", "r") in pairs
    assert result["data"]["issues"][0]["id"] == 1


@pytest.mark.asyncio
async def test_list_issues_revision_comparison_query(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await issues.list_issues(
        ctx,
        category="vulnerability",
        scope_type="project",
        project_locator="p",
        revision_locator="new-rev",
        compare_to_revision="old-rev",
        change_status="new",
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("scope[revision]", "new-rev") in pairs
    assert ("scope[compareTo][revision]", "old-rev") in pairs
    assert ("scope[compareTo][changeStatus]", "new") in pairs


@pytest.mark.asyncio
async def test_list_issues_comparison_revision_is_also_normalized(
    settings, respx_mock, make_context
):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    project = "git+github.com/acme/widget"
    await issues.list_issues(
        ctx,
        category="vulnerability",
        scope_type="project",
        project_locator=project,
        revision_locator=f"{project}$new",
        compare_to_revision=f"{project}$old",
        change_status="new",
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("scope[revision]", "new") in pairs
    assert ("scope[compareTo][revision]", "old") in pairs


@pytest.mark.asyncio
@pytest.mark.parametrize("supplied_revision", ["git+github.com/acme/widget$abc123", "abc123"])
async def test_list_issues_scope_revision_is_the_bare_revision_id(
    settings, respx_mock, make_context, supplied_revision
):
    """FOSSA builds scope[id] + '$' + scope[revision] itself.

    Sending the full locator as scope[revision] yields
    `...widget$git+github.com/acme/widget$abc123` and a 404, so both the full
    locator and a bare revision id must normalize to the bare id here.
    """
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await issues.list_issues(
        ctx,
        category="vulnerability",
        scope_type="project",
        project_locator="git+github.com/acme/widget",
        revision_locator=supplied_revision,
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("scope[id]", "git+github.com/acme/widget") in pairs
    assert ("scope[revision]", "abc123") in pairs


@pytest.mark.asyncio
async def test_get_issue_scope_revision_is_the_bare_revision_id(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues/42").mock(
        return_value=httpx.Response(200, json={"id": 42})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await issues.get_issue(
        ctx,
        issue_id=42,
        category="vulnerability",
        scope_type="project",
        project_locator="git+github.com/acme/widget",
        revision_locator="git+github.com/acme/widget$abc123",
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("scope[revision]", "abc123") in pairs


@pytest.mark.asyncio
async def test_list_issues_filter_keys_and_iso_dates(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await issues.list_issues(
        ctx,
        category="licensing",
        issue_ids=[7, 9],
        search="log4j",
        depths=["direct", "deep"],
        issue_types=["policy_conflict"],
        package_managers=["npm"],
        project_labels=["prod"],
        found_after=datetime(2026, 1, 2, 3, 4, 5),
        sort="created_at_desc",
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("ids[]", "7") in pairs
    assert ("ids[]", "9") in pairs
    assert ("filter[search]", "log4j") in pairs
    assert ("filter[depths][]", "direct") in pairs
    assert ("filter[depths][]", "deep") in pairs
    assert ("filter[type][]", "policy_conflict") in pairs
    assert ("filter[packageManagers][]", "npm") in pairs
    assert ("filter[projectLabels][]", "prod") in pairs
    assert ("filter[foundAfter]", "2026-01-02T03:04:05") in pairs
    assert ("sort", "created_at_desc") in pairs


@pytest.mark.asyncio
async def test_list_issues_global_scope_rejects_project_locator(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)
    with pytest.raises(ValueError):
        await issues.list_issues(ctx, category="licensing", project_locator="p")
    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_list_issues_202_reports_analysis_in_progress(settings, respx_mock, make_context):
    respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(202, json={"message": "still scanning"})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await issues.list_issues(ctx, category="licensing")
    await client.aclose()

    assert result["ok"] is True
    assert result["state"] == "analysis_in_progress"
    assert result["message"] == "still scanning"


@pytest.mark.asyncio
async def test_get_issue_global_scope(settings, respx_mock, make_context):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues/42").mock(
        return_value=httpx.Response(200, json={"id": 42})
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await issues.get_issue(ctx, issue_id=42, category="quality")
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("scope[type]", "global") in pairs
    assert result["data"]["id"] == 42
