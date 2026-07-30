"""Tests for the composite `fossa_project_posture` tool."""

import asyncio
from urllib.parse import quote

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.errors import FossaApiError
from fossa_mcp.tools import posture


def _mock_all_success(respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/issues/categories").mock(
        return_value=httpx.Response(200, json={"licensing": 2, "vulnerability": 5, "quality": 1})
    )
    respx_mock.get(
        "https://app.fossa.com/api/v2/issues", params={"category": "vulnerability"}
    ).mock(return_value=httpx.Response(200, json={"issues": [{"id": 1, "severity": "critical"}]}))
    respx_mock.get("https://app.fossa.com/api/v2/issues", params={"category": "licensing"}).mock(
        return_value=httpx.Response(200, json={"issues": [{"id": 2}]})
    )
    respx_mock.get("https://app.fossa.com/api/v2/issues", params={"category": "quality"}).mock(
        return_value=httpx.Response(200, json={"issues": [{"id": 3}]})
    )
    # Full locator in the path: project "p" + revision "r" -> "p$r".
    respx_mock.get("https://app.fossa.com/api/v2/revisions/p%24r/dependencies").mock(
        return_value=httpx.Response(200, json={"dependencies": [{"id": "dep1"}]})
    )


@pytest.mark.asyncio
async def test_posture_makes_exactly_five_calls_and_maps_fields(settings, respx_mock, make_context):
    _mock_all_success(respx_mock)
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await posture.project_posture(ctx, project_locator="p", revision_locator="r")
    await client.aclose()

    assert respx_mock.calls.call_count == 5
    assert result.ok is True
    assert result.project_locator == "p"
    assert result.revision_locator == "p$r"
    assert result.issue_counts == {"licensing": 2, "vulnerability": 5, "quality": 1}
    assert result.top_vulnerability_issues == [{"id": 1, "severity": "critical"}]
    assert result.top_licensing_issues == [{"id": 2}]
    assert result.top_quality_issues == [{"id": 3}]
    assert result.direct_dependencies_with_issues == [{"id": "dep1"}]
    assert result.analysis_state == "complete"


@pytest.mark.asyncio
async def test_posture_upstream_query_parameters(settings, respx_mock, make_context):
    _mock_all_success(respx_mock)
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await posture.project_posture(ctx, project_locator="p", revision_locator="r", top_issue_count=7)
    await client.aclose()

    by_path: dict[str, list[list[tuple[str, str]]]] = {}
    for call in respx_mock.calls:
        pairs = httpx.QueryParams(call.request.url.query.decode()).multi_items()
        by_path.setdefault(call.request.url.path, []).append(pairs)

    scope = [("scope[type]", "project"), ("scope[id]", "p"), ("scope[revision]", "r")]

    categories = by_path["/api/v2/issues/categories"][0]
    assert categories == scope

    issue_calls = {dict(p)["category"]: p for p in by_path["/api/v2/issues"]}
    assert set(issue_calls) == {"vulnerability", "licensing", "quality"}
    for category, expected_sort in [
        ("vulnerability", "severity_desc"),
        ("licensing", "created_at_desc"),
        ("quality", "created_at_desc"),
    ]:
        pairs = issue_calls[category]
        assert ("status", "active") in pairs
        assert all(item in pairs for item in scope)
        assert ("sort", expected_sort) in pairs
        assert ("page", "1") in pairs
        assert ("count", "7") in pairs

    deps = by_path["/api/v2/revisions/p$r/dependencies"][0]
    assert ("depth[]", "direct") in deps
    assert ("hasIssues[]", "hasIssues") in deps
    assert ("page", "1") in deps
    assert ("count", "7") in deps


@pytest.mark.asyncio
async def test_posture_sends_bare_revision_to_issues_and_full_locator_to_dependencies(
    settings, respx_mock, make_context
):
    """The two endpoint families need different forms of the same revision.

    Regression test for a 404-on-everything bug: `scope[revision]` must carry the
    bare revision id (FOSSA appends it to `scope[id]` itself) while the
    dependencies path parameter must carry the full locator. Passing one form to
    both makes this tool fail whichever value the caller supplies.
    """
    project = "git+github.com/acme/widget"
    sha = "abc123"
    full = f"{project}${sha}"

    respx_mock.get("https://app.fossa.com/api/v2/issues/categories").mock(
        return_value=httpx.Response(200, json={"licensing": 0, "vulnerability": 0, "quality": 0})
    )
    respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    deps = respx_mock.get(
        f"https://app.fossa.com/api/v2/revisions/{quote(full, safe='')}/dependencies"
    ).mock(return_value=httpx.Response(200, json={"dependencies": []}))

    client = FossaClient(settings)
    ctx = make_context(client, settings)

    # Both input forms must behave identically.
    for supplied in (full, sha):
        result = await posture.project_posture(
            ctx, project_locator=project, revision_locator=supplied
        )
        assert result.revision_locator == full, supplied

    await client.aclose()

    for call in respx_mock.calls:
        if call.request.url.path == "/api/v2/issues" or call.request.url.path.endswith(
            "/categories"
        ):
            pairs = httpx.QueryParams(call.request.url.query.decode())
            assert pairs["scope[revision]"] == sha
            assert pairs["scope[id]"] == project
    assert deps.call_count == 2


@pytest.mark.asyncio
async def test_posture_upstream_calls_run_concurrently(settings, respx_mock, make_context):
    """All five upstream calls must be in flight together, not issued serially.

    Each mocked handler waits until the fifth request has arrived. Sequential
    execution can never reach five in flight, so it fails on the barrier
    timeout instead of quietly passing.
    """
    in_flight = 0
    all_arrived = asyncio.Event()

    async def barrier(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight
        in_flight += 1
        if in_flight == 5:
            all_arrived.set()
        await asyncio.wait_for(all_arrived.wait(), timeout=5)
        if request.url.path.endswith("/categories"):
            return httpx.Response(200, json={"licensing": 0, "vulnerability": 0, "quality": 0})
        if request.url.path.endswith("/dependencies"):
            return httpx.Response(200, json={"dependencies": []})
        return httpx.Response(200, json={"issues": []})

    respx_mock.get(url__startswith="https://app.fossa.com/api/").mock(side_effect=barrier)

    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await posture.project_posture(ctx, project_locator="p", revision_locator="r")
    await client.aclose()

    assert in_flight == 5
    assert result.analysis_state == "complete"


@pytest.mark.asyncio
async def test_posture_in_progress_when_any_issue_call_returns_202(
    settings, respx_mock, make_context
):
    respx_mock.get("https://app.fossa.com/api/v2/issues/categories").mock(
        return_value=httpx.Response(202, json={})
    )
    respx_mock.get(
        "https://app.fossa.com/api/v2/issues", params={"category": "vulnerability"}
    ).mock(return_value=httpx.Response(200, json={"issues": []}))
    respx_mock.get("https://app.fossa.com/api/v2/issues", params={"category": "licensing"}).mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    respx_mock.get("https://app.fossa.com/api/v2/issues", params={"category": "quality"}).mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    respx_mock.get("https://app.fossa.com/api/v2/revisions/p%24r/dependencies").mock(
        return_value=httpx.Response(200, json={"dependencies": []})
    )

    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await posture.project_posture(ctx, project_locator="p", revision_locator="r")
    await client.aclose()

    assert result.analysis_state == "in_progress"
    # No categories were discarded silently; missing keys default to 0.
    assert result.issue_counts == {"licensing": 0, "vulnerability": 0, "quality": 0}


@pytest.mark.asyncio
async def test_posture_fails_entirely_on_401(settings, respx_mock, make_context):
    respx_mock.get("https://app.fossa.com/api/v2/issues/categories").mock(
        return_value=httpx.Response(401, json={"message": "no token"})
    )
    respx_mock.get(
        "https://app.fossa.com/api/v2/issues", params={"category": "vulnerability"}
    ).mock(return_value=httpx.Response(200, json={"issues": []}))
    respx_mock.get("https://app.fossa.com/api/v2/issues", params={"category": "licensing"}).mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    respx_mock.get("https://app.fossa.com/api/v2/issues", params={"category": "quality"}).mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    respx_mock.get("https://app.fossa.com/api/v2/revisions/p%24r/dependencies").mock(
        return_value=httpx.Response(200, json={"dependencies": []})
    )

    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(FossaApiError) as excinfo:
        await posture.project_posture(ctx, project_locator="p", revision_locator="r")
    await client.aclose()

    assert excinfo.value.status_code == 401


@pytest.mark.asyncio
async def test_posture_validates_top_issue_count_bounds(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(ValueError):
        await posture.project_posture(
            ctx, project_locator="p", revision_locator="r", top_issue_count=26
        )
    await client.aclose()
    assert respx_mock.calls.call_count == 0
