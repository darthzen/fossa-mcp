"""Tests for the composite `fossa_project_posture` tool."""

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
    respx_mock.get("https://app.fossa.com/api/v2/revisions/r/dependencies").mock(
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
    assert result.revision_locator == "r"
    assert result.issue_counts == {"licensing": 2, "vulnerability": 5, "quality": 1}
    assert result.top_vulnerability_issues == [{"id": 1, "severity": "critical"}]
    assert result.top_licensing_issues == [{"id": 2}]
    assert result.top_quality_issues == [{"id": 3}]
    assert result.direct_dependencies_with_issues == [{"id": "dep1"}]
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
    respx_mock.get("https://app.fossa.com/api/v2/revisions/r/dependencies").mock(
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
    respx_mock.get("https://app.fossa.com/api/v2/revisions/r/dependencies").mock(
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
