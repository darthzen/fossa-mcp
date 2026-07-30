"""Tests for `fossa_get_attribution_report`."""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.tools import reports

_URL = "https://app.fossa.com/api/v2/revisions/rev/attribution/download"


@pytest.mark.asyncio
async def test_markdown_report(settings, respx_mock, make_context):
    respx_mock.get(_URL).mock(
        return_value=httpx.Response(
            200, text="# Attribution\n...", headers={"content-type": "text/markdown"}
        )
    )
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="MD")
    await client.aclose()

    data = result
    assert data["ok"] is True
    assert data["format"] == "MD"
    assert data["truncated"] is False
    assert data["content"] == "# Attribution\n..."


@pytest.mark.asyncio
async def test_report_query_keys_match_fossa_contract(settings, respx_mock, make_context):
    route = respx_mock.get(_URL).mock(return_value=httpx.Response(200, text="# Attribution"))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    await reports.get_attribution_report(ctx, revision_locator="rev", format="MD")
    await client.aclose()

    pairs = dict(httpx.QueryParams(route.calls.last.request.url.query.decode()).multi_items())
    assert pairs == {
        "format": "MD",
        # Defaults per scope §13.9: cheap/summary fields on, full-text fields off.
        "includeDeepDependencies": "true",
        "includeDirectDependencies": "true",
        "includeLicenseList": "true",
        "includeLicenseScan": "false",
        "includeProjectLicense": "true",
        "includeCopyrightList": "false",
        "includeFileMatches": "false",
        "includeOpenVulnerabilities": "false",
        "includeClosedVulnerabilities": "false",
        "includeDependencySummary": "true",
        "includeLicenseHeaders": "false",
        "includePackageLabels": "false",
        "includeHashAndVersionData": "false",
    }


@pytest.mark.asyncio
async def test_report_result_is_flat_not_nested_under_data(settings, respx_mock, make_context):
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text="# Attribution"))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="MD")
    await client.aclose()

    # Scope §13.9 puts report fields at the top level of the tool result.
    assert "data" not in result
    assert result["format"] == "MD"
    assert result["content"] == "# Attribution"


@pytest.mark.asyncio
async def test_txt_report(settings, respx_mock, make_context):
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text="plain text report"))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="TXT")
    await client.aclose()

    assert result["content"] == "plain text report"


@pytest.mark.asyncio
async def test_valid_spdx_json(settings, respx_mock, make_context):
    payload = {"spdxVersion": "SPDX-2.3", "packages": []}
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text=json.dumps(payload)))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="SPDX_JSON")
    await client.aclose()

    data = result
    assert data["content"] == payload
    assert "json_parse_error" not in data


@pytest.mark.asyncio
async def test_valid_cyclonedx_json(settings, respx_mock, make_context):
    payload = {"bomFormat": "CycloneDX", "components": []}
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text=json.dumps(payload)))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(
        ctx, revision_locator="rev", format="CYCLONEDX_JSON"
    )
    await client.aclose()

    assert result["content"] == payload


@pytest.mark.asyncio
async def test_malformed_json_falls_back_to_text(settings, respx_mock, make_context):
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text="{not valid json"))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="SPDX_JSON")
    await client.aclose()

    data = result
    assert data["json_parse_error"] is True
    assert data["content"] == "{not valid json"


@pytest.mark.asyncio
async def test_truncation_sets_flag_and_original_char_count(respx_mock, make_context):
    settings = Settings(
        fossa_api_token="test-token",
        fossa_report_max_chars=1000,
        _env_file=None,  # type: ignore[call-arg]
    )
    long_text = "x" * 5000
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text=long_text))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="TXT")
    await client.aclose()

    data = result
    assert data["truncated"] is True
    assert data["original_char_count"] == 5000
    assert len(data["content"]) == 1000


@pytest.mark.asyncio
async def test_truncation_applies_to_json_formats_too(respx_mock, make_context):
    settings = Settings(
        fossa_api_token="test-token",
        fossa_report_max_chars=1000,
        _env_file=None,  # type: ignore[call-arg]
    )
    long_json_text = json.dumps({"packages": [{"name": f"pkg-{i}"} for i in range(500)]})
    assert len(long_json_text) > 1000
    respx_mock.get(_URL).mock(return_value=httpx.Response(200, text=long_json_text))
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    result = await reports.get_attribution_report(ctx, revision_locator="rev", format="SPDX_JSON")
    await client.aclose()

    data = result
    assert data["truncated"] is True
    assert data["original_char_count"] == len(long_json_text)
