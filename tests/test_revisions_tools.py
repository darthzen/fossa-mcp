"""Endpoint contract tests for the revision tools.

Every tool asserts the method, the encoded path (by way of the respx route
matching it), the exact query pairs, and the exact JSON body where there is one.
The gated tools additionally assert that a refusal leaves zero HTTP calls
behind.

`tests/test_tools.py` already covers fossa_list_project_revisions.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaApiError, FossaWriteNotPermittedError
from fossa_mcp.tools import revisions

PROJECT = "git+github.com/acme/widget"
REVISION = "abc123"
FULL_REVISION = f"{PROJECT}${REVISION}"
ENCODED_REVISION = "git%2Bgithub.com%2Facme%2Fwidget%24abc123"
BASE = "https://app.fossa.com/api"

# The twelve shared attribution content flags, at the tools' defaults.
DEFAULT_REPORT_OPTIONS = [
    ("includeDeepDependencies", "true"),
    ("includeDirectDependencies", "true"),
    ("includeLicenseList", "true"),
    ("includeLicenseScan", "false"),
    ("includeProjectLicense", "true"),
    ("includeCopyrightList", "false"),
    ("includeFileMatches", "false"),
    ("includeOpenVulnerabilities", "false"),
    ("includeClosedVulnerabilities", "false"),
    ("includeDependencySummary", "true"),
    ("includeLicenseHeaders", "false"),
    ("includePackageLabels", "false"),
]


@pytest.fixture
def writable_settings() -> Settings:
    return Settings(fossa_api_token="test-token", fossa_allow_writes=True, _env_file=None)  # type: ignore[call-arg]


def _query_pairs(request: httpx.Request) -> list[tuple[str, str]]:
    return httpx.QueryParams(request.url.query.decode()).multi_items()


# --- scans -------------------------------------------------------------------


async def test_list_revision_scans_endpoint_and_query(
    settings, respx_mock, make_context, assert_raw_path
):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/scans").mock(
        return_value=httpx.Response(
            200, json={"results": [{"id": 5}], "page": 2, "pageSize": 25, "totalCount": 30}
        )
    )

    client = FossaClient(settings)
    result = await revisions.list_revision_scans(
        make_context(client, settings), PROJECT, REVISION, page=2, page_size=25
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    # Asserted on the bytes sent. Route matching proves nothing here: respx
    # normalizes both sides, so `git+github.com/acme/widget$abc123` unescaped
    # would match this route while addressing a completely different path.
    assert_raw_path(request, f"/revisions/{ENCODED_REVISION}/scans")
    assert _query_pairs(request) == [("page", "2"), ("pageSize", "25")]
    assert result["endpoint"] == "GET /revisions/{locator}/scans"
    assert result["data"]["totalCount"] == 30


async def test_list_revision_scans_accepts_a_full_revision_locator(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/scans").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    client = FossaClient(settings)
    await revisions.list_revision_scans(make_context(client, settings), PROJECT, FULL_REVISION)
    await client.aclose()

    assert route.called


async def test_list_revision_scans_rejects_oversized_page(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await revisions.list_revision_scans(
            make_context(client, settings), PROJECT, REVISION, page_size=51
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- notice files ------------------------------------------------------------


async def test_get_revision_notice_files_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/notice-files").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": 1, "path": "NOTICE.txt", "contents": "Apache", "copyrights": ["2024"]}],
        )
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_notice_files(
        make_context(client, settings), PROJECT, REVISION
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == []
    assert result["data"]["count"] == 1
    assert result["data"]["notice_files"][0]["contents"] == "Apache"
    assert result["data"]["truncated"] is False


async def test_get_revision_notice_files_can_drop_contents(settings, respx_mock, make_context):
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/notice-files").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "path": "NOTICE.txt", "contents": "x"}])
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_notice_files(
        make_context(client, settings), PROJECT, REVISION, include_contents=False
    )
    await client.aclose()

    assert "contents" not in result["data"]["notice_files"][0]
    assert result["data"]["contents_included"] is False


async def test_get_revision_notice_files_caps_total_contents(settings, respx_mock, make_context):
    settings = settings.model_copy(update={"fossa_report_max_chars": 1000})
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/notice-files").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "path": "a", "contents": "a" * 900},
                {"id": 2, "path": "b", "contents": "b" * 900},
            ],
        )
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_notice_files(
        make_context(client, settings), PROJECT, REVISION
    )
    await client.aclose()

    files = result["data"]["notice_files"]
    assert len(files[0]["contents"]) == 900
    assert len(files[1]["contents"]) == 100
    assert files[1]["contents_truncated"] is True
    assert result["data"]["truncated"] is True


# --- SBOM --------------------------------------------------------------------


async def test_get_revision_sbom_analysis(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/sbom-analysis").mock(
        return_value=httpx.Response(200, json={"sbomFile": {"status": "success"}})
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_sbom(make_context(client, settings), PROJECT, REVISION)
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == []
    assert result["endpoint"] == "GET /revisions/{locator}/sbom-analysis"
    assert result["data"]["sbomFile"]["status"] == "success"


async def test_get_revision_sbom_original_returns_redirect_target(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/original-sbom").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://s3.example.com/sbom.json"},
            text="Found. Redirecting to https://s3.example.com/sbom.json",
        )
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_sbom(
        make_context(client, settings), PROJECT, REVISION, part="original"
    )
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["ok"] is True
    assert result["endpoint"] == "GET /revisions/{locator}/original-sbom"
    assert result["data"]["status_code"] == 302
    assert result["data"]["download_url"] == "https://s3.example.com/sbom.json"


async def test_get_revision_sbom_original_returns_inline_document(
    settings, respx_mock, make_context
):
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/original-sbom").mock(
        return_value=httpx.Response(200, text='{"bomFormat":"CycloneDX"}')
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_sbom(
        make_context(client, settings), PROJECT, REVISION, part="original"
    )
    await client.aclose()

    assert result["data"]["status_code"] == 200
    assert result["data"]["content"] == '{"bomFormat":"CycloneDX"}'


async def test_get_revision_sbom_original_propagates_real_errors(
    settings, respx_mock, make_context
):
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/original-sbom").mock(
        return_value=httpx.Response(400, json={"message": "The revision is not associated"})
    )

    client = FossaClient(settings)
    with pytest.raises(FossaApiError):
        await revisions.get_revision_sbom(
            make_context(client, settings), PROJECT, REVISION, part="original"
        )
    await client.aclose()


# --- remediation guidance ----------------------------------------------------


async def test_get_revision_remediation_guidance_query_and_parse(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/report/remediation-guidance").mock(
        return_value=httpx.Response(
            200, text='{"quickWins": []}', headers={"content-type": "application/json"}
        )
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_remediation_guidance(
        make_context(client, settings),
        PROJECT,
        REVISION,
        exclude_low_priority=True,
        include_transitive_vulnerabilities=True,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("format", "JSON"),
        ("excludeQuickWins", "false"),
        ("excludeHighPriority", "false"),
        ("excludeLowPriority", "true"),
        ("excludeOutdatedDependencies", "false"),
        ("includeTransitiveVulns", "true"),
        ("deduplicateOutdatedDeps", "false"),
        ("includeMalware", "false"),
    ]
    assert result["data"]["content"] == {"quickWins": []}
    assert result["data"]["truncated"] is False


async def test_get_revision_remediation_guidance_html_is_left_as_text(
    settings, respx_mock, make_context
):
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/report/remediation-guidance").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_remediation_guidance(
        make_context(client, settings), PROJECT, REVISION, format="HTML"
    )
    await client.aclose()

    assert result["data"]["content"] == "<html></html>"
    assert "json_parse_error" not in result["data"]


# --- attribution JSON --------------------------------------------------------


async def test_get_revision_attribution_json_v2_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution/json").mock(
        return_value=httpx.Response(200, json={"dependencies": []})
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_attribution_json(
        make_context(client, settings),
        PROJECT,
        REVISION,
        include_notice_files=True,
        exclude_package_labels=["internal", "vendored"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("preview", "false"),
        ("includeDeepDependencies", "true"),
        ("includeHashAndVersionData", "false"),
        ("includeCopyrightList", "false"),
        ("includeFileMatches", "false"),
        ("includeOpenVulnerabilities", "false"),
        ("includeClosedVulnerabilities", "false"),
        ("includeNoticeFiles", "true"),
        ("includePackageLabels", "false"),
        ("excludeFields[packageLabels][0]", "internal"),
        ("excludeFields[packageLabels][1]", "vendored"),
    ]
    assert result["endpoint"] == "GET /v2/revisions/{locator}/attribution/json"


async def test_get_revision_attribution_json_v1_path(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/attribution/json").mock(
        return_value=httpx.Response(200, json={})
    )

    client = FossaClient(settings)
    result = await revisions.get_revision_attribution_json(
        make_context(client, settings), PROJECT, REVISION, api_version="v1"
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /revisions/{locator}/attribution/json"


async def test_get_revision_attribution_json_rejects_blank_exclude_label(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="blank"):
        await revisions.get_revision_attribution_json(
            make_context(client, settings), PROJECT, REVISION, exclude_package_labels=[" "]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- rendered attribution ----------------------------------------------------


async def test_render_revision_attribution_stream_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution").mock(
        return_value=httpx.Response(
            200, text="# Attribution", headers={"content-type": "text/markdown"}
        )
    )

    client = FossaClient(settings)
    result = await revisions.render_revision_attribution(
        make_context(client, settings), PROJECT, REVISION
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("format", "MD"),
        *DEFAULT_REPORT_OPTIONS,
        ("includeHashAndVersionData", "false"),
    ]
    assert result["endpoint"] == "GET /v2/revisions/{locator}/attribution"
    assert result["data"]["content"] == "# Attribution"
    assert result["data"]["content_type"] == "text/markdown"


async def test_render_revision_attribution_preview_path(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution/preview").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )

    client = FossaClient(settings)
    result = await revisions.render_revision_attribution(
        make_context(client, settings), PROJECT, REVISION, variant="preview", format="HTML"
    )
    await client.aclose()

    assert ("format", "HTML") in _query_pairs(route.calls.last.request)
    assert result["endpoint"] == "GET /v2/revisions/{locator}/attribution/preview"


async def test_render_revision_attribution_full_sends_no_options(
    settings, respx_mock, make_context
):
    route = respx_mock.get(
        f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution/full/SPDX_JSON"
    ).mock(return_value=httpx.Response(200, text='{"spdxVersion": "SPDX-2.3"}'))

    client = FossaClient(settings)
    result = await revisions.render_revision_attribution(
        make_context(client, settings), PROJECT, REVISION, variant="full", format="SPDX_JSON"
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /v2/revisions/{locator}/attribution/full/{format}"
    assert result["data"]["content"] == {"spdxVersion": "SPDX-2.3"}


async def test_render_revision_attribution_full_rejects_options(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="accepts no"):
        await revisions.render_revision_attribution(
            make_context(client, settings),
            PROJECT,
            REVISION,
            variant="full",
            include_copyright_list=True,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


async def test_render_revision_attribution_truncates(settings, respx_mock, make_context):
    settings = settings.model_copy(update={"fossa_report_max_chars": 1000})
    respx_mock.get(f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution").mock(
        return_value=httpx.Response(200, text="x" * 2000)
    )

    client = FossaClient(settings)
    result = await revisions.render_revision_attribution(
        make_context(client, settings), PROJECT, REVISION
    )
    await client.aclose()

    assert result["data"]["truncated"] is True
    assert result["data"]["original_char_count"] == 2000
    assert len(result["data"]["content"]) == 1000


# --- legacy dependencies -----------------------------------------------------


async def test_list_revision_dependencies_v1_get_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/dependencies").mock(
        return_value=httpx.Response(200, json=[{"locator": "npm+lodash$4.17.21"}])
    )

    client = FossaClient(settings)
    result = await revisions.list_revision_dependencies_v1(
        make_context(client, settings),
        PROJECT,
        REVISION,
        limit=50,
        offset=25,
        dependency_locators=["npm+lodash$4.17.21"],
        include_license_text=True,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("limit", "50"),
        ("offset", "25"),
        ("include_ignored", "false"),
        ("includeHashData", "false"),
        ("include_license_text", "true"),
        # Plain repeated parameter, not the bracketed form the v2 paths use.
        ("includeLocators", "npm+lodash$4.17.21"),
    ]
    assert result["endpoint"] == "GET /revisions/{locator}/dependencies"


async def test_list_revision_dependencies_v1_switches_to_post_for_long_lists(
    settings, respx_mock, make_context
):
    locators = [f"npm+package-number-{index}$1.0.0" for index in range(100)]
    route = respx_mock.post(f"{BASE}/revisions/{ENCODED_REVISION}/list-dependencies").mock(
        return_value=httpx.Response(200, json=[])
    )

    client = FossaClient(settings)
    result = await revisions.list_revision_dependencies_v1(
        make_context(client, settings), PROJECT, REVISION, dependency_locators=locators
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _query_pairs(request) == []
    assert json.loads(request.content) == {
        "limit": 100,
        "offset": 0,
        "include_ignored": False,
        "includeHashData": False,
        "include_license_text": False,
        "includeLocators": locators,
    }
    assert result["endpoint"] == "POST /revisions/{locator}/list-dependencies"


async def test_list_revision_dependencies_v1_forced_post_body(settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/revisions/{ENCODED_REVISION}/list-dependencies").mock(
        return_value=httpx.Response(200, json=[])
    )

    client = FossaClient(settings)
    await revisions.list_revision_dependencies_v1(
        make_context(client, settings), PROJECT, REVISION, transport="post", include_ignored=True
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "limit": 100,
        "offset": 0,
        "include_ignored": True,
        "includeHashData": False,
        "include_license_text": False,
    }


async def test_list_revision_dependencies_v1_rejects_unclamped_limit(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await revisions.list_revision_dependencies_v1(
            make_context(client, settings), PROJECT, REVISION, limit=10
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- write gate --------------------------------------------------------------


async def test_update_revision_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await revisions.update_revision(
            make_context(client, settings), PROJECT, REVISION, author="rick"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


async def test_email_attribution_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await revisions.email_revision_attribution(
            make_context(client, settings), PROJECT, REVISION
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


async def test_public_report_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await revisions.create_public_attribution_report(
            make_context(client, settings), PROJECT, REVISION
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- writes ------------------------------------------------------------------


async def test_update_revision_sends_only_the_fields_given(
    writable_settings, respx_mock, make_context, assert_raw_path
):
    route = respx_mock.patch(f"{BASE}/revisions/{ENCODED_REVISION}").mock(
        return_value=httpx.Response(200, json={"locator": FULL_REVISION})
    )

    client = FossaClient(writable_settings)
    result = await revisions.update_revision(
        make_context(client, writable_settings),
        PROJECT,
        REVISION,
        author="rick@theashfords.org",
        link="https://ci.example.com/build/12",
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PATCH"
    assert_raw_path(request, f"/revisions/{ENCODED_REVISION}")
    assert _query_pairs(request) == []
    assert json.loads(request.content) == {
        "link": "https://ci.example.com/build/12",
        "author": "rick@theashfords.org",
    }
    assert result["endpoint"] == "PATCH /revisions/{locator}"
    assert result["data"]["revision_locator"] == FULL_REVISION


async def test_update_revision_requires_at_least_one_field(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="at least one"):
        await revisions.update_revision(make_context(client, writable_settings), PROJECT, REVISION)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


async def test_email_revision_attribution_query(writable_settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution/email").mock(
        return_value=httpx.Response(200, json={"task": {"id": 3, "status": "queued"}})
    )

    client = FossaClient(writable_settings)
    result = await revisions.email_revision_attribution(
        make_context(client, writable_settings), PROJECT, REVISION
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("preview", "false"),
        ("format", "PDF"),
        *DEFAULT_REPORT_OPTIONS,
    ]
    assert result["endpoint"] == "GET /v2/revisions/{locator}/attribution/email"
    assert result["data"]["task"]["status"] == "queued"


async def test_email_revision_attribution_v1_path(writable_settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/attribution/email").mock(
        return_value=httpx.Response(200, json={})
    )

    client = FossaClient(writable_settings)
    result = await revisions.email_revision_attribution(
        make_context(client, writable_settings), PROJECT, REVISION, api_version="v1", format="MD"
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /revisions/{locator}/attribution/email"


async def test_create_public_attribution_report_query_and_202(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/v2/revisions/{ENCODED_REVISION}/attribution/public").mock(
        return_value=httpx.Response(
            202, json={"report": {"uuid": "abc"}, "task": {"id": 9, "status": "queued"}}
        )
    )

    client = FossaClient(writable_settings)
    result = await revisions.create_public_attribution_report(
        make_context(client, writable_settings),
        PROJECT,
        REVISION,
        recipient_email="rick@theashfords.org",
        exclude_package_labels=["internal"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert request.content == b""
    assert _query_pairs(request) == [
        ("format", "HTML"),
        ("emails", "rick@theashfords.org"),
        *DEFAULT_REPORT_OPTIONS,
        ("excludeFields[packageLabels][0]", "internal"),
    ]
    assert result["data"]["status_code"] == 202
    assert result["data"]["queued"] is True
    assert result["data"]["report"]["report"]["uuid"] == "abc"


async def test_create_public_attribution_report_rejects_bad_email(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="email address"):
        await revisions.create_public_attribution_report(
            make_context(client, writable_settings), PROJECT, REVISION, recipient_email="nope"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0
