"""Endpoint contract tests for the integration and configuration tools.

Covers the HTTP shape of every Jira, fossabot, report option, custom risk score
and snippet operation the server exposes: the exact path each one calls, the
exact query pairs and JSON body it sends, the redaction that keeps Jira
credentials out of tool output, and the refusal path that must fire before any
request leaves the process when a tool's write tier is off.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import integrations

BASE = "https://app.fossa.com/api"

PROJECT = "git+github.com/acme/widget"
ENCODED_PROJECT = "git%2Bgithub.com%2Facme%2Fwidget"
REVISION = "abc123"
FULL_REVISION = f"{PROJECT}${REVISION}"
ENCODED_REVISION = f"{ENCODED_PROJECT}%24{REVISION}"
OLDER_REVISION = "def456"
ENCODED_OLDER_REVISION = f"{ENCODED_PROJECT}%24{OLDER_REVISION}"


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


def _body(request: httpx.Request) -> dict:
    return json.loads(request.content)


# --- Jira: reads and redaction ----------------------------------------------

# A configuration as FOSSA returns it, credentials and all. Every test that
# touches it asserts none of this reaches tool output.
JIRA_CONFIG = {
    "id": 3,
    "organizationId": 1000,
    "name": "Acme Jira",
    "enabled": True,
    "base_url": "https://jira.acme.example",
    "webhookURL": "https://app.fossa.com/api/jira/webhook/s3cr3t-capability-token",
    "credentials": {"basic": {"username": "fossa-svc", "password": "hunter2"}},
    "headers": {"x-atlassian-token": "no-check", "authorization": "Bearer s3cr3t"},
    "jiraProjectIds": ["ENG"],
}

SECRET_STRINGS = ("hunter2", "fossa-svc", "Bearer s3cr3t", "s3cr3t-capability-token")


@pytest.mark.asyncio
async def test_get_jira_configurations_redacts_every_credential_bearing_field(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/jira").mock(
        return_value=httpx.Response(200, json=[JIRA_CONFIG])
    )

    client = FossaClient(settings)
    result = await integrations.get_jira_configurations(make_context(client, settings))
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["endpoint"] == "GET /jira"

    configuration = result["data"]["configurations"][0]
    assert configuration["name"] == "Acme Jira"
    assert configuration["base_url"] == "https://jira.acme.example"
    assert "credentials" not in configuration
    assert "headers" not in configuration
    assert "webhookURL" not in configuration
    assert configuration["credentials_redacted"] == {"username_set": True, "password_set": True}
    assert configuration["headers_redacted"] == {
        "header_names": ["authorization", "x-atlassian-token"]
    }
    assert configuration["webhook_url_set"] is True

    serialized = json.dumps(result)
    for secret in SECRET_STRINGS:
        assert secret not in serialized


@pytest.mark.asyncio
async def test_get_jira_configurations_reports_absent_credentials_as_absent(
    settings, respx_mock, make_context
):
    respx_mock.get(f"{BASE}/jira").mock(
        return_value=httpx.Response(200, json=[{"id": 4, "name": "Unconfigured"}])
    )

    client = FossaClient(settings)
    result = await integrations.get_jira_configurations(make_context(client, settings))
    await client.aclose()

    configuration = result["data"]["configurations"][0]
    assert configuration["credentials_redacted"] == {"username_set": False, "password_set": False}
    assert configuration["headers_redacted"] == {"header_names": []}
    assert configuration["webhook_url_set"] is False


# --- Jira: writes ------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_jira_configuration_creates_with_post(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/jira").mock(return_value=httpx.Response(201, json=JIRA_CONFIG))

    client = FossaClient(writable_settings)
    result = await integrations.save_jira_configuration(
        make_context(client, writable_settings),
        name="Acme Jira",
        enabled=True,
        base_url="https://jira.acme.example",
        username="fossa-svc",
        password="hunter2",
        headers={"authorization": "Bearer s3cr3t"},
        components=[{"id": "10001", "displayName": "Platform"}],
        custom_fields={"12345": {"fieldId": "12345", "displayName": "Team", "isRequired": True}},
        jira_project_ids=["ENG"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _body(request) == {
        "name": "Acme Jira",
        "enabled": True,
        "base_url": "https://jira.acme.example",
        "credentials": {"basic": {"username": "fossa-svc", "password": "hunter2"}},
        "headers": {"authorization": "Bearer s3cr3t"},
        "components": [{"id": "10001", "displayName": "Platform"}],
        "jiraProjectIds": ["ENG"],
        "customFields": {
            "12345": {
                "fieldId": "12345",
                "displayName": "Team",
                "isRequired": True,
                "defaultValue": None,
            }
        },
    }

    assert result["endpoint"] == "POST /jira"
    serialized = json.dumps(result)
    for secret in SECRET_STRINGS:
        assert secret not in serialized


@pytest.mark.asyncio
async def test_save_jira_configuration_updates_with_patch_and_tolerates_204(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.patch(f"{BASE}/jira/3").mock(return_value=httpx.Response(204))

    client = FossaClient(writable_settings)
    result = await integrations.save_jira_configuration(
        make_context(client, writable_settings),
        jira_id=3,
        enabled=False,
        clear_fields=["headers", "defaultSecurityProject"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PATCH"
    assert _body(request) == {
        "enabled": False,
        "headers": None,
        "defaultSecurityProject": None,
    }
    assert result["endpoint"] == "PATCH /jira/{id}"
    assert result["data"]["configuration"] is None


@pytest.mark.asyncio
async def test_save_jira_configuration_rejects_a_half_credential(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="together"):
        await integrations.save_jira_configuration(
            make_context(client, writable_settings), name="Acme", username="fossa-svc"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_save_jira_configuration_rejects_setting_and_clearing_one_field(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="set and clear"):
        await integrations.save_jira_configuration(
            make_context(client, writable_settings),
            jira_id=3,
            base_url="https://jira.acme.example",
            clear_fields=["base_url"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_jira_configuration_reports_fossas_own_verdict(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/jira/3").mock(
        return_value=httpx.Response(200, json={"id": 3, "deleted": False})
    )

    client = FossaClient(destructive_settings)
    result = await integrations.delete_jira_configuration(
        make_context(client, destructive_settings), 3
    )
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /jira/{id}"
    assert result["data"]["deleted"] is False


# --- fossabot ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_fossabot_status_without_a_project_sends_no_query(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/fossabot/status").mock(
        return_value=httpx.Response(200, json={"connected": True, "creditLevel": "available"})
    )

    client = FossaClient(settings)
    result = await integrations.get_fossabot_status(make_context(client, settings))
    await client.aclose()

    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == "GET /fossabot/status"


@pytest.mark.asyncio
async def test_get_fossabot_status_scopes_to_a_project(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/fossabot/status").mock(
        return_value=httpx.Response(200, json={"connected": False})
    )

    client = FossaClient(settings)
    await integrations.get_fossabot_status(make_context(client, settings), PROJECT)
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("projectLocator", PROJECT)]


@pytest.mark.asyncio
async def test_list_fossabot_upgrade_prs_sends_the_forward_cursor(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/fossabot/dependency-upgrade-prs").mock(
        return_value=httpx.Response(200, json={"nodes": [], "pageInfo": {}})
    )

    client = FossaClient(settings)
    result = await integrations.list_fossabot_upgrade_prs(
        make_context(client, settings),
        PROJECT,
        first=25,
        after="cursor-1",
        state="open",
        search="lodash",
        sort="newest",
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _query_pairs(route.calls.last.request) == [
        ("projectLocator", PROJECT),
        ("first", "25"),
        ("after", "cursor-1"),
        ("state", "open"),
        ("search", "lodash"),
        ("sort", "newest"),
    ]
    assert result["endpoint"] == "GET /fossabot/dependency-upgrade-prs"
    assert "counts" not in result["data"]


@pytest.mark.asyncio
async def test_list_fossabot_upgrade_prs_can_also_fetch_counts(settings, respx_mock, make_context):
    respx_mock.get(f"{BASE}/fossabot/dependency-upgrade-prs").mock(
        return_value=httpx.Response(200, json={"nodes": [], "pageInfo": {}})
    )
    counts = respx_mock.get(f"{BASE}/fossabot/dependency-upgrade-prs/counts").mock(
        return_value=httpx.Response(200, json={"total": 4, "open": 2})
    )

    client = FossaClient(settings)
    result = await integrations.list_fossabot_upgrade_prs(
        make_context(client, settings), PROJECT, include_counts=True
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 2
    assert _query_pairs(counts.calls.last.request) == [("projectLocator", PROJECT)]
    assert result["endpoint"] == (
        "GET /fossabot/dependency-upgrade-prs, GET /fossabot/dependency-upgrade-prs/counts"
    )
    assert result["data"]["counts"] == {"total": 4, "open": 2}


@pytest.mark.asyncio
async def test_list_fossabot_upgrade_prs_refuses_to_mix_cursor_directions(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="not both"):
        await integrations.list_fossabot_upgrade_prs(
            make_context(client, settings), PROJECT, first=10, before="cursor-1"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_get_fossabot_upgrade_pr_passes_the_job_id(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/fossabot/issues/42/dependency-upgrade-pr").mock(
        return_value=httpx.Response(200, json={"status": "failed", "jobId": "job-9"})
    )

    client = FossaClient(settings)
    result = await integrations.get_fossabot_upgrade_pr(
        make_context(client, settings), 42, project_locator=PROJECT, job_id="job-9"
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("projectLocator", PROJECT),
        ("jobId", "job-9"),
    ]
    assert result["endpoint"] == "GET /fossabot/issues/{issueId}/dependency-upgrade-pr"


@pytest.mark.asyncio
async def test_request_fossabot_upgrade_pr_creates(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/fossabot/issues/42/dependency-upgrade-pr").mock(
        return_value=httpx.Response(200, json={"status": "creating", "jobId": "job-9"})
    )

    client = FossaClient(writable_settings)
    result = await integrations.request_fossabot_upgrade_pr(
        make_context(client, writable_settings), 42, project_locator=PROJECT, fix="partial"
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _body(request) == {"projectLocator": PROJECT, "fix": "partial"}
    assert result["endpoint"] == "POST /fossabot/issues/{issueId}/dependency-upgrade-pr"


@pytest.mark.asyncio
async def test_request_fossabot_upgrade_pr_retries_analysis(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/fossabot/issues/42/dependency-upgrade-pr/retry").mock(
        return_value=httpx.Response(200, json={"status": "analyzing"})
    )

    client = FossaClient(writable_settings)
    result = await integrations.request_fossabot_upgrade_pr(
        make_context(client, writable_settings), 42, retry_analysis=True
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _body(request) == {}
    assert result["endpoint"] == "POST /fossabot/issues/{issueId}/dependency-upgrade-pr/retry"


@pytest.mark.asyncio
async def test_request_fossabot_upgrade_pr_rejects_a_fix_on_a_retry(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="retrying"):
        await integrations.request_fossabot_upgrade_pr(
            make_context(client, writable_settings), 42, fix="complete", retry_analysis=True
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- report options ----------------------------------------------------------


@pytest.mark.asyncio
async def test_list_report_options_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/report-options").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    client = FossaClient(settings)
    result = await integrations.list_report_options(make_context(client, settings))
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert result["endpoint"] == "GET /report-options"


@pytest.mark.asyncio
async def test_save_report_option_creates_with_every_switch_expanded(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/report-options").mock(
        return_value=httpx.Response(201, json={"id": 8})
    )

    client = FossaClient(writable_settings)
    result = await integrations.save_report_option(
        make_context(client, writable_settings),
        name="Release notices",
        sections=["licenseList", "directDependencies"],
        dependency_data=["authors", "declaredLicenses"],
        use_hash_and_version_data=False,
        exclude_package_labels=[11, 12],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _body(request) == {
        "name": "Release notices",
        "options": {
            "sections": {
                "projectDeclaredLicenses": False,
                "firstPartyLicenses": False,
                "licenseList": True,
                "directDependencies": True,
                "deepDependencies": False,
                "snippetDependencies": False,
                "copyrightList": False,
            },
            "toggles": {"useHashAndVersionData": False},
            "excludeFields": {"packageLabels": [11, 12]},
            "dependencyData": {
                "projects": False,
                "authors": True,
                "description": False,
                "homepage": False,
                "packageManager": False,
                "downloadUrl": False,
                "concludedLicenses": False,
                "declaredLicenses": True,
                "discoveredLicenses": False,
                "copyrights": False,
                "licenseUrl": False,
                "licenseFileMatches": False,
                "issueResolutionNotes": False,
                "packageLabels": False,
                "dependencyPaths": False,
                "filePaths": False,
                "noticeFiles": False,
                "fullLicenseText": False,
            },
        },
    }
    assert result["endpoint"] == "POST /report-options"


@pytest.mark.asyncio
async def test_save_report_option_updates_only_the_groups_supplied(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/report-options/8").mock(
        return_value=httpx.Response(200, json={"id": 8})
    )

    client = FossaClient(writable_settings)
    result = await integrations.save_report_option(
        make_context(client, writable_settings),
        report_option_id=8,
        name="Renamed",
        use_hash_and_version_data=True,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert _body(request) == {
        "name": "Renamed",
        "options": {"toggles": {"useHashAndVersionData": True}},
    }
    assert result["endpoint"] == "PUT /report-options/{id}"


@pytest.mark.asyncio
async def test_save_report_option_requires_every_group_on_create(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="every option group"):
        await integrations.save_report_option(
            make_context(client, writable_settings), name="Partial", sections=["licenseList"]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_report_option_accepts_an_empty_204(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/report-options/8").mock(return_value=httpx.Response(204))

    client = FossaClient(destructive_settings)
    result = await integrations.delete_report_option(make_context(client, destructive_settings), 8)
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /report-options/{id}"
    assert result["data"] == {"report_option_id": 8, "response": None}


# --- custom risk scores ------------------------------------------------------


@pytest.mark.asyncio
async def test_set_custom_risk_score_creates_with_post(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/custom-risk-scores/77").mock(
        return_value=httpx.Response(201, json={"issueId": 77, "score": 40})
    )

    client = FossaClient(writable_settings)
    result = await integrations.set_custom_risk_score(
        make_context(client, writable_settings),
        action="create",
        issue_id=77,
        scope_type="project",
        scope_id=PROJECT,
        score=40,
        reason="Not reachable from any entry point",
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _query_pairs(request) == [("scope[type]", "project"), ("scope[id]", PROJECT)]
    assert _body(request) == {"score": 40, "reason": "Not reachable from any entry point"}
    assert result["endpoint"] == "POST /custom-risk-scores/{issueId}"


@pytest.mark.asyncio
async def test_set_custom_risk_score_updates_with_patch(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.patch(f"{BASE}/custom-risk-scores/77").mock(
        return_value=httpx.Response(200, json={"issueId": 77, "score": 90})
    )

    client = FossaClient(writable_settings)
    result = await integrations.set_custom_risk_score(
        make_context(client, writable_settings),
        action="update",
        issue_id=77,
        scope_type="release_group",
        scope_id="12",
        score=90,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PATCH"
    assert _query_pairs(request) == [("scope[type]", "release_group"), ("scope[id]", "12")]
    assert _body(request) == {"score": 90}
    assert result["endpoint"] == "PATCH /custom-risk-scores/{issueId}"


@pytest.mark.asyncio
async def test_set_custom_risk_score_rejects_an_out_of_range_score(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError):
        await integrations.set_custom_risk_score(
            make_context(client, writable_settings),
            action="create",
            issue_id=77,
            scope_type="project",
            scope_id=PROJECT,
            score=101,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_custom_risk_score_sends_the_scope_and_accepts_204(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/custom-risk-scores/77").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(destructive_settings)
    result = await integrations.delete_custom_risk_score(
        make_context(client, destructive_settings),
        issue_id=77,
        scope_type="project",
        scope_id=PROJECT,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "DELETE"
    assert _query_pairs(request) == [("scope[type]", "project"), ("scope[id]", PROJECT)]
    assert result["endpoint"] == "DELETE /custom-risk-scores/{issueId}"
    assert result["data"]["response"] is None


# --- snippets ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_snippets_default_view_sends_plain_repeated_filter_keys(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets").mock(
        return_value=httpx.Response(200, json={"results": [], "totalCount": 0})
    )

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings),
        PROJECT,
        REVISION,
        path="src/vendor",
        snippet_ids=["s1", "s2"],
        package_ids=["p1"],
        search="zlib",
        rejection_status=["unrejected"],
        package_labels=["approved"],
        vendored_match=["exVendored"],
        sort="package_asc",
        page=2,
        page_size=50,
    )
    await client.aclose()

    # The route matching on the encoded path is the assertion that the locator
    # was percent-encoded; httpx re-decodes `url.path`.
    assert route.called
    assert _query_pairs(route.calls.last.request) == [
        ("path", "src/vendor"),
        ("ids", "s1"),
        ("ids", "s2"),
        ("packageIds", "p1"),
        ("search", "zlib"),
        ("rejectionStatus", "unrejected"),
        ("packageLabels", "approved"),
        ("vendoredMatch", "exVendored"),
        ("sort", "package_asc"),
        ("page", "2"),
        ("pageSize", "50"),
    ]
    assert result["endpoint"] == "GET /revisions/{locator}/snippets"
    assert result["data"]["view"] == "snippets"


@pytest.mark.asyncio
async def test_list_snippets_accepts_a_full_revision_locator(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/count").mock(
        return_value=httpx.Response(200, json={"count": 12})
    )

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings), PROJECT, FULL_REVISION, view="count", path="/"
    )
    await client.aclose()

    # `count` takes no sort or paging.
    assert _query_pairs(route.calls.last.request) == [("path", "/")]
    assert result["endpoint"] == "GET /revisions/{locator}/snippets/count"


@pytest.mark.asyncio
async def test_list_snippets_paths_view_omits_paging_and_allows_no_path(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/paths").mock(
        return_value=httpx.Response(200, json={"paths": []})
    )

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings), PROJECT, REVISION, view="paths"
    )
    await client.aclose()

    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == "GET /revisions/{locator}/snippets/paths"


@pytest.mark.asyncio
async def test_list_snippets_packages_view(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/packages").mock(
        return_value=httpx.Response(200, json={"results": [], "totalCount": 0})
    )

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings), PROJECT, REVISION, view="packages", path="/"
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("path", "/"),
        ("page", "1"),
        ("pageSize", "10"),
    ]
    assert result["endpoint"] == "GET /revisions/{locator}/snippets/packages"


@pytest.mark.asyncio
async def test_list_snippets_compares_two_revisions(settings, respx_mock, make_context):
    route = respx_mock.get(
        f"{BASE}/revisions/{ENCODED_REVISION}/snippets/compare/{ENCODED_OLDER_REVISION}/new"
    ).mock(return_value=httpx.Response(200, json={"results": [], "totalCount": 0}))

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings),
        PROJECT,
        REVISION,
        path="/",
        compare_to_revision=OLDER_REVISION,
        change_status="new",
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == (
        "GET /revisions/{locator}/snippets/compare/{olderRevisionLocator}/{status}"
    )


@pytest.mark.asyncio
async def test_list_snippets_compare_packages_view(settings, respx_mock, make_context):
    route = respx_mock.get(
        f"{BASE}/revisions/{ENCODED_REVISION}/snippets/compare/"
        f"{ENCODED_OLDER_REVISION}/removed/packages"
    ).mock(return_value=httpx.Response(200, json={"results": [], "totalCount": 0}))

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings),
        PROJECT,
        REVISION,
        view="packages",
        path="/",
        compare_to_revision=OLDER_REVISION,
        change_status="removed",
    )
    await client.aclose()

    assert route.called
    assert result["endpoint"] == (
        "GET /revisions/{locator}/snippets/compare/{olderRevisionLocator}/{status}/packages"
    )


@pytest.mark.asyncio
async def test_list_snippets_compare_paths_view(settings, respx_mock, make_context):
    route = respx_mock.get(
        f"{BASE}/revisions/{ENCODED_REVISION}/snippets/compare/"
        f"{ENCODED_OLDER_REVISION}/unchanged/paths"
    ).mock(return_value=httpx.Response(200, json={"paths": []}))

    client = FossaClient(settings)
    result = await integrations.list_snippets(
        make_context(client, settings),
        PROJECT,
        REVISION,
        view="paths",
        compare_to_revision=OLDER_REVISION,
        change_status="unchanged",
    )
    await client.aclose()

    assert route.called
    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == (
        "GET /revisions/{locator}/snippets/compare/{olderRevisionLocator}/{status}/paths"
    )


@pytest.mark.asyncio
async def test_list_snippets_refuses_a_compared_count(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="no snippet count endpoint"):
        await integrations.list_snippets(
            make_context(client, settings),
            PROJECT,
            REVISION,
            view="count",
            path="/",
            compare_to_revision=OLDER_REVISION,
            change_status="new",
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_list_snippets_requires_a_path_for_every_view_but_paths(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="path is required"):
        await integrations.list_snippets(make_context(client, settings), PROJECT, REVISION)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_get_snippet_reads_one_snippet(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/snip-1").mock(
        return_value=httpx.Response(200, json={"snippet": {"id": "snip-1"}})
    )

    client = FossaClient(settings)
    result = await integrations.get_snippet(
        make_context(client, settings), PROJECT, REVISION, "snip-1"
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == "GET /revisions/{locator}/snippets/{snippetId}"


@pytest.mark.asyncio
async def test_get_snippet_fetches_match_details_at_an_encoded_path(
    settings, respx_mock, make_context
):
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/snip-1").mock(
        return_value=httpx.Response(200, json={"snippet": {"id": "snip-1"}})
    )
    matches = respx_mock.get(
        f"{BASE}/revisions/{ENCODED_REVISION}/snippets/snip-1/matches/src%2Fzlib.c"
    ).mock(return_value=httpx.Response(200, json={"matchDetails": {"lines": ["a", "b"]}}))

    client = FossaClient(settings)
    result = await integrations.get_snippet(
        make_context(client, settings),
        PROJECT,
        REVISION,
        "snip-1",
        path="src/zlib.c",
        include_match_details=True,
    )
    await client.aclose()

    assert matches.called
    assert result["endpoint"] == (
        "GET /revisions/{locator}/snippets/{snippetId}, "
        "GET /revisions/{locator}/snippets/{snippetId}/matches/{path}"
    )
    assert result["data"]["match_details"] == {"matchDetails": {"lines": ["a", "b"]}}
    assert result["data"]["truncated"] is False


@pytest.mark.asyncio
async def test_get_snippet_truncates_oversized_match_details(respx_mock, make_context):
    tight_settings = Settings(
        fossa_api_token="test-token",
        fossa_report_max_chars=1000,
        _env_file=None,  # type: ignore[call-arg]
    )
    respx_mock.get(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/snip-1").mock(
        return_value=httpx.Response(200, json={"snippet": {"id": "snip-1"}})
    )
    respx_mock.get(
        f"{BASE}/revisions/{ENCODED_REVISION}/snippets/snip-1/matches/src%2Fzlib.c"
    ).mock(return_value=httpx.Response(200, json={"matchDetails": {"lines": ["x" * 5000]}}))

    client = FossaClient(tight_settings)
    result = await integrations.get_snippet(
        make_context(client, tight_settings),
        PROJECT,
        REVISION,
        "snip-1",
        path="src/zlib.c",
        include_match_details=True,
    )
    await client.aclose()

    assert result["data"]["truncated"] is True
    assert len(result["data"]["match_details"]) == 1000
    assert result["data"]["original_char_count"] > 5000


@pytest.mark.asyncio
async def test_get_snippet_requires_a_path_for_match_details(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="needs the path"):
        await integrations.get_snippet(
            make_context(client, settings),
            PROJECT,
            REVISION,
            "snip-1",
            include_match_details=True,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_reject_snippets_by_explicit_ids_is_a_plain_write(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/reject").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(writable_settings)
    result = await integrations.set_snippet_rejection(
        make_context(client, writable_settings),
        PROJECT,
        REVISION,
        rejected=True,
        path="src/vendor",
        snippet_ids=["s1", "s2"],
        vendored_match=["vendored"],
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _body(request) == {
        "path": "src/vendor",
        "ids": ["s1", "s2"],
        "vendoredMatch": ["vendored"],
    }
    assert result["endpoint"] == "POST /revisions/{locator}/snippets/reject"
    assert result["data"]["tier"] == "write"
    assert result["data"]["response"] is None


@pytest.mark.asyncio
async def test_unreject_snippets_posts_to_the_unreject_endpoint(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/unreject").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(writable_settings)
    result = await integrations.set_snippet_rejection(
        make_context(client, writable_settings),
        PROJECT,
        REVISION,
        rejected=False,
        path="/",
        package_ids=["p1"],
    )
    await client.aclose()

    assert route.calls.last.request.method == "POST"
    assert _body(route.calls.last.request) == {"path": "/", "packageIds": ["p1"]}
    assert result["endpoint"] == "POST /revisions/{locator}/snippets/unreject"


@pytest.mark.asyncio
async def test_reject_snippets_by_filter_alone_needs_the_destructive_tier(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/revisions/{ENCODED_REVISION}/snippets/reject").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(destructive_settings)
    result = await integrations.set_snippet_rejection(
        make_context(client, destructive_settings),
        PROJECT,
        REVISION,
        rejected=True,
        path="/",
        search="zlib",
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"path": "/", "search": "zlib"}
    assert result["data"]["tier"] == "destructive"


# --- refusals ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_write_refuses_without_the_write_tier(settings, respx_mock, make_context):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    for call in (
        integrations.save_jira_configuration(ctx, name="Acme Jira"),
        integrations.delete_jira_configuration(ctx, 3),
        integrations.request_fossabot_upgrade_pr(ctx, 42),
        integrations.save_report_option(
            ctx,
            name="Preset",
            sections=[],
            dependency_data=[],
            use_hash_and_version_data=False,
            exclude_package_labels=[],
        ),
        integrations.delete_report_option(ctx, 8),
        integrations.set_custom_risk_score(
            ctx,
            action="create",
            issue_id=77,
            scope_type="project",
            scope_id=PROJECT,
            score=40,
        ),
        integrations.delete_custom_risk_score(
            ctx, issue_id=77, scope_type="project", scope_id=PROJECT
        ),
        integrations.set_snippet_rejection(
            ctx, PROJECT, REVISION, rejected=True, path="/", snippet_ids=["s1"]
        ),
        integrations.set_snippet_rejection(ctx, PROJECT, REVISION, rejected=True, path="/"),
    ):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_destructive_tools_refuse_when_only_writes_are_enabled(
    writable_settings, respx_mock, make_context
):
    assert writable_settings.fossa_allow_destructive is False
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    for call in (
        integrations.delete_jira_configuration(ctx, 3),
        integrations.delete_report_option(ctx, 8),
        integrations.delete_custom_risk_score(
            ctx, issue_id=77, scope_type="project", scope_id=PROJECT
        ),
        # No ids and no package ids: the target set is a filter, so this one
        # needs the destructive tier even though the verb is POST.
        integrations.set_snippet_rejection(ctx, PROJECT, REVISION, rejected=True, path="/"),
        integrations.set_snippet_rejection(ctx, PROJECT, REVISION, rejected=False, path="/"),
    ):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0
