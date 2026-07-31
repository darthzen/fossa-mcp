"""Endpoint contract tests for the security policy tools.

Covers the HTTP shape of the reads, the exact body sent by the writes, and the
refusal path that must fire before any request leaves the process when
`FOSSA_ALLOW_WRITES` is off.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import policies

PROJECT = "git+github.com/acme/widget"
ENCODED_PROJECT = "git%2Bgithub.com%2Facme%2Fwidget"
REVISION = "abc123"
ENCODED_REVISION = "git%2Bgithub.com%2Facme%2Fwidget%24abc123"

PROJECT_BODY = {
    "securityPolicyId": 7,
    "securityIssueScanningEnabled": True,
    "securityStatusCheckEnabled": False,
}

ORG_SECURITY_BODY = {
    "defaultSecurityPolicyId": 1,
    "projectDefaultStatusCheckFilterVulnerability": 4,
}


@pytest.fixture
def writable_settings() -> Settings:
    return Settings(fossa_api_token="test-token", fossa_allow_writes=True, _env_file=None)  # type: ignore[call-arg]


def _query_pairs(request: httpx.Request) -> list[tuple[str, str]]:
    return httpx.QueryParams(request.url.query.decode()).multi_items()


def _policy_file(tmp_path, payload) -> str:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload))
    return str(path)


# --- reads -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_security_policy_reads_project_and_org_settings(
    settings, respx_mock, make_context
):
    settings = settings.model_copy(update={"fossa_org_id": 42})
    project_route = respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json=PROJECT_BODY)
    )
    org_route = respx_mock.get(
        "https://app.fossa.com/api/organizations/42/settings/projects/issues/security"
    ).mock(return_value=httpx.Response(200, json=ORG_SECURITY_BODY))

    client = FossaClient(settings)
    result = await policies.get_security_policy(make_context(client, settings), PROJECT)
    await client.aclose()

    assert project_route.calls.last.request.method == "GET"
    assert org_route.called

    baseline = result["data"]["baseline"]
    assert baseline["security_policy_id"] == 7
    assert baseline["org_default_security_policy_id"] == 1
    assert baseline["security_status_check_enabled"] is False
    # Undocumented integer scale: carried through, never interpreted.
    assert baseline["status_check_filter_vulnerability"] == 4
    assert result["data"]["effective_fossa_policy_id"] == 7
    assert result["data"]["overlay"]["loaded"] is False


@pytest.mark.asyncio
async def test_get_security_policy_skips_org_call_without_org_id(
    settings, respx_mock, make_context
):
    respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json=PROJECT_BODY)
    )

    client = FossaClient(settings)
    result = await policies.get_security_policy(make_context(client, settings), PROJECT)
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert result["data"]["baseline"]["org_default_security_policy_id"] is None


@pytest.mark.asyncio
async def test_get_security_policy_falls_back_to_org_default_policy(
    settings, respx_mock, make_context
):
    settings = settings.model_copy(update={"fossa_org_id": 42})
    respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json={"securityIssueScanningEnabled": True})
    )
    respx_mock.get(
        "https://app.fossa.com/api/organizations/42/settings/projects/issues/security"
    ).mock(return_value=httpx.Response(200, json=ORG_SECURITY_BODY))

    client = FossaClient(settings)
    result = await policies.get_security_policy(make_context(client, settings), PROJECT)
    await client.aclose()

    assert result["data"]["effective_fossa_policy_id"] == 1


@pytest.mark.asyncio
async def test_evaluate_security_policy_endpoint_and_verdict(
    settings, respx_mock, make_context, tmp_path, assert_raw_path
):
    settings = settings.model_copy(
        update={
            "fossa_policy_file": _policy_file(
                tmp_path,
                {"version": 1, "security": [{"id": "strict", "rules": {"max_cvss": 4.0}}]},
            )
        }
    )
    respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json=PROJECT_BODY)
    )
    deps_route = respx_mock.get(
        f"https://app.fossa.com/api/v2/revisions/{ENCODED_REVISION}/dependencies"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "dependencies": [
                    {
                        "locator": "pip+mcp$1.6.0",
                        "title": "mcp",
                        "depth": 1,
                        "issues": [
                            {
                                "type": "vulnerability",
                                "status": "active",
                                "vulnId": "CVE-2025-53365_pip+mcp",
                                "cvssScore": 8.7,
                            }
                        ],
                    },
                    {"locator": "pip+requests$2.31", "title": "requests", "depth": 1, "issues": []},
                ]
            },
        )
    )

    client = FossaClient(settings)
    result = await policies.evaluate_security_policy(
        make_context(client, settings), PROJECT, REVISION, depths=["direct"], count=50
    )
    await client.aclose()

    request = deps_route.calls.last.request
    assert request.method == "GET"
    # Encoding is asserted on the bytes sent, not by the route matching: respx
    # normalizes both sides, so an unescaped `$` would match this route too.
    assert_raw_path(request, f"/v2/revisions/{ENCODED_REVISION}/dependencies")
    pairs = _query_pairs(request)
    assert ("depth[]", "direct") in pairs
    assert ("count", "50") in pairs

    assert result.verdict == "block"
    assert result.revision_locator == f"{PROJECT}${REVISION}"
    assert result.applied_policy_ids == ["strict"]
    assert [pkg.locator for pkg in result.blocked] == ["pip+mcp$1.6.0"]
    assert result.allowed_count == 1


@pytest.mark.asyncio
async def test_evaluate_security_policy_accepts_a_full_revision_locator(
    settings, respx_mock, make_context
):
    respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json=PROJECT_BODY)
    )
    deps_route = respx_mock.get(
        f"https://app.fossa.com/api/v2/revisions/{ENCODED_REVISION}/dependencies"
    ).mock(return_value=httpx.Response(200, json={"dependencies": []}))

    client = FossaClient(settings)
    await policies.evaluate_security_policy(
        make_context(client, settings), PROJECT, f"{PROJECT}${REVISION}"
    )
    await client.aclose()

    assert deps_route.called


@pytest.mark.asyncio
async def test_evaluate_rejects_broken_policy_file_before_any_request(
    settings, respx_mock, make_context, tmp_path
):
    path = tmp_path / "policy.json"
    path.write_text("{not json")
    settings = settings.model_copy(update={"fossa_policy_file": str(path)})

    client = FossaClient(settings)
    with pytest.raises(Exception, match="not valid JSON"):
        await policies.evaluate_security_policy(make_context(client, settings), PROJECT, REVISION)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_evaluate_rejects_count_over_max_page_size(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await policies.evaluate_security_policy(
            make_context(client, settings),
            PROJECT,
            REVISION,
            count=settings.fossa_max_page_size + 1,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- write gate --------------------------------------------------------------


@pytest.mark.asyncio
async def test_enable_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await policies.enable_security_policy(make_context(client, settings), PROJECT, 7)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_assign_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError):
        await policies.assign_security_policy_to_projects(
            make_context(client, settings), 7, [PROJECT]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- writes ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enable_security_policy_sends_expected_put_body(
    writable_settings, respx_mock, make_context, assert_raw_path
):
    respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json=PROJECT_BODY)
    )
    put_route = respx_mock.put(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json={"id": 1})
    )

    client = FossaClient(writable_settings)
    result = await policies.enable_security_policy(
        make_context(client, writable_settings), PROJECT, 9
    )
    await client.aclose()

    request = put_route.calls.last.request
    assert request.method == "PUT"
    assert_raw_path(request, f"/projects/{ENCODED_PROJECT}")
    assert json.loads(request.content) == {
        "securityPolicyId": 9,
        "securityIssueScanningEnabled": True,
        "securityStatusCheckEnabled": True,
    }

    assert result["ok"] is True
    assert result["endpoint"] == "PUT /projects/{locator}"
    assert result["data"]["before"]["security_policy_id"] == 7
    assert result["data"]["applied"]["securityPolicyId"] == 9


@pytest.mark.asyncio
async def test_enable_security_policy_can_assign_without_enforcing(
    writable_settings, respx_mock, make_context
):
    respx_mock.get(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json=PROJECT_BODY)
    )
    put_route = respx_mock.put(f"https://app.fossa.com/api/projects/{ENCODED_PROJECT}").mock(
        return_value=httpx.Response(200, json={})
    )

    client = FossaClient(writable_settings)
    await policies.enable_security_policy(
        make_context(client, writable_settings),
        PROJECT,
        9,
        enable_scanning=False,
        enable_status_check=False,
    )
    await client.aclose()

    assert json.loads(put_route.calls.last.request.content) == {
        "securityPolicyId": 9,
        "securityIssueScanningEnabled": False,
        "securityStatusCheckEnabled": False,
    }


@pytest.mark.asyncio
async def test_enable_security_policy_rejects_invalid_policy_id(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError):
        await policies.enable_security_policy(make_context(client, writable_settings), PROJECT, 0)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_assign_policy_to_projects_query_and_partial_failure(
    writable_settings, respx_mock, make_context
):
    other = "git+github.com/acme/gadget"
    route = respx_mock.put("https://app.fossa.com/api/v2/projects/policy").mock(
        return_value=httpx.Response(200, json={other: "Insufficient permissions"})
    )

    client = FossaClient(writable_settings)
    result = await policies.assign_security_policy_to_projects(
        make_context(client, writable_settings), 9, [PROJECT, other]
    )
    await client.aclose()

    pairs = _query_pairs(route.calls.last.request)
    assert ("policyId", "9") in pairs
    assert ("locators[]", PROJECT) in pairs
    assert ("locators[]", other) in pairs

    assert result["data"]["succeeded"] == [PROJECT]
    assert result["data"]["failures"] == {other: "Insufficient permissions"}


@pytest.mark.asyncio
async def test_assign_policy_refuses_an_unbounded_target_set(
    writable_settings, respx_mock, make_context
):
    """No request is built for an empty, blank, or wildcard target set.

    `PUT /v2/projects/policy` does not enforce its locator list: sent without
    one it re-policies every project matching the filters, and `locators=all`
    ignores the filters entirely. DECISIONS.md §5 promises that mode is
    unreachable from this tool; this is the assertion behind the promise.
    """
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError, match="at least one project"):
        await policies.assign_security_policy_to_projects(ctx, 9, [])

    with pytest.raises(ValueError, match="blank"):
        await policies.assign_security_policy_to_projects(ctx, 9, [PROJECT, "  "])

    with pytest.raises(ValueError, match="wildcard"):
        await policies.assign_security_policy_to_projects(ctx, 9, ["all"])

    await client.aclose()
    assert respx_mock.calls.call_count == 0
