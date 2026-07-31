"""Endpoint contract tests for the package block/unblock tools.

These endpoints are undocumented, so the request shapes asserted here are the
ones captured from FOSSA's own web app and verified against the live API. Two of
them are load-bearing and easy to get wrong: the block body carries `versions` as
the string `"ALL"` rather than an array, and the unblock body is a **bare
top-level array** — every wrapper object tried against the live API returned an
opaque 500.

What these tests cannot do is notice FOSSA changing its side. They pin our
request, not their contract.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaApiError, FossaWriteNotPermittedError
from fossa_mcp.tools import packages

PACKAGE = "pip+aiofile"
ENCODED_PACKAGE = "pip%2Baiofile"
POLICY_ID = 266648

BLOCK_URL = f"https://app.fossa.com/api/packages/{ENCODED_PACKAGE}/rules"
POLICY_URL = f"https://app.fossa.com/api/policies/{POLICY_ID}"
POLICY_RULES_URL = f"{POLICY_URL}/rules"

# Abridged from a real `GET /api/policies/266648`, keeping the fields the tools
# read and enough of the rest to prove rules are echoed back untouched.
BLOCK_RULE = {
    "ruleId": 58586851,
    "type": "blacklisted_dependency",
    "packageProjectLocator": PACKAGE,
    "dependencyFilterVersionType": "ALL",
    "dependencyFilterName": None,
    "dependencyFilterStartVersion": None,
    "dependencyFilterEndVersion": None,
    "enabled": True,
    "notes": None,
    "createdAt": "2026-07-31T20:01:41.871Z",
    "updatedAt": "2026-07-31T20:01:41.871Z",
    "PolicyVersionRule": {"policyVersionId": 359431, "ruleId": 58586851},
}

OTHER_BLOCK_RULE = {
    "ruleId": 58586852,
    "type": "blacklisted_dependency",
    "packageProjectLocator": "npm+left-pad",
    "dependencyFilterVersionType": "ALL",
    "enabled": True,
    "PolicyVersionRule": {"policyVersionId": 359431, "ruleId": 58586852},
}

QUALITY_RULE = {
    "ruleId": 58480306,
    "type": "outdated_dependency",
    "notes": "Major difference of 3 or more",
    "dependencyOutdatedType": "SEMVER",
    "dependencyOutdatedVersionPart": "MAJOR",
    "dependencyOutdatedVersionDiff": 3,
    "packageProjectLocator": None,
    "enabled": True,
    "PolicyVersionRule": {"policyVersionId": 359431, "ruleId": 58480306},
}

POLICY_VERSIONS = [
    {
        "id": 359431,
        "policyId": POLICY_ID,
        "rulesHash": "53e41a0d1ddaa1bc828431e5381ae993",
        "defaultAction": "APPROVE",
    }
]


def _policy_body(rules: list[dict]) -> dict:
    return {"policyId": POLICY_ID, "title": "Major - 3 Policy", "type": "QUALITY", "rules": rules}


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


# --- write gate --------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await packages.block_package(make_context(client, settings), PACKAGE, [POLICY_ID])
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unblock_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await packages.unblock_package(make_context(client, settings), PACKAGE, POLICY_ID)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unblock_refuses_when_only_writes_are_enabled(
    writable_settings, respx_mock, make_context
):
    """Writes alone are not enough: rewriting a whole rule set is destructive."""
    client = FossaClient(writable_settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await packages.unblock_package(make_context(client, writable_settings), PACKAGE, POLICY_ID)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_destructive_alone_does_not_grant_unblock(respx_mock, make_context):
    settings = Settings(
        fossa_api_token="test-token",
        fossa_allow_destructive=True,
        _env_file=None,  # type: ignore[call-arg]
    )
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await packages.unblock_package(make_context(client, settings), PACKAGE, POLICY_ID)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- block -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_block_sends_versions_all_by_default(writable_settings, respx_mock, make_context):
    route = respx_mock.post(BLOCK_URL).mock(return_value=httpx.Response(200, json=POLICY_VERSIONS))

    client = FossaClient(writable_settings)
    result = await packages.block_package(
        make_context(client, writable_settings), PACKAGE, [POLICY_ID]
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    # `versions` is the string "ALL", not a list. An object 400s and an omitted
    # key 400s, so this spelling is the contract.
    assert json.loads(request.content) == {"policyIds": [POLICY_ID], "versions": "ALL"}

    assert result["ok"] is True
    assert result["endpoint"] == "POST /packages/{locator}/rules"
    assert result["data"]["versions"] == "ALL"
    assert result["data"]["policy_versions"] == POLICY_VERSIONS


@pytest.mark.asyncio
async def test_block_sends_named_versions_and_multiple_policies(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(BLOCK_URL).mock(return_value=httpx.Response(200, json=POLICY_VERSIONS))

    client = FossaClient(writable_settings)
    await packages.block_package(
        make_context(client, writable_settings),
        PACKAGE,
        [POLICY_ID, 266649],
        versions=["3.11.1", "3.12.0"],
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "policyIds": [POLICY_ID, 266649],
        "versions": ["3.11.1", "3.12.0"],
    }


@pytest.mark.asyncio
async def test_block_rejects_a_versioned_locator_before_any_request(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)

    with pytest.raises(ValueError, match="versionless"):
        await packages.block_package(
            make_context(client, writable_settings), f"{PACKAGE}$1.2.3", [POLICY_ID]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_block_rejects_empty_versions_rather_than_blocking_everything(
    writable_settings, respx_mock, make_context
):
    """FOSSA reads `[]` as every version; an accidental empty list must not do that."""
    client = FossaClient(writable_settings)

    with pytest.raises(ValueError, match="omit it to block every version"):
        await packages.block_package(
            make_context(client, writable_settings), PACKAGE, [POLICY_ID], versions=[]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_block_rejects_empty_and_invalid_policy_ids(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError):
        await packages.block_package(ctx, PACKAGE, [])

    with pytest.raises(ValueError, match=">= 1"):
        await packages.block_package(ctx, PACKAGE, [0])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- unblock -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_unblock_puts_a_bare_array_of_surviving_rules(
    destructive_settings, respx_mock, make_context
):
    respx_mock.get(POLICY_URL).mock(
        return_value=httpx.Response(
            200, json=_policy_body([QUALITY_RULE, BLOCK_RULE, OTHER_BLOCK_RULE])
        )
    )
    put_route = respx_mock.put(POLICY_RULES_URL).mock(
        return_value=httpx.Response(200, json=POLICY_VERSIONS)
    )

    client = FossaClient(destructive_settings)
    result = await packages.unblock_package(
        make_context(client, destructive_settings), PACKAGE, POLICY_ID
    )
    await client.aclose()

    body = json.loads(put_route.calls.last.request.content)
    # A bare top-level array. Every wrapper object returns an opaque 500.
    assert isinstance(body, list)
    # Rules are echoed back verbatim, including the join object and timestamps.
    assert body == [QUALITY_RULE, OTHER_BLOCK_RULE]

    assert result["endpoint"] == "PUT /policies/{policyId}/rules"
    assert [rule["rule_id"] for rule in result["data"]["removed"]] == [BLOCK_RULE["ruleId"]]
    assert result["data"]["rules_sent_count"] == 2
    assert [rule["rule_id"] for rule in result["data"]["rules_sent"]] == [
        QUALITY_RULE["ruleId"],
        OTHER_BLOCK_RULE["ruleId"],
    ]


@pytest.mark.asyncio
async def test_unblock_leaves_the_policy_alone_when_no_block_exists(
    destructive_settings, respx_mock, make_context
):
    respx_mock.get(POLICY_URL).mock(
        return_value=httpx.Response(200, json=_policy_body([QUALITY_RULE, OTHER_BLOCK_RULE]))
    )
    put_route = respx_mock.put(POLICY_RULES_URL).mock(return_value=httpx.Response(200, json=[]))

    client = FossaClient(destructive_settings)
    result = await packages.unblock_package(
        make_context(client, destructive_settings), PACKAGE, POLICY_ID
    )
    await client.aclose()

    # No rule to remove means no read-modify-write, so no clobber risk taken.
    assert put_route.called is False
    assert result["data"]["removed"] == []
    assert result["data"]["packages_blocked_by_this_policy"] == ["npm+left-pad"]
    assert "nothing was changed" in result["message"]


@pytest.mark.asyncio
async def test_unblock_refuses_a_policy_body_it_does_not_understand(
    destructive_settings, respx_mock, make_context
):
    """An unrecognized shape must raise, not send an empty rule set."""
    respx_mock.get(POLICY_URL).mock(
        return_value=httpx.Response(200, json={"policyId": POLICY_ID, "title": "Major - 3 Policy"})
    )
    put_route = respx_mock.put(POLICY_RULES_URL).mock(return_value=httpx.Response(200, json=[]))

    client = FossaClient(destructive_settings)
    with pytest.raises(FossaApiError, match="rules"):
        await packages.unblock_package(
            make_context(client, destructive_settings), PACKAGE, POLICY_ID
        )
    await client.aclose()

    assert put_route.called is False


@pytest.mark.asyncio
async def test_unblock_rejects_a_versioned_locator_before_any_request(
    destructive_settings, respx_mock, make_context
):
    client = FossaClient(destructive_settings)

    with pytest.raises(ValueError, match="versionless"):
        await packages.unblock_package(
            make_context(client, destructive_settings), f"{PACKAGE}$1.2.3", POLICY_ID
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unblock_rejects_an_invalid_policy_id(destructive_settings, respx_mock, make_context):
    client = FossaClient(destructive_settings)

    with pytest.raises(ValueError):
        await packages.unblock_package(make_context(client, destructive_settings), PACKAGE, 0)
    await client.aclose()

    assert respx_mock.calls.call_count == 0
