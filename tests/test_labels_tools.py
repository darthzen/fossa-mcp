"""Endpoint contract tests for the label tools.

Covers the HTTP shape of every package-label and organization-label operation,
the exact JSON body each write sends, and the refusal paths that must fire
before any request leaves the process when a tool's tier is off.

`GET /projects/{locator}/labels` and `PUT /v2/projects/labels` are exercised in
`tests/test_projects_tools.py`; they belong to the project tools.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import labels

BASE = "https://app.fossa.com/api"
PACKAGE = "npm+lodash"
LOCATOR = "npm+lodash$4.17.21"
OTHER_LOCATOR = "npm+express$4.18.2"


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


def _body(request: httpx.Request) -> dict:
    return json.loads(request.content)


# --- reads -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_package_labels_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/package-labels").mock(
        return_value=httpx.Response(
            200, json={"packageLabels": [{"id": 3, "name": "approved-crypto"}]}
        )
    )

    client = FossaClient(settings)
    result = await labels.list_package_labels(make_context(client, settings))
    await client.aclose()

    assert route.calls.last.request.method == "GET"
    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /package-labels"
    assert result["data"]["packageLabels"][0]["id"] == 3


@pytest.mark.asyncio
async def test_list_package_label_assignments_sends_no_filters_by_default(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/package-label-assignments").mock(
        return_value=httpx.Response(200, json={"packageLabelAssignments": []})
    )

    client = FossaClient(settings)
    await labels.list_package_label_assignments(make_context(client, settings))
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == []


@pytest.mark.asyncio
async def test_list_package_label_assignments_filter_names(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/package-label-assignments").mock(
        return_value=httpx.Response(200, json={"packageLabelAssignments": []})
    )

    client = FossaClient(settings)
    result = await labels.list_package_label_assignments(
        make_context(client, settings),
        package_id=PACKAGE,
        package_version="4.17.21",
        scope="project",
        scope_id="git+github.com/acme/widget",
        include_package_wide_labels=True,
        include_revision_scoped_labels=False,
    )
    await client.aclose()

    # Scalar `filters[name]`, never the `filters[name][]` array convention.
    assert _query_pairs(route.calls.last.request) == [
        ("filters[packageId]", PACKAGE),
        ("filters[packageVersion]", "4.17.21"),
        ("filters[scope]", "project"),
        ("filters[scopeId]", "git+github.com/acme/widget"),
        ("filters[shouldIncludePackageWideLabels]", "true"),
        ("filters[shouldIncludeRevisionScopedLabels]", "false"),
    ]
    assert result["endpoint"] == "GET /package-label-assignments"


@pytest.mark.asyncio
async def test_list_organization_labels_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/organizations/labels").mock(
        return_value=httpx.Response(200, json={"labels": [{"id": 1, "label": "tier-1"}]})
    )

    client = FossaClient(settings)
    result = await labels.list_organization_labels(make_context(client, settings))
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /organizations/labels"


@pytest.mark.asyncio
async def test_list_organization_labels_reads_one_by_id(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/organizations/labels/7").mock(
        return_value=httpx.Response(200, json={"id": 7, "label": "tier-1", "projects": []})
    )

    client = FossaClient(settings)
    result = await labels.list_organization_labels(make_context(client, settings), label_id=7)
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "GET /organizations/labels/{id}"
    assert result["data"]["id"] == 7


# --- input validation, before any request ------------------------------------


@pytest.mark.asyncio
async def test_assign_requires_a_version_or_an_explicit_all_versions(
    writable_settings, respx_mock, make_context
):
    """A forgotten version would silently label every version of the package."""
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError, match="package_version is required"):
        await labels.assign_package_labels(ctx, PACKAGE, "org", [3])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_assign_rejects_a_version_and_all_versions_together(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError, match="mutually exclusive"):
        await labels.assign_package_labels(
            ctx,
            PACKAGE,
            "org",
            [3],
            package_version="4.17.21",
            apply_to_all_versions=True,
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_assign_rejects_a_blank_version(writable_settings, respx_mock, make_context):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError):
        await labels.assign_package_labels(ctx, PACKAGE, "org", [3], package_version="")

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_scope_and_scope_id_must_agree(writable_settings, respx_mock, make_context):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError, match="scope_id is required"):
        await labels.assign_package_labels(ctx, PACKAGE, "project", [3], package_version="1.0.0")

    with pytest.raises(ValueError, match="scope_id must be omitted"):
        await labels.assign_package_labels(
            ctx, PACKAGE, "org", [3], package_version="1.0.0", scope_id="whatever"
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_bulk_assign_requires_versioned_locators(writable_settings, respx_mock, make_context):
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    with pytest.raises(ValueError, match="must include the version"):
        await labels.bulk_assign_package_label(ctx, 3, ["npm+lodash"], "org")

    with pytest.raises(ValueError, match='"all" is not accepted'):
        await labels.bulk_assign_package_label(ctx, 3, ["all"], "org")

    with pytest.raises(ValueError, match="at least one package"):
        await labels.bulk_assign_package_label(ctx, 3, [], "org")

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_reconcile_rejects_an_empty_map(destructive_settings, respx_mock, make_context):
    client = FossaClient(destructive_settings)
    ctx = make_context(client, destructive_settings)

    with pytest.raises(ValueError, match="at least one version"):
        await labels.set_package_label_assignments(ctx, PACKAGE, "org", {})

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_tools_reject_empty_id_lists(destructive_settings, respx_mock, make_context):
    client = FossaClient(destructive_settings)
    ctx = make_context(client, destructive_settings)

    with pytest.raises(ValueError, match="at least one id"):
        await labels.delete_package_labels(ctx, [])

    with pytest.raises(ValueError, match="at least one id"):
        await labels.unassign_package_labels(ctx, [])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- write gate --------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_write_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    for call in (
        labels.create_package_labels(ctx, ["approved-crypto"]),
        labels.assign_package_labels(ctx, PACKAGE, "org", [3], package_version="4.17.21"),
        labels.bulk_assign_package_label(ctx, 3, [LOCATOR], "org"),
        labels.create_organization_label(ctx, "tier-1"),
        labels.delete_package_labels(ctx, [3]),
        labels.set_package_label_assignments(ctx, PACKAGE, "org", {"all": [3]}),
        labels.unassign_package_labels(ctx, [11]),
        labels.delete_organization_label(ctx, 7),
    ):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_destructive_tools_refuse_when_only_the_write_tier_is_enabled(
    writable_settings, respx_mock, make_context
):
    assert writable_settings.fossa_allow_destructive is False
    client = FossaClient(writable_settings)
    ctx = make_context(client, writable_settings)

    for call in (
        labels.delete_package_labels(ctx, [3]),
        # A PUT, but it removes assignments it is not told about.
        labels.set_package_label_assignments(ctx, PACKAGE, "org", {"all": [3]}),
        labels.unassign_package_labels(ctx, [11]),
        labels.delete_organization_label(ctx, 7),
    ):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- writes ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_package_labels_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/package-labels").mock(
        return_value=httpx.Response(201, json={"packageLabels": [{"id": 9, "name": "vetted"}]})
    )

    client = FossaClient(writable_settings)
    result = await labels.create_package_labels(
        make_context(client, writable_settings), ["vetted", "needs-review"]
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"labels": ["vetted", "needs-review"]}
    assert result["endpoint"] == "POST /package-labels"
    assert result["data"]["created"]["packageLabels"][0]["id"] == 9


@pytest.mark.asyncio
async def test_assign_package_labels_body_with_a_named_version(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/package-label-assignments").mock(
        return_value=httpx.Response(201, json={"packageLabelAssignments": [{"id": 11}]})
    )

    client = FossaClient(writable_settings)
    result = await labels.assign_package_labels(
        make_context(client, writable_settings),
        PACKAGE,
        "project",
        [3, 4],
        package_version="4.17.21",
        scope_id="git+github.com/acme/widget",
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "packageId": PACKAGE,
        "scope": "project",
        "labelIds": [3, 4],
        "packageVersion": "4.17.21",
        "scopeId": "git+github.com/acme/widget",
    }
    assert result["data"]["applies_to_all_versions"] is False


@pytest.mark.asyncio
async def test_assign_package_labels_omits_the_version_for_all_versions(
    writable_settings, respx_mock, make_context
):
    """All-versions is the absent key, and only reachable through the flag."""
    route = respx_mock.post(f"{BASE}/package-label-assignments").mock(
        return_value=httpx.Response(201, json={"packageLabelAssignments": []})
    )

    client = FossaClient(writable_settings)
    result = await labels.assign_package_labels(
        make_context(client, writable_settings),
        PACKAGE,
        "org",
        [3],
        apply_to_all_versions=True,
    )
    await client.aclose()

    body = _body(route.calls.last.request)
    assert body == {"packageId": PACKAGE, "scope": "org", "labelIds": [3]}
    assert "packageVersion" not in body
    assert result["data"]["applies_to_all_versions"] is True


@pytest.mark.asyncio
async def test_bulk_assign_package_label_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/package-label-assignments/bulk").mock(
        return_value=httpx.Response(201, json={"packageLabelAssignments": [{"id": 12}]})
    )

    client = FossaClient(writable_settings)
    result = await labels.bulk_assign_package_label(
        make_context(client, writable_settings),
        3,
        [LOCATOR, OTHER_LOCATOR],
        "revision",
        scope_id="git+github.com/acme/widget$abc123",
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "packageLocators": [LOCATOR, OTHER_LOCATOR],
        "labelId": 3,
        "scope": "revision",
        "shouldUseSpecificVersion": True,
        "scopeId": "git+github.com/acme/widget$abc123",
    }
    assert result["endpoint"] == "POST /package-label-assignments/bulk"


@pytest.mark.asyncio
async def test_bulk_assign_inverts_the_all_versions_flag(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/package-label-assignments/bulk").mock(
        return_value=httpx.Response(201, json={"packageLabelAssignments": []})
    )

    client = FossaClient(writable_settings)
    await labels.bulk_assign_package_label(
        make_context(client, writable_settings),
        3,
        [LOCATOR],
        "org",
        apply_to_all_versions=True,
    )
    await client.aclose()

    assert _body(route.calls.last.request)["shouldUseSpecificVersion"] is False


@pytest.mark.asyncio
async def test_create_organization_label_body(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{BASE}/organizations/labels").mock(
        return_value=httpx.Response(201, json={"id": 7, "label": "tier-1"})
    )

    client = FossaClient(writable_settings)
    result = await labels.create_organization_label(
        make_context(client, writable_settings), "tier-1"
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"label": "tier-1"}
    assert result["data"]["created"]["id"] == 7


# --- destructive -------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_package_labels_sends_a_body_and_survives_204(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/package-labels").mock(return_value=httpx.Response(204))

    client = FossaClient(destructive_settings)
    result = await labels.delete_package_labels(make_context(client, destructive_settings), [3, 4])
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert _body(route.calls.last.request) == {"ids": [3, 4]}
    assert result["data"]["deleted"] == [3, 4]
    assert result["data"]["response"] is None


@pytest.mark.asyncio
async def test_unassign_package_labels_sends_assignment_ids(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/package-label-assignments").mock(
        return_value=httpx.Response(200, text="")
    )

    client = FossaClient(destructive_settings)
    result = await labels.unassign_package_labels(
        make_context(client, destructive_settings), [11, 12]
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {"assignmentIds": [11, 12]}
    assert result["endpoint"] == "DELETE /package-label-assignments"
    assert result["data"]["removed"] == [11, 12]


@pytest.mark.asyncio
async def test_set_package_label_assignments_body(destructive_settings, respx_mock, make_context):
    route = respx_mock.put(f"{BASE}/package-label-assignments").mock(
        return_value=httpx.Response(200, json={"packageLabelAssignments": [{"id": 13}]})
    )

    client = FossaClient(destructive_settings)
    result = await labels.set_package_label_assignments(
        make_context(client, destructive_settings),
        PACKAGE,
        "project",
        {"4.17.21": [3], "all": [4], "4.17.20": []},
        scope_id="git+github.com/acme/widget",
    )
    await client.aclose()

    assert _body(route.calls.last.request) == {
        "packageId": PACKAGE,
        "scope": "project",
        "newLabelIds": {"4.17.21": [3], "all": [4], "4.17.20": []},
        "scopeId": "git+github.com/acme/widget",
    }
    assert result["endpoint"] == "PUT /package-label-assignments"


@pytest.mark.asyncio
async def test_delete_organization_label_endpoint(destructive_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{BASE}/organizations/labels/7").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(destructive_settings)
    result = await labels.delete_organization_label(make_context(client, destructive_settings), 7)
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /organizations/labels/{id}"
    assert result["data"]["deleted"] == 7
