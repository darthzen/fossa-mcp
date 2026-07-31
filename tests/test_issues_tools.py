"""Endpoint contract tests for the issue, issue overview, and issue filter tools.

`tests/test_tools.py` already covers `list_issues` and `get_issue`; this module
covers everything added by the API-parity work. Each tool gets one test that
pins the method, path, exact query pairs, and exact JSON body, and each gated
tool gets a test proving the refusal happens before any request is constructed.
"""

import json
from datetime import date, datetime

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import issues

API = "https://app.fossa.com/api"
PROJECT = "git+github.com/acme/widget"
REVISION = "abc123"


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


# --- facets ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_issue_facets_categories_sends_scope_only(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/categories").mock(
        return_value=httpx.Response(200, json={"licensing": 3})
    )

    client = FossaClient(settings)
    result = await issues.get_issue_facets(make_context(client, settings), "categories")
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [("scope[type]", "global")]
    assert result["endpoint"] == "GET /v2/issues/categories"
    assert result["data"] == {"licensing": 3}


@pytest.mark.asyncio
async def test_get_issue_facets_package_managers_scoped_to_a_revision(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{API}/v2/issues/package-managers").mock(
        return_value=httpx.Response(200, json=["pip"])
    )

    client = FossaClient(settings)
    await issues.get_issue_facets(
        make_context(client, settings),
        "package-managers",
        category="vulnerability",
        status="ignored",
        scope_type="project",
        project_locator=PROJECT,
        revision_locator=f"{PROJECT}${REVISION}",
        team_ids=["7", "9"],
    )
    await client.aclose()

    # The revision locator is normalized back to the bare revision id, which is
    # what `scope[revision]` wants.
    assert _query_pairs(route.calls.last.request) == [
        ("category", "vulnerability"),
        ("status", "ignored"),
        ("scope[type]", "project"),
        ("scope[id]", PROJECT),
        ("scope[revision]", REVISION),
        ("teamId", "7"),
        ("teamId", "9"),
    ]


@pytest.mark.asyncio
async def test_get_issue_facets_rejects_mismatched_arguments(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(ValueError, match="not accepted by the categories facet"):
        await issues.get_issue_facets(ctx, "categories", category="licensing")

    with pytest.raises(ValueError, match="only applies to the licensing category"):
        await issues.get_issue_facets(ctx, "license-list", category="vulnerability")

    with pytest.raises(ValueError, match="category is required for the statuses facet"):
        await issues.get_issue_facets(ctx, "statuses")

    with pytest.raises(ValueError, match="status is not accepted by the types facet"):
        await issues.get_issue_facets(ctx, "types", status="active")

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- issue revisions ---------------------------------------------------------


@pytest.mark.asyncio
async def test_list_issue_revisions_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/revisions").mock(
        return_value=httpx.Response(200, json={"revisions": []})
    )

    client = FossaClient(settings)
    result = await issues.list_issue_revisions(
        make_context(client, settings),
        category="vulnerability",
        scope_type="project",
        project_locator=PROJECT,
        revision_locator=REVISION,
        compare_to_revision="def456",
        change_status="new",
        search="log4j",
        depths=["direct"],
        package_managers=["mvn"],
        severity=["critical", "high"],
        found_after=datetime(2026, 1, 1),
        sort="issue_count_desc",
        team_ids=["7"],
        page=2,
        count=50,
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("category", "vulnerability"),
        ("status", "active"),
        ("scope[type]", "project"),
        ("scope[id]", PROJECT),
        ("scope[revision]", REVISION),
        ("scope[compareTo][revision]", "def456"),
        ("scope[compareTo][changeStatus]", "new"),
        ("filter[depths][]", "direct"),
        ("filter[packageManagers][]", "mvn"),
        ("filter[severity][]", "critical"),
        ("filter[severity][]", "high"),
        ("filter[search]", "log4j"),
        ("filter[foundAfter]", "2026-01-01T00:00:00"),
        ("sort", "issue_count_desc"),
        ("teamId", "7"),
        ("page", "2"),
        ("count", "50"),
    ]
    assert result["endpoint"] == "GET /v2/issues/revisions"


@pytest.mark.asyncio
async def test_list_issue_revisions_rejects_count_over_max_page_size(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError):
        await issues.list_issue_revisions(
            make_context(client, settings),
            category="licensing",
            count=settings.fossa_max_page_size + 1,
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- comparison summaries ----------------------------------------------------


@pytest.mark.asyncio
async def test_compare_issue_summaries_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/compare/summaries").mock(
        return_value=httpx.Response(200, json={"new": 2, "remediated": 1})
    )

    client = FossaClient(settings)
    result = await issues.compare_issue_summaries(
        make_context(client, settings),
        category="vulnerability",
        project_locator=PROJECT,
        revision_locator=REVISION,
        compare_to_revision=f"{PROJECT}$def456",
        change_status="new",
        cwes=["CWE-79"],
        severity=["critical"],
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("category", "vulnerability"),
        ("scope[type]", "project"),
        ("scope[id]", PROJECT),
        ("scope[revision]", REVISION),
        ("scope[compareTo][revision]", "def456"),
        ("scope[compareTo][changeStatus]", "new"),
        ("filter[cwes][]", "CWE-79"),
        ("filter[severity][]", "critical"),
    ]
    assert result["data"]["new"] == 2


@pytest.mark.asyncio
async def test_compare_issue_summaries_rejects_cwes_for_licensing(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="cwes filter"):
        await issues.compare_issue_summaries(
            make_context(client, settings),
            category="licensing",
            project_locator=PROJECT,
            revision_locator=REVISION,
            compare_to_revision="def456",
            cwes=["CWE-79"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- affected projects -------------------------------------------------------


@pytest.mark.asyncio
async def test_get_issue_affected_projects_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/512/affected-projects").mock(
        return_value=httpx.Response(200, json=[{"id": PROJECT}])
    )

    client = FossaClient(settings)
    result = await issues.get_issue_affected_projects(
        make_context(client, settings), 512, "vulnerability"
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("category", "vulnerability"),
        ("scope[type]", "global"),
    ]
    assert result["endpoint"] == "GET /v2/issues/{issueId}/affected-projects"


@pytest.mark.asyncio
async def test_get_issue_affected_projects_rejects_locator_in_global_scope(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="must be None for global scope"):
        await issues.get_issue_affected_projects(
            make_context(client, settings), 512, "vulnerability", project_locator=PROJECT
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- global CSV export -------------------------------------------------------


@pytest.mark.asyncio
async def test_export_global_issues_csv_returns_task_metadata(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/csv/global").mock(
        return_value=httpx.Response(
            200,
            json={"id": 5, "task": "ExportGlobalIssues", "jobToken": "tok"},
        )
    )

    client = FossaClient(settings)
    result = await issues.export_global_issues_csv(
        make_context(client, settings), email=True, team_ids=["7"]
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [("email", "true"), ("teamIds", "7")]
    assert result["data"]["jobToken"] == "tok"


@pytest.mark.asyncio
async def test_export_global_issues_csv_reports_a_streamed_archive(
    settings, respx_mock, make_context
):
    respx_mock.get(f"{API}/v2/issues/csv/global").mock(
        return_value=httpx.Response(
            200, content=b"PK\x03\x04", headers={"content-type": "application/octet-stream"}
        )
    )

    client = FossaClient(settings)
    result = await issues.export_global_issues_csv(make_context(client, settings), email=False)
    await client.aclose()

    assert result["data"]["delivered"] == "stream"
    assert result["data"]["content_type"] == "application/octet-stream"


# --- exception reads ---------------------------------------------------------


@pytest.mark.asyncio
async def test_get_issue_exceptions_list_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/exceptions").mock(
        return_value=httpx.Response(200, json={"exceptions": []})
    )

    client = FossaClient(settings)
    result = await issues.get_issue_exceptions(
        make_context(client, settings),
        category="licensing",
        project_id="custom+1/widget",
        release_group_id=4,
        search="MIT",
        sort_by="package",
        order_by="desc",
        page=3,
        count=25,
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("filters[category]", "licensing"),
        ("filters[projectId]", "custom+1/widget"),
        ("filters[releaseGroupId]", "4"),
        ("search", "MIT"),
        ("sortBy", "package"),
        ("orderBy", "desc"),
        ("page", "3"),
        ("count", "25"),
    ]
    assert result["endpoint"] == "GET /v2/issues/exceptions"


@pytest.mark.asyncio
async def test_get_issue_exceptions_by_id(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/v2/issues/exceptions/12").mock(
        return_value=httpx.Response(200, json={"id": 12})
    )

    client = FossaClient(settings)
    result = await issues.get_issue_exceptions(make_context(client, settings), exception_id=12)
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == []
    assert result["endpoint"] == "GET /v2/issues/exceptions/{id}"


@pytest.mark.asyncio
async def test_get_issue_exceptions_rejects_mixed_arguments(settings, respx_mock, make_context):
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    with pytest.raises(ValueError, match="category is required when listing"):
        await issues.get_issue_exceptions(ctx)

    with pytest.raises(ValueError, match="must be None when exception_id is given"):
        await issues.get_issue_exceptions(ctx, exception_id=12, category="licensing")

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- write gate --------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_issues_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await issues.update_issues(
            make_context(client, settings), "ignore", "vulnerability", issue_ids=[1]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_issues_by_filter_needs_the_destructive_tier(
    writable_settings, respx_mock, make_context
):
    """Writes enabled is not enough when the target set is a filter."""
    client = FossaClient(writable_settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await issues.update_issues(
            make_context(client, writable_settings),
            "ignore",
            "vulnerability",
            severity=["critical"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_issues_refuses_an_unbounded_target_set(
    destructive_settings, respx_mock, make_context
):
    """Even at the destructive tier, "every issue in the org" is not offered."""
    client = FossaClient(destructive_settings)

    with pytest.raises(ValueError, match="refusing to act on every issue"):
        await issues.update_issues(
            make_context(client, destructive_settings), "ignore", "vulnerability"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_extend_issue_exception_refuses_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError):
        await issues.extend_issue_exception(make_context(client, settings), 12, None)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_issue_exceptions_refuses_without_destructive_tier(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await issues.delete_issue_exceptions(
            make_context(client, writable_settings), exception_id=12
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_create_issue_dispute_refuses_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError):
        await issues.create_issue_dispute(
            make_context(client, settings), 512, "LICENSE_DETECTION_FALSE_POSITIVE"
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_export_issue_overview_refuses_when_writes_disabled(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError):
        await issues.export_issue_overview(make_context(client, settings))
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_save_issue_filter_refuses_when_writes_disabled(settings, respx_mock, make_context):
    client = FossaClient(settings)

    with pytest.raises(FossaWriteNotPermittedError):
        await issues.save_issue_filter(
            make_context(client, settings),
            "Critical only",
            {"severity": "critical"},
            category="vulnerability",
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_issue_filter_refuses_without_destructive_tier(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)

    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await issues.delete_issue_filter(make_context(client, writable_settings), 3)
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- issue writes ------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_issues_by_id_sends_expected_query_and_body(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{API}/v2/issues").mock(return_value=httpx.Response(200, json={}))

    client = FossaClient(writable_settings)
    result = await issues.update_issues(
        make_context(client, writable_settings),
        "ignore",
        "vulnerability",
        issue_ids=[11, 12],
        notes="accepted risk",
        reason="Vulnerable_code_not_in_execute_path",
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert _query_pairs(request) == [
        ("category", "vulnerability"),
        ("status", "active"),
        ("scope[type]", "global"),
        ("ids[]", "11"),
        ("ids[]", "12"),
    ]
    assert json.loads(request.content) == {
        "type": "ignore",
        "notes": "accepted risk",
        "reason": "Vulnerable_code_not_in_execute_path",
    }
    assert result["data"]["targeted_by_filter"] is False
    assert result["data"]["tier"] == "write"


@pytest.mark.asyncio
async def test_update_issues_creates_an_exception_over_a_filter(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{API}/v2/issues").mock(
        return_value=httpx.Response(200, json={"updated": 4})
    )

    client = FossaClient(destructive_settings)
    result = await issues.update_issues(
        make_context(client, destructive_settings),
        "issueException",
        "licensing",
        scope_type="project",
        project_locator=PROJECT,
        revision_locator=REVISION,
        licenses=["GPL-3.0"],
        package_scope="ALL_VERSIONS",
        ignore_scope="PROJECT",
        expires_after=date(2026, 12, 31),
        license_id="GPL-3.0",
        notes="legal signed off",
    )
    await client.aclose()

    request = route.calls.last.request
    assert _query_pairs(request) == [
        ("category", "licensing"),
        ("status", "active"),
        ("scope[type]", "project"),
        ("scope[id]", PROJECT),
        ("scope[revision]", REVISION),
        ("filter[licenses][]", "GPL-3.0"),
    ]
    assert json.loads(request.content) == {
        "type": "issueException",
        "notes": "legal signed off",
        "packageScope": "ALL_VERSIONS",
        "ignoreScope": "PROJECT",
        "expiresAfter": "2026-12-31",
        "licenseId": "GPL-3.0",
    }
    assert result["data"]["targeted_by_filter"] is True
    assert result["data"]["tier"] == "destructive"


@pytest.mark.asyncio
async def test_update_issues_rejects_exception_fields_on_other_actions(
    destructive_settings, respx_mock, make_context
):
    client = FossaClient(destructive_settings)

    with pytest.raises(ValueError, match="only allowed for the issueException action"):
        await issues.update_issues(
            make_context(client, destructive_settings),
            "unignore",
            "licensing",
            issue_ids=[1],
            ignore_scope="PROJECT",
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_extend_issue_exception_sends_a_null_expiry(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{API}/v2/issues/exceptions/12").mock(return_value=httpx.Response(204))

    client = FossaClient(writable_settings)
    result = await issues.extend_issue_exception(make_context(client, writable_settings), 12, None)
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert json.loads(request.content) == {"expiresAfter": None}
    # A 204 carries no body; that is success, not a parse failure.
    assert result["ok"] is True
    assert result["data"]["result"] is None


@pytest.mark.asyncio
async def test_extend_issue_exception_sends_a_date(writable_settings, respx_mock, make_context):
    route = respx_mock.put(f"{API}/v2/issues/exceptions/12").mock(return_value=httpx.Response(204))

    client = FossaClient(writable_settings)
    await issues.extend_issue_exception(
        make_context(client, writable_settings), 12, date(2026, 12, 31)
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {"expiresAfter": "2026-12-31"}


@pytest.mark.asyncio
async def test_delete_issue_exception_by_id(destructive_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{API}/v2/issues/exceptions/12").mock(
        return_value=httpx.Response(200, json=7)
    )

    client = FossaClient(destructive_settings)
    result = await issues.delete_issue_exceptions(
        make_context(client, destructive_settings), exception_id=12
    )
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /v2/issues/exceptions/{id}"
    assert result["data"]["issues_unignored"] == 7


@pytest.mark.asyncio
async def test_delete_issue_exceptions_by_id_list(destructive_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{API}/v2/issues/exceptions").mock(
        return_value=httpx.Response(200, json={"count": 2})
    )

    client = FossaClient(destructive_settings)
    result = await issues.delete_issue_exceptions(
        make_context(client, destructive_settings), exception_ids=[1, 2]
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {"kind": "idList", "value": [1, 2]}
    assert result["data"]["result"] == {"count": 2}


@pytest.mark.asyncio
async def test_delete_issue_exceptions_by_filter(destructive_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{API}/v2/issues/exceptions").mock(
        return_value=httpx.Response(200, json={"count": 5})
    )

    client = FossaClient(destructive_settings)
    await issues.delete_issue_exceptions(
        make_context(client, destructive_settings),
        category="licensing",
        project_id="custom+1/widget",
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "kind": "all",
        "filters": {"category": "licensing", "projectId": "custom+1/widget"},
    }


@pytest.mark.asyncio
async def test_delete_issue_exceptions_requires_exactly_one_target(
    destructive_settings, respx_mock, make_context
):
    client = FossaClient(destructive_settings)
    ctx = make_context(client, destructive_settings)

    with pytest.raises(ValueError, match="exactly one of"):
        await issues.delete_issue_exceptions(ctx)

    with pytest.raises(ValueError, match="exactly one of"):
        await issues.delete_issue_exceptions(ctx, exception_id=1, exception_ids=[2])

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_create_issue_dispute_sends_expected_body(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{API}/v2/issues/512/disputes").mock(
        return_value=httpx.Response(200, json={"id": 3})
    )

    client = FossaClient(writable_settings)
    result = await issues.create_issue_dispute(
        make_context(client, writable_settings),
        512,
        "LICENSE_DETECTION_FALSE_POSITIVE",
        comment="vendored under a different license",
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "reason": "LICENSE_DETECTION_FALSE_POSITIVE",
        "comment": "vendored under a different license",
    }
    assert result["data"]["dispute"] == {"id": 3}


# --- issue overview ----------------------------------------------------------


@pytest.mark.asyncio
async def test_get_issue_overview_query(settings, respx_mock, make_context):
    route = respx_mock.get(f"{API}/issue_counts").mock(
        return_value=httpx.Response(200, json={"counts": [], "totalProjects": 9})
    )

    client = FossaClient(settings)
    result = await issues.get_issue_overview(
        make_context(client, settings),
        start=datetime(2026, 1, 1),
        end=datetime(2026, 2, 1),
        category="vulnerability",
        project_id="custom+1/widget",
        label_ids=[3, 4],
        team_ids=["7"],
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("start", "2026-01-01T00:00:00"),
        ("end", "2026-02-01T00:00:00"),
        ("labels[]", "3"),
        ("labels[]", "4"),
        ("category", "vulnerability"),
        ("projectId", "custom+1/widget"),
        ("teamId", "7"),
    ]
    assert result["data"]["totalProjects"] == 9


@pytest.mark.asyncio
async def test_get_issue_overview_rejects_a_reversed_window(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="start must not be after end"):
        await issues.get_issue_overview(
            make_context(client, settings),
            start=datetime(2026, 2, 1),
            end=datetime(2026, 1, 1),
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_export_issue_overview_posts_with_the_same_query(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{API}/issue_counts/export").mock(
        return_value=httpx.Response(200, json={"task": "ExportIssueSnapshots", "jobToken": "tok"})
    )

    client = FossaClient(writable_settings)
    result = await issues.export_issue_overview(
        make_context(client, writable_settings), category="licensing"
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert _query_pairs(request) == [("category", "licensing")]
    assert result["data"]["jobToken"] == "tok"


# --- saved issue filters -----------------------------------------------------


@pytest.mark.asyncio
async def test_get_issue_filters_list_and_by_id(settings, respx_mock, make_context):
    list_route = respx_mock.get(f"{API}/issue-filters").mock(
        return_value=httpx.Response(200, json=[{"id": 3}])
    )
    one_route = respx_mock.get(f"{API}/issue-filters/3").mock(
        return_value=httpx.Response(200, json={"id": 3})
    )

    client = FossaClient(settings)
    ctx = make_context(client, settings)
    listed = await issues.get_issue_filters(ctx, category="vulnerability")
    single = await issues.get_issue_filters(ctx, filter_id=3)
    await client.aclose()

    assert _query_pairs(list_route.calls.last.request) == [("category", "vulnerability")]
    assert _query_pairs(one_route.calls.last.request) == []
    assert listed["endpoint"] == "GET /issue-filters"
    assert single["endpoint"] == "GET /issue-filters/{filterId}"


@pytest.mark.asyncio
async def test_get_issue_filters_rejects_category_with_filter_id(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="category must be None"):
        await issues.get_issue_filters(
            make_context(client, settings), category="licensing", filter_id=3
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_save_issue_filter_creates(writable_settings, respx_mock, make_context):
    route = respx_mock.post(f"{API}/issue-filters").mock(
        return_value=httpx.Response(200, json={"id": 3})
    )

    client = FossaClient(writable_settings)
    result = await issues.save_issue_filter(
        make_context(client, writable_settings),
        "Critical only",
        {"severity": "critical", "hasFix": "has_fix"},
        category="vulnerability",
        sort="severity_desc",
        group="issue",
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "name": "Critical only",
        "filter": {"severity": "critical", "hasFix": "has_fix"},
        "category": "vulnerability",
        "sort": "severity_desc",
        "group": "issue",
    }
    assert result["endpoint"] == "POST /issue-filters"


@pytest.mark.asyncio
async def test_save_issue_filter_updates(writable_settings, respx_mock, make_context):
    route = respx_mock.put(f"{API}/issue-filters/3").mock(
        return_value=httpx.Response(200, json={"id": 3})
    )

    client = FossaClient(writable_settings)
    result = await issues.save_issue_filter(
        make_context(client, writable_settings),
        "Critical only",
        {"severity": "critical"},
        filter_id=3,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "PUT"
    assert json.loads(request.content) == {
        "name": "Critical only",
        "filter": {"severity": "critical"},
    }
    assert result["endpoint"] == "PUT /issue-filters/{filterId}"


@pytest.mark.asyncio
async def test_save_issue_filter_rejects_changing_category(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValueError, match="category cannot be changed"):
        await issues.save_issue_filter(
            make_context(client, writable_settings),
            "Critical only",
            {"severity": "critical"},
            filter_id=3,
            category="vulnerability",
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_issue_filter_tolerates_an_empty_body(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{API}/issue-filters/3").mock(return_value=httpx.Response(200))

    client = FossaClient(destructive_settings)
    result = await issues.delete_issue_filter(make_context(client, destructive_settings), 3)
    await client.aclose()

    assert route.calls.last.request.method == "DELETE"
    assert result["ok"] is True
    assert result["data"] == {"filter_id": 3, "result": None}
