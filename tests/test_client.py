"""Tests for the FOSSA HTTP client: auth, encoding, errors, retries, and the
response shapes FOSSA answers with that a plain `.json()` cannot express."""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.errors import FossaApiError


@pytest.mark.asyncio
async def test_authorization_header_sent(settings, respx_mock):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(200, json={"projects": []})
    )
    client = FossaClient(settings)
    await client.request_json("GET", "/v2/projects")
    await client.aclose()

    assert route.calls.last.request.headers["Authorization"] == "Bearer test-token"
    assert route.calls.last.request.headers["Accept"] == "application/json"
    assert "fossa-mcp/" in route.calls.last.request.headers["User-Agent"]


@pytest.mark.asyncio
async def test_no_double_api_prefix(settings, respx_mock):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(200, json={})
    )
    client = FossaClient(settings)
    await client.request_json("GET", "/v2/projects")
    await client.aclose()

    url = str(route.calls.last.request.url)
    assert url == "https://app.fossa.com/api/v2/projects"
    assert "/api/api" not in url


@pytest.mark.parametrize(
    "locator",
    [
        "git+github.com/acme/widget",
        "git+github.com/acme/widget$abc123",
        "npm+lodash$4.17.21",
        "custom+1234/example",
    ],
)
@pytest.mark.asyncio
async def test_locator_path_encoding_no_double_encoding(settings, respx_mock, locator):
    from urllib.parse import quote, unquote

    encoded = quote(locator, safe="")
    route = respx_mock.get(f"https://app.fossa.com/api/projects/{encoded}").mock(
        return_value=httpx.Response(200, json={})
    )
    client = FossaClient(settings)
    await client.request_json("GET", f"/projects/{encoded}")
    await client.aclose()

    # Assert on the path httpx actually put on the wire: the locator must be
    # encoded exactly once, so a single unquote round-trip recovers it and no
    # "%2F" was re-encoded into "%252F".
    raw_path = route.calls.last.request.url.raw_path.decode()
    assert raw_path == f"/api/projects/{encoded}"
    assert "%25" not in raw_path
    assert unquote(raw_path) == f"/api/projects/{locator}"


@pytest.mark.asyncio
async def test_query_values_are_not_preencoded(settings, respx_mock):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    client = FossaClient(settings)
    await client.request_json("GET", "/v2/issues", params=[("filter[search]", "log4j & shell x/y")])
    await client.aclose()

    request = route.calls.last.request
    assert httpx.QueryParams(request.url.query.decode())["filter[search]"] == "log4j & shell x/y"


@pytest.mark.asyncio
async def test_repeated_query_params_round_trip(settings, respx_mock):
    route = respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(200, json={"issues": []})
    )
    client = FossaClient(settings)
    await client.request_json(
        "GET",
        "/v2/issues",
        params=[("filter[severity][]", "critical"), ("filter[severity][]", "high")],
    )
    await client.aclose()

    query = str(route.calls.last.request.url.query, "utf-8")
    assert "filter%5Bseverity%5D%5B%5D=critical" in query
    assert "filter%5Bseverity%5D%5B%5D=high" in query


@pytest.mark.asyncio
async def test_token_not_in_exception_text(settings, respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(
            401, json={"message": "Invalid token", "name": "UnauthorizedError"}
        )
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json("GET", "/v2/projects")
    await client.aclose()

    assert "test-token" not in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 403, 404, 500])
async def test_error_status_codes_raise_with_fossa_error_shape(settings, respx_mock, status_code):
    respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(
            status_code,
            json={
                "uuid": "abc-123",
                "code": 2004,
                "message": "Something went wrong",
                "name": "SomeError",
                "httpStatusCode": status_code,
            },
        )
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json("GET", "/v2/projects")
    await client.aclose()

    err = excinfo.value
    assert err.status_code == status_code
    assert err.error_name == "SomeError"
    assert err.fossa_code == 2004
    assert err.reference_uuid == "abc-123"
    assert "Something went wrong" in str(err)


@pytest.mark.asyncio
async def test_malformed_json_error_body(settings, respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(500, text="<html>not json</html>")
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json("GET", "/v2/projects")
    await client.aclose()

    assert excinfo.value.status_code == 500


@pytest.mark.asyncio
async def test_timeout_error_message_is_safe(settings, respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        side_effect=httpx.ReadTimeout("timed out")
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json("GET", "/v2/projects")
    await client.aclose()

    assert "timed out" in str(excinfo.value)
    assert "test-token" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_connection_error(settings, respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        side_effect=httpx.ConnectError("boom")
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError):
        await client.request_json("GET", "/v2/projects")
    await client.aclose()


@pytest.mark.asyncio
async def test_issue_202_is_not_an_error(settings, respx_mock):
    respx_mock.get("https://app.fossa.com/api/v2/issues").mock(
        return_value=httpx.Response(202, json={"message": "analysis in progress"})
    )
    client = FossaClient(settings)
    status_code, body = await client.request_json_with_status("GET", "/v2/issues")
    await client.aclose()

    assert status_code == 202
    assert body == {"message": "analysis in progress"}


@pytest.mark.asyncio
async def test_retries_on_503_then_succeeds(settings, respx_mock):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects")
    route.side_effect = [
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(200, json={"ok": True}),
    ]
    client = FossaClient(settings)
    result = await client.request_json("GET", "/v2/projects")
    await client.aclose()

    assert result == {"ok": True}
    assert route.call_count == 3


@pytest.mark.asyncio
async def test_gives_up_after_max_retries(settings, respx_mock):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(503)
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json("GET", "/v2/projects")
    await client.aclose()

    # initial attempt + 2 retries = 3 total
    assert route.call_count == 3
    assert excinfo.value.status_code == 503


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 409, 422])
async def test_does_not_retry_non_retryable_status_codes(settings, respx_mock, status_code):
    route = respx_mock.get("https://app.fossa.com/api/v2/projects").mock(
        return_value=httpx.Response(status_code, json={"message": "no"})
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError):
        await client.request_json("GET", "/v2/projects")
    await client.aclose()

    assert route.call_count == 1


# --- bodyless 2xx, array bodies, scalars, and redirects ----------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(204),
        httpx.Response(200, content=b""),
        httpx.Response(200, content=b"   \n"),
        httpx.Response(201, content=b""),
    ],
)
async def test_request_json_optional_returns_none_for_an_empty_2xx(settings, respx_mock, response):
    """A successful request that carries no body is a success, not an error.

    `request_json` calls `.json()` on every 2xx and reports the parse failure as
    a `FossaApiError`, which is why five domain modules had each grown a private
    helper that caught that error and re-inspected its status code.
    """
    respx_mock.delete("https://app.fossa.com/api/teams/7").mock(return_value=response)
    client = FossaClient(settings)
    body = await client.request_json_optional("DELETE", "/teams/7")
    await client.aclose()

    assert body is None


@pytest.mark.asyncio
async def test_request_json_optional_returns_a_parsed_2xx_body(settings, respx_mock):
    respx_mock.delete("https://app.fossa.com/api/jira/3").mock(
        return_value=httpx.Response(200, json={"id": 3, "deleted": False})
    )
    client = FossaClient(settings)
    body = await client.request_json_optional("DELETE", "/jira/3")
    await client.aclose()

    assert body == {"id": 3, "deleted": False}


@pytest.mark.asyncio
async def test_request_json_optional_still_rejects_a_non_empty_invalid_body(settings, respx_mock):
    """Empty is not the same as unparseable, and the two must not be conflated.

    The helpers this method replaced mapped *any* unparseable 2xx to `None`, so
    an HTML error page served with a 200 would have read as a clean success.
    """
    respx_mock.delete("https://app.fossa.com/api/teams/7").mock(
        return_value=httpx.Response(200, content=b"<html>gateway</html>")
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json_optional("DELETE", "/teams/7")
    await client.aclose()

    assert excinfo.value.status_code == 200


@pytest.mark.asyncio
async def test_request_json_optional_propagates_an_error_status(settings, respx_mock):
    respx_mock.delete("https://app.fossa.com/api/teams/7").mock(
        return_value=httpx.Response(403, json={"message": "nope", "name": "ForbiddenError"})
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_json_optional("DELETE", "/teams/7")
    await client.aclose()

    assert excinfo.value.status_code == 403


@pytest.mark.asyncio
async def test_a_bare_array_is_a_valid_request_body(settings, respx_mock):
    """Several endpoints take a top-level JSON array, not an object.

    The organization-settings propagate endpoints take an array of field names
    and two settings sections take an array outright. `httpx` always handled
    this — only the `json_body` annotation was too narrow, which is what pushed
    `tools/org_settings.py` into casting at the call site.
    """
    route = respx_mock.patch(
        "https://app.fossa.com/api/organizations/1/settings/projects/issues/security"
    ).mock(return_value=httpx.Response(204))
    client = FossaClient(settings)
    body = await client.request_json_optional(
        "PATCH",
        "/organizations/1/settings/projects/issues/security",
        json_body=["projectDefaultSecurityStatusCheckEnabled"],
    )
    await client.aclose()

    assert body is None
    assert json.loads(route.calls.last.request.content) == [
        "projectDefaultSecurityStatusCheckEnabled"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [1, 0, "2026-07-30T12:00:00Z", True])
async def test_request_json_returns_non_object_json_unchanged(settings, respx_mock, payload):
    """`GET /counts/builds` answers with a bare JSON number.

    Verified live: `?projectId=<locator>` returns the single byte `1`. Other
    endpoints answer with a bare string (`last-published`). The old
    `dict | list` return annotation was simply untrue.
    """
    respx_mock.get("https://app.fossa.com/api/counts/builds").mock(
        return_value=httpx.Response(200, json=payload)
    )
    client = FossaClient(settings)
    result = await client.request_json("GET", "/counts/builds")
    await client.aclose()

    assert result == payload


@pytest.mark.asyncio
async def test_request_redirect_location_returns_the_target_without_following_it(
    settings, respx_mock
):
    """The whole payload of the GitHub App endpoint is its `Location` header.

    Verified live: two consecutive calls returned the same constant target with
    an empty body and no `state`, `code`, or nonce on it. Following it would
    fetch a GitHub HTML page no client can use, so the redirect is read, not
    chased.
    """
    target = "https://github.com/apps/fossa-integration/installations/new"
    route = respx_mock.get("https://app.fossa.com/api/services/github-app/installation-url").mock(
        return_value=httpx.Response(302, headers={"location": target})
    )
    github = respx_mock.get(target).mock(return_value=httpx.Response(200, html="<html></html>"))

    client = FossaClient(settings)
    status_code, location = await client.request_redirect_location(
        "GET", "/services/github-app/installation-url"
    )
    await client.aclose()

    assert (status_code, location) == (302, target)
    assert route.call_count == 1
    assert not github.called


@pytest.mark.asyncio
async def test_request_redirect_location_raises_on_an_error_status(settings, respx_mock):
    respx_mock.get("https://app.fossa.com/api/services/github-app/installation-url").mock(
        return_value=httpx.Response(404, json={"message": "not configured"})
    )
    client = FossaClient(settings)
    with pytest.raises(FossaApiError) as excinfo:
        await client.request_redirect_location("GET", "/services/github-app/installation-url")
    await client.aclose()

    assert excinfo.value.status_code == 404
