"""Tests for the FOSSA HTTP client: auth, encoding, errors, and retries."""

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
    from urllib.parse import quote

    encoded = quote(locator, safe="")
    respx_mock.get(f"https://app.fossa.com/api/projects/{encoded}").mock(
        return_value=httpx.Response(200, json={})
    )
    client = FossaClient(settings)
    await client.request_json("GET", f"/projects/{encoded}")
    await client.aclose()

    # No application-created double-encoding, e.g. "%2F" becoming "%252F".
    assert "%25" not in encoded


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
