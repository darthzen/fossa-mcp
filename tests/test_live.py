"""Live smoke tests against the real FOSSA API.

Skipped unless FOSSA_API_TOKEN is set. Never mutates data and never assumes
any project exists in the target FOSSA organization.
"""

import os

import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings

pytestmark = pytest.mark.live

requires_live_token = pytest.mark.skipif(
    not os.environ.get("FOSSA_API_TOKEN"),
    reason="FOSSA_API_TOKEN not set; skipping live FOSSA API smoke test",
)


@requires_live_token
@pytest.mark.asyncio
async def test_live_list_one_project_and_optionally_fetch_it():
    settings = Settings()
    client = FossaClient(settings)
    try:
        result = await client.request_json("GET", "/v2/projects", params=[("count", "1")])
        assert isinstance(result, (dict, list))

        projects = result.get("projects") if isinstance(result, dict) else result
        if projects:
            locator = projects[0].get("locator") or projects[0].get("id")
            if locator:
                from urllib.parse import quote

                encoded = quote(str(locator), safe="")
                project = await client.request_json("GET", f"/projects/{encoded}")
                assert isinstance(project, dict)
    finally:
        await client.aclose()
