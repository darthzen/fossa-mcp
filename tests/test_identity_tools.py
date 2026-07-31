"""Endpoint contract tests for the federated-identity tools (OIDC and SAML).

Covers the HTTP shape of every OIDC and SAML operation the server exposes, the
exact JSON body each write sends, the refusal path in all three gate states
(writes off; writes on and admin off; admin on and writes off), and the two
safety behaviors this domain adds on top of the API: the wildcard-only `sub`
claim is refused, and the FOSSA API token minted by the token exchange never
reaches a tool result.
"""

import json

import httpx
import pytest

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaWriteNotPermittedError
from fossa_mcp.tools import identity

BASE = "https://app.fossa.com/api"
SUB_CLAIM = {"claim": "sub", "value": "repo:acme/widget:ref:refs/heads/main"}


@pytest.fixture
def admin_settings() -> Settings:
    """Both flags on: the only state in which an ADMIN tool may run."""
    return Settings(
        fossa_api_token="test-token",
        fossa_allow_writes=True,
        fossa_allow_admin=True,
        _env_file=None,  # type: ignore[call-arg]
    )


@pytest.fixture
def full_settings() -> Settings:
    """Writes, admin, and destructive all on — what the three deletes require."""
    return Settings(
        fossa_api_token="test-token",
        fossa_allow_writes=True,
        fossa_allow_admin=True,
        fossa_allow_destructive=True,
        _env_file=None,  # type: ignore[call-arg]
    )


@pytest.fixture
def writes_only_settings() -> Settings:
    """Writes enabled, admin still off."""
    return Settings(fossa_api_token="test-token", fossa_allow_writes=True, _env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def admin_only_settings() -> Settings:
    """Admin enabled but writes off — a half-configured deployment must fail closed."""
    return Settings(fossa_api_token="test-token", fossa_allow_admin=True, _env_file=None)  # type: ignore[call-arg]


def _query_pairs(request: httpx.Request) -> list[tuple[str, str]]:
    return httpx.QueryParams(request.url.query.decode()).multi_items()


# --- OIDC reads --------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_oidc_providers_sends_pagination_and_scope_filter(
    settings, respx_mock, make_context
):
    route = respx_mock.get(f"{BASE}/oidc/providers").mock(
        return_value=httpx.Response(200, json={"results": [], "pageSize": 25, "last": 0})
    )

    client = FossaClient(settings)
    result = await identity.list_oidc_providers(
        make_context(client, settings),
        page_size=25,
        prev=123,
        filter_scope="team",
        filter_scope_id=789,
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "GET"
    assert _query_pairs(request) == [
        ("pageSize", "25"),
        ("prev", "123"),
        ("filter[scope]", "team"),
        ("filter[scopeId]", "789"),
    ]
    assert result["endpoint"] == "GET /oidc/providers"
    assert result["data"]["pageSize"] == 25


@pytest.mark.asyncio
async def test_list_oidc_providers_rejects_team_scope_without_an_id(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(ValueError, match="filter_scope_id"):
        await identity.list_oidc_providers(make_context(client, settings), filter_scope="team")
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_get_oidc_provider_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/oidc/providers/42").mock(
        return_value=httpx.Response(200, json={"id": 42, "issuer": "https://token.actions.example"})
    )

    client = FossaClient(settings)
    result = await identity.get_oidc_provider(make_context(client, settings), 42)
    await client.aclose()

    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == "GET /oidc/providers/{id}"
    assert result["data"]["issuer"] == "https://token.actions.example"


@pytest.mark.asyncio
async def test_list_oidc_provider_service_accounts_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/oidc/providers/42/available-service-accounts").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [{"id": 7, "username": "ci-bot", "email": "ci@acme.example"}],
                "pageSize": 10,
                "last": 7,
            },
        )
    )

    client = FossaClient(settings)
    result = await identity.list_oidc_provider_service_accounts(
        make_context(client, settings), 42, team_id=5
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("pageSize", "10"),
        ("prev", "0"),
        ("teamId", "5"),
    ]
    assert result["endpoint"] == "GET /oidc/providers/{id}/available-service-accounts"
    assert result["data"]["results"][0]["username"] == "ci-bot"


@pytest.mark.asyncio
async def test_list_oidc_trust_relationships_filters(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/oidc/trust-relationships").mock(
        return_value=httpx.Response(200, json={"results": [], "pageSize": 10, "last": 0})
    )

    client = FossaClient(settings)
    result = await identity.list_oidc_trust_relationships(
        make_context(client, settings), user_id=7, provider_id=42
    )
    await client.aclose()

    assert _query_pairs(route.calls.last.request) == [
        ("pageSize", "10"),
        ("prev", "0"),
        ("userId", "7"),
        ("providerId", "42"),
    ]
    assert result["endpoint"] == "GET /oidc/trust-relationships"


@pytest.mark.asyncio
async def test_get_oidc_trust_relationship_endpoint(settings, respx_mock, make_context):
    route = respx_mock.get(f"{BASE}/oidc/trust-relationships/99").mock(
        return_value=httpx.Response(
            200, json={"id": 99, "audiences": ["fossa"], "requiredClaims": [SUB_CLAIM]}
        )
    )

    client = FossaClient(settings)
    result = await identity.get_oidc_trust_relationship(make_context(client, settings), 99)
    await client.aclose()

    assert route.calls.last.request.url.query == b""
    assert result["endpoint"] == "GET /oidc/trust-relationships/{id}"
    assert result["data"]["id"] == 99


# --- write gate --------------------------------------------------------------


def _all_writes(ctx):
    """Every gated call in this domain, as un-awaited coroutines."""
    return (
        identity.create_oidc_provider(ctx, "https://token.actions.example"),
        identity.delete_oidc_provider(ctx, 42),
        identity.create_oidc_trust_relationship(ctx, 7, 42, ["fossa"], [SUB_CLAIM]),
        identity.update_oidc_trust_relationship(ctx, 99, audiences=["fossa"]),
        identity.delete_oidc_trust_relationship(ctx, 99),
        identity.exchange_oidc_token(ctx, 42, "ci-bot", "header.payload.signature"),
        identity.update_saml_settings(
            ctx, "https://sso.example/saml2", "-----BEGIN CERTIFICATE-----", "urn:acme", 1
        ),
        identity.delete_saml_settings(ctx, 1),
    )


@pytest.mark.asyncio
async def test_every_write_refuses_and_sends_nothing_when_writes_disabled(
    settings, respx_mock, make_context
):
    assert settings.fossa_allow_writes is False
    assert settings.fossa_allow_admin is False
    client = FossaClient(settings)
    ctx = make_context(client, settings)

    for call in _all_writes(ctx):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_every_write_refuses_when_writes_are_on_but_admin_is_off(
    writes_only_settings, respx_mock, make_context
):
    assert writes_only_settings.fossa_allow_admin is False
    client = FossaClient(writes_only_settings)
    ctx = make_context(client, writes_only_settings)

    for call in _all_writes(ctx):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_ADMIN"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_every_write_refuses_when_admin_is_on_but_writes_are_off(
    admin_only_settings, respx_mock, make_context
):
    """FOSSA_ALLOW_ADMIN alone grants nothing; it is a qualifier on writes."""
    assert admin_only_settings.fossa_allow_writes is False
    client = FossaClient(admin_only_settings)
    ctx = make_context(client, admin_only_settings)

    for call in _all_writes(ctx):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


def _deletes(ctx):
    """The three deletes, which need DESTRUCTIVE on top of ADMIN."""
    return (
        identity.delete_oidc_provider(ctx, 42),
        identity.delete_oidc_trust_relationship(ctx, 99),
        identity.delete_saml_settings(ctx, 1),
    )


@pytest.mark.asyncio
async def test_deletes_refuse_when_destructive_is_off_even_with_admin_on(
    admin_settings, respx_mock, make_context
):
    """ADMIN says what kind of thing this is; DESTRUCTIVE says how bad it is wrong.

    Removing an OIDC provider, a trust relationship, or the SAML configuration
    is irreversible from here, so it needs both. Everything else in the domain
    still runs on ADMIN alone — see the test below.
    """
    assert admin_settings.fossa_allow_destructive is False
    client = FossaClient(admin_settings)
    ctx = make_context(client, admin_settings)

    for call in _deletes(ctx):
        with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
            await call

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_non_deletes_do_not_need_the_destructive_tier(
    admin_settings, respx_mock, make_context
):
    """The DESTRUCTIVE requirement is scoped to the deletes, not to the domain."""
    route = respx_mock.post(f"{BASE}/oidc/providers").mock(
        return_value=httpx.Response(200, json={"id": 42})
    )

    client = FossaClient(admin_settings)
    await identity.create_oidc_provider(
        make_context(client, admin_settings), "https://token.actions.example"
    )
    await client.aclose()

    assert route.calls.call_count == 1


# --- OIDC writes -------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_oidc_provider_sends_org_scope_without_a_scope_id(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/oidc/providers").mock(
        return_value=httpx.Response(201, json={"id": 42, "scope": "org"})
    )

    client = FossaClient(admin_settings)
    result = await identity.create_oidc_provider(
        make_context(client, admin_settings), "https://token.actions.example"
    )
    await client.aclose()

    request = route.calls.last.request
    assert request.method == "POST"
    assert json.loads(request.content) == {
        "issuer": "https://token.actions.example",
        "scope": "org",
    }
    assert result["endpoint"] == "POST /oidc/providers"
    assert result["data"]["provider"]["id"] == 42


@pytest.mark.asyncio
async def test_create_oidc_provider_sends_team_scope_with_a_scope_id(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/oidc/providers").mock(
        return_value=httpx.Response(201, json={"id": 43, "scope": "team"})
    )

    client = FossaClient(admin_settings)
    await identity.create_oidc_provider(
        make_context(client, admin_settings),
        "https://token.actions.example",
        scope="team",
        scope_id=789,
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "issuer": "https://token.actions.example",
        "scope": "team",
        "scopeId": 789,
    }


@pytest.mark.asyncio
async def test_create_oidc_provider_rejects_mismatched_scope(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    ctx = make_context(client, admin_settings)

    with pytest.raises(ValueError, match="scope_id"):
        await identity.create_oidc_provider(ctx, "https://idp.example", scope="team")
    with pytest.raises(ValueError, match="scope_id"):
        await identity.create_oidc_provider(ctx, "https://idp.example", scope="org", scope_id=1)

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_oidc_provider_tolerates_the_empty_204_body(
    full_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/oidc/providers/42").mock(return_value=httpx.Response(204))

    client = FossaClient(full_settings)
    result = await identity.delete_oidc_provider(make_context(client, full_settings), 42)
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "DELETE /oidc/providers/{id}"
    assert result["data"] == {"deleted_provider_id": 42, "response": None}


@pytest.mark.asyncio
async def test_create_oidc_trust_relationship_sends_claims_verbatim(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/oidc/trust-relationships").mock(
        return_value=httpx.Response(201, json={"id": 99})
    )

    client = FossaClient(admin_settings)
    result = await identity.create_oidc_trust_relationship(
        make_context(client, admin_settings),
        user_id=7,
        provider_id=42,
        audiences=["https://app.fossa.com", "fossa"],
        required_claims=[
            {"claim": "sub", "value": "repo:acme/*", "hasWildcards": True},
            {"claim": "admin", "value": True},
            {"claim": "run_number", "value": 12},
        ],
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "userId": 7,
        "providerId": 42,
        "scope": "org",
        "audiences": ["https://app.fossa.com", "fossa"],
        "requiredClaims": [
            {"claim": "sub", "value": "repo:acme/*", "hasWildcards": True},
            {"claim": "admin", "value": True, "hasWildcards": False},
            {"claim": "run_number", "value": 12, "hasWildcards": False},
        ],
    }
    assert result["endpoint"] == "POST /oidc/trust-relationships"


@pytest.mark.asyncio
async def test_create_oidc_trust_relationship_adds_scope_id_for_a_team_grant(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/oidc/trust-relationships").mock(
        return_value=httpx.Response(201, json={"id": 100})
    )

    client = FossaClient(admin_settings)
    await identity.create_oidc_trust_relationship(
        make_context(client, admin_settings),
        user_id=7,
        provider_id=42,
        audiences=["fossa"],
        required_claims=[SUB_CLAIM],
        scope="team",
        scope_id=5,
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content)["scopeId"] == 5


@pytest.mark.asyncio
async def test_create_oidc_trust_relationship_refuses_a_wildcard_only_subject(
    admin_settings, respx_mock, make_context
):
    """`sub: *` would let every token the issuer signs authenticate."""
    client = FossaClient(admin_settings)
    ctx = make_context(client, admin_settings)

    for value in ("*", "**", " * "):
        with pytest.raises(ValueError, match="only wildcards"):
            await identity.create_oidc_trust_relationship(
                ctx,
                user_id=7,
                provider_id=42,
                audiences=["fossa"],
                required_claims=[{"claim": "sub", "value": value, "hasWildcards": True}],
            )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_create_oidc_trust_relationship_requires_a_subject_claim(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)

    with pytest.raises(ValueError, match='"sub"'):
        await identity.create_oidc_trust_relationship(
            make_context(client, admin_settings),
            user_id=7,
            provider_id=42,
            audiences=["fossa"],
            required_claims=[{"claim": "repository", "value": "acme/widget"}],
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_create_oidc_trust_relationship_rejects_unknown_claim_keys(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)

    with pytest.raises(ValueError):
        await identity.create_oidc_trust_relationship(
            make_context(client, admin_settings),
            user_id=7,
            provider_id=42,
            audiences=["fossa"],
            required_claims=[{"claim": "sub", "value": "x", "wildcards": True}],
        )

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_update_oidc_trust_relationship_sends_only_the_named_fields(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/oidc/trust-relationships/99").mock(
        return_value=httpx.Response(200, json={"id": 99})
    )

    client = FossaClient(admin_settings)
    result = await identity.update_oidc_trust_relationship(
        make_context(client, admin_settings), 99, audiences=["fossa"]
    )
    await client.aclose()

    assert route.calls.last.request.method == "PUT"
    assert json.loads(route.calls.last.request.content) == {"audiences": ["fossa"]}
    assert result["endpoint"] == "PUT /oidc/trust-relationships/{id}"


@pytest.mark.asyncio
async def test_update_oidc_trust_relationship_requires_something_to_change(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)

    with pytest.raises(ValueError, match="audiences, required_claims, or both"):
        await identity.update_oidc_trust_relationship(make_context(client, admin_settings), 99)

    await client.aclose()
    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_oidc_trust_relationship_tolerates_the_empty_204_body(
    full_settings, respx_mock, make_context
):
    route = respx_mock.delete(f"{BASE}/oidc/trust-relationships/99").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(full_settings)
    result = await identity.delete_oidc_trust_relationship(make_context(client, full_settings), 99)
    await client.aclose()

    assert route.called
    assert result["data"] == {"deleted_trust_relationship_id": 99, "response": None}


# --- token exchange ----------------------------------------------------------


@pytest.mark.asyncio
async def test_exchange_oidc_token_sends_the_documented_body(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/oidc/token-exchange").mock(
        return_value=httpx.Response(
            200,
            json={
                "userId": 7,
                "providerId": 42,
                "issuer": "https://token.actions.example",
                "subject": "repo:acme/widget",
                "credential": {
                    "token": "fossa-minted-token",
                    "isPushOnly": True,
                    "expiration": "2026-07-31T12:00:00Z",
                },
            },
        )
    )

    client = FossaClient(admin_settings)
    result = await identity.exchange_oidc_token(
        make_context(client, admin_settings),
        provider_id=42,
        username="ci-bot",
        token="header.payload.signature",
        expires_in=900,
        is_push_only=True,
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "providerId": 42,
        "username": "ci-bot",
        "token": "header.payload.signature",
        "expiresIn": 900,
        "isPushOnly": True,
    }
    assert result["endpoint"] == "POST /oidc/token-exchange"
    assert result["data"]["subject"] == "repo:acme/widget"
    assert result["data"]["credential"]["token_minted"] is True
    assert result["data"]["credential"]["expiration"] == "2026-07-31T12:00:00Z"


@pytest.mark.asyncio
async def test_exchange_oidc_token_never_returns_the_minted_token(
    admin_settings, respx_mock, make_context
):
    """The same standard as test_token_absent_from_tool_output_and_logs."""
    respx_mock.post(f"{BASE}/oidc/token-exchange").mock(
        return_value=httpx.Response(
            200,
            json={
                "userId": 7,
                "providerId": 42,
                "issuer": "https://token.actions.example",
                "subject": "repo:acme/widget",
                "credential": {"token": "leaky-minted-token", "isPushOnly": False},
                "refreshToken": "leaky-minted-token-2",
            },
        )
    )

    client = FossaClient(admin_settings)
    result = await identity.exchange_oidc_token(
        make_context(client, admin_settings), 42, "ci-bot", "header.payload.signature"
    )
    await client.aclose()

    serialized = json.dumps(result)
    assert "leaky-minted-token" not in serialized
    assert "leaky-minted-token-2" not in serialized
    # An undocumented field is named, never valued, so a new secret cannot ride
    # along in a tool result before anyone has looked at it.
    assert result["data"]["undocumented_fields"] == ["refreshToken"]


@pytest.mark.asyncio
async def test_exchange_oidc_token_omits_unset_optional_fields(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.post(f"{BASE}/oidc/token-exchange").mock(
        return_value=httpx.Response(200, json={"userId": 7})
    )

    client = FossaClient(admin_settings)
    await identity.exchange_oidc_token(
        make_context(client, admin_settings), 42, "ci-bot", "header.payload.signature"
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "providerId": 42,
        "username": "ci-bot",
        "token": "header.payload.signature",
    }


@pytest.mark.asyncio
async def test_exchange_oidc_token_rejects_an_out_of_range_lifetime(
    admin_settings, respx_mock, make_context
):
    client = FossaClient(admin_settings)
    ctx = make_context(client, admin_settings)

    with pytest.raises(ValueError):
        await identity.exchange_oidc_token(ctx, 42, "ci-bot", "jwt", expires_in=60)
    with pytest.raises(ValueError):
        await identity.exchange_oidc_token(ctx, 42, "ci-bot", "jwt", expires_in=100000)

    await client.aclose()
    assert respx_mock.calls.call_count == 0


# --- SAML --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_saml_settings_sends_the_required_fields(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/organizations/1234/saml").mock(
        return_value=httpx.Response(200, json={"id": 1, "organizationId": 1234})
    )

    client = FossaClient(admin_settings)
    result = await identity.update_saml_settings(
        make_context(client, admin_settings),
        entry_point="https://sso.example.com/saml2/idp",
        cert="-----BEGIN CERTIFICATE-----\nMIIF\n-----END CERTIFICATE-----",
        audience="urn:acme:fossa",
        organization_id=1234,
        org_role_management="mixed",
        team_role_management="idp_teams_fossa_roles",
        create_missing_teams=False,
    )
    await client.aclose()

    assert route.calls.last.request.method == "PUT"
    assert json.loads(route.calls.last.request.content) == {
        "entryPoint": "https://sso.example.com/saml2/idp",
        "cert": "-----BEGIN CERTIFICATE-----\nMIIF\n-----END CERTIFICATE-----",
        "audience": "urn:acme:fossa",
        "orgRoleManagement": "mixed",
        "teamRoleManagement": "idp_teams_fossa_roles",
        "createMissingTeams": False,
    }
    assert result["endpoint"] == "PUT /organizations/{id}/saml"
    assert result["data"]["organization_id"] == 1234


@pytest.mark.asyncio
async def test_update_saml_settings_omits_unset_role_management(
    admin_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{BASE}/organizations/1234/saml").mock(
        return_value=httpx.Response(200, json={})
    )

    client = FossaClient(admin_settings)
    await identity.update_saml_settings(
        make_context(client, admin_settings),
        entry_point="https://sso.example.com/saml2/idp",
        cert="cert",
        audience="urn:acme:fossa",
        organization_id=1234,
    )
    await client.aclose()

    assert json.loads(route.calls.last.request.content) == {
        "entryPoint": "https://sso.example.com/saml2/idp",
        "cert": "cert",
        "audience": "urn:acme:fossa",
    }


@pytest.mark.asyncio
async def test_saml_tools_fall_back_to_the_configured_org_id(respx_mock, make_context):
    configured = Settings(
        fossa_api_token="test-token",
        fossa_allow_writes=True,
        fossa_allow_admin=True,
        fossa_allow_destructive=True,
        fossa_org_id=555,
        _env_file=None,  # type: ignore[call-arg]
    )
    route = respx_mock.delete(f"{BASE}/organizations/555/saml").mock(
        return_value=httpx.Response(200, text="")
    )

    client = FossaClient(configured)
    result = await identity.delete_saml_settings(make_context(client, configured))
    await client.aclose()

    assert route.called
    assert result["endpoint"] == "DELETE /organizations/{id}/saml"
    assert result["data"] == {"organization_id": 555, "response": None}


@pytest.mark.asyncio
async def test_saml_tools_refuse_to_guess_an_organization(admin_settings, respx_mock, make_context):
    assert admin_settings.fossa_org_id is None
    client = FossaClient(admin_settings)
    ctx = make_context(client, admin_settings)

    with pytest.raises(ValueError, match="FOSSA_ORG_ID"):
        await identity.delete_saml_settings(ctx)
    with pytest.raises(ValueError, match="FOSSA_ORG_ID"):
        await identity.update_saml_settings(ctx, "https://sso.example", "cert", "urn:acme")

    await client.aclose()
    assert respx_mock.calls.call_count == 0
