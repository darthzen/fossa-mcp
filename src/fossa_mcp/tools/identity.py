"""Federated-identity tools for the FOSSA MCP server — OIDC and SAML.

This is the organization's login configuration. Reads are ungated; **every write
in this module is `WriteTier.ADMIN` without exception**, because each one changes
who is able to authenticate to FOSSA:

* An OIDC provider plus a trust relationship is a standing grant: any workload
  holding a token from that issuer whose claims match becomes the named FOSSA
  user, with that user's permissions, without a password.
* SAML settings are the whole organization's SSO. A wrong `entry_point` or
  `cert` breaks every SSO login; deleting them removes the configuration and the
  organization domains that authenticate through it.

**The three deletes require `WriteTier.DESTRUCTIVE` as well.** ADMIN and
DESTRUCTIVE answer different questions — "what kind of thing is this?" and "how
bad is it if it is wrong?" — and a delete is destructive regardless of which
domain it lives in. `require_tier` takes one tier, so those tools call it twice;
`tools/org_settings.py` set the precedent on `DELETE /organizations/{id}/logo`.

`ADMIN` requires `FOSSA_ALLOW_ADMIN` **and** `FOSSA_ALLOW_WRITES`; neither
implies the other, and neither implies `FOSSA_ALLOW_DESTRUCTIVE`. Per
DECISIONS.md §7 the ADMIN tier should stay off on any shared deployment: under
§2 this server authenticates no callers and executes every request with one
shared token, so anyone who can reach the transport inherits whatever tiers are
on. Turning ADMIN on is turning "anyone who can reach this server can change who
is able to log in to the organization" on.

Two things about this domain that are not obvious from the endpoint list:

* **`POST /oidc/token-exchange` mints a live FOSSA API token.** This module does
  not return it. See `exchange_oidc_token` for what is returned instead and why.
* **Nothing else here returns a credential.** FOSSA's OIDC federation is
  keyless — a provider is an issuer URL, a trust relationship is a set of
  audiences and claims — so there is no client secret to leak on a read. The
  SAML `cert` is the identity provider's X.509 *public* signing certificate,
  which is published in IdP metadata by design; there is no private key or
  service-provider signing key anywhere in this surface.

The spec documents no `GET /organizations/{id}/saml`, so there is no read tool
for SAML: the only way to see the current configuration through the API is the
body `PUT` echoes back, which means reading it requires writing it. That is not
worth doing, so it is not offered.
"""

from typing import Any

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models.identity import (
    OidcProviderCreateInput,
    OidcProviderDeleteInput,
    OidcProviderListInput,
    OidcProviderReadInput,
    OidcProviderServiceAccountsInput,
    OidcRequiredClaim,
    OidcScope,
    OidcTokenExchangeInput,
    OidcTrustRelationshipCreateInput,
    OidcTrustRelationshipDeleteInput,
    OidcTrustRelationshipListInput,
    OidcTrustRelationshipReadInput,
    OidcTrustRelationshipUpdateInput,
    SamlOrgRoleManagement,
    SamlSettingsDeleteInput,
    SamlSettingsUpdateInput,
    SamlTeamRoleManagement,
)
from ..writes import WriteTier, require_tier

# The fields `POST /oidc/token-exchange` documents beside the credential. Anything
# outside this set is reported by name only, never by value, so an undocumented
# field added to that response cannot smuggle a secret into a tool result.
_DOCUMENTED_EXCHANGE_FIELDS = ("userId", "providerId", "issuer", "subject")

_REDACTED = "<redacted by fossa-mcp: this tool never returns a FOSSA API token>"


def _claims(raw: list[dict[str, Any]]) -> list[OidcRequiredClaim]:
    """Validate raw claim objects into `OidcRequiredClaim`s.

    The tool signatures take plain objects so FastMCP builds the JSON schema
    from the signature alone; the strictness (`claim` and `value` required,
    unknown keys rejected) lives in the model.
    """
    return [OidcRequiredClaim.model_validate(claim) for claim in raw]


def _dump_claims(claims: list[OidcRequiredClaim]) -> list[dict[str, Any]]:
    """Render validated claims as FOSSA body objects."""
    return [claim.model_dump() for claim in claims]


def _resolve_org_id(settings: Settings, organization_id: int | None) -> int:
    """Resolve the organization id for the SAML endpoints.

    Falls back to `FOSSA_ORG_ID` so an operator who configured it once does not
    have to repeat it, but refuses to guess when neither is set — these calls
    replace or delete an organization's SSO and must not act on a default.
    """
    resolved = organization_id if organization_id is not None else settings.fossa_org_id
    if resolved is None:
        raise ValueError(
            "organization_id is required: pass it explicitly or set FOSSA_ORG_ID. "
            "This call changes an organization's SAML SSO and will not guess which one."
        )
    if resolved < 1:
        raise ValueError("organization_id must be >= 1")
    return resolved


# --- OIDC reads --------------------------------------------------------------


async def list_oidc_providers(
    ctx: Context,
    page_size: int = 10,
    prev: int = 0,
    filter_scope: OidcScope | None = None,
    filter_scope_id: int | None = None,
) -> dict[str, Any]:
    """
    List the OIDC identity providers this FOSSA organization federates with.

    Read-only. Each provider is an issuer URL scoped to the organization or to
    one team; it is what a trust relationship points at. Pagination is by cursor:
    pass the `last` value from a previous page as `prev`. Filtering by team scope
    requires `filter_scope_id`. Requires a premium FOSSA subscription; other
    organizations get a 403.

    No credential is returned: FOSSA's OIDC federation stores no client secret.
    """
    validated = OidcProviderListInput(
        page_size=page_size,
        prev=prev,
        filter_scope=filter_scope,
        filter_scope_id=filter_scope_id,
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = [
        ("pageSize", str(validated.page_size)),
        ("prev", str(validated.prev)),
    ]
    if validated.filter_scope is not None:
        params.append(("filter[scope]", validated.filter_scope))
    if validated.filter_scope_id is not None:
        params.append(("filter[scopeId]", str(validated.filter_scope_id)))

    result = await client.request_json("GET", "/oidc/providers", params=params)

    return {"ok": True, "endpoint": "GET /oidc/providers", "data": result}


async def get_oidc_provider(ctx: Context, provider_id: int) -> dict[str, Any]:
    """
    Show one OIDC provider: its issuer URL, its scope, and when it was created.

    Read-only. FOSSA answers 401 rather than 404 when the provider does not
    exist, belongs to another organization, or is not visible to this token, so
    an "unauthorized" here does not necessarily mean the token is wrong.
    """
    validated = OidcProviderReadInput(provider_id=provider_id)

    client: FossaClient = ctx.request_context.lifespan_context["client"]
    result = await client.request_json("GET", f"/oidc/providers/{validated.provider_id}")

    return {"ok": True, "endpoint": "GET /oidc/providers/{id}", "data": result}


async def list_oidc_provider_service_accounts(
    ctx: Context,
    provider_id: int,
    team_id: int | None = None,
    page_size: int = 10,
    prev: int = 0,
) -> dict[str, Any]:
    """
    List the service accounts that may be named in a new trust relationship for
    an OIDC provider.

    Read-only. Use this before fossa_create_oidc_trust_relationship to find the
    `user_id` to grant. `team_id` is required when the calling token only has
    team-level permission to manage trust relationships.

    Returns account ids, usernames, and email addresses — identity, not
    credentials.
    """
    validated = OidcProviderServiceAccountsInput(
        provider_id=provider_id, team_id=team_id, page_size=page_size, prev=prev
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = [
        ("pageSize", str(validated.page_size)),
        ("prev", str(validated.prev)),
    ]
    if validated.team_id is not None:
        params.append(("teamId", str(validated.team_id)))

    result = await client.request_json(
        "GET", f"/oidc/providers/{validated.provider_id}/available-service-accounts", params=params
    )

    return {
        "ok": True,
        "endpoint": "GET /oidc/providers/{id}/available-service-accounts",
        "data": result,
    }


async def list_oidc_trust_relationships(
    ctx: Context,
    user_id: int | None = None,
    provider_id: int | None = None,
    page_size: int = 10,
    prev: int = 0,
) -> dict[str, Any]:
    """
    List the OIDC trust relationships configured for this organization.

    Read-only. Each one is a standing grant: a workload presenting a token from
    the named provider whose claims match becomes the named FOSSA user. This is
    the tool to read when auditing what can authenticate without a password —
    look at `requiredClaims`, and treat a `sub` that matches broadly as a finding.

    No credential is returned; a trust relationship holds only audiences and
    claim rules.
    """
    validated = OidcTrustRelationshipListInput(
        user_id=user_id, provider_id=provider_id, page_size=page_size, prev=prev
    )

    client: FossaClient = ctx.request_context.lifespan_context["client"]

    params: list[tuple[str, str]] = [
        ("pageSize", str(validated.page_size)),
        ("prev", str(validated.prev)),
    ]
    if validated.user_id is not None:
        params.append(("userId", str(validated.user_id)))
    if validated.provider_id is not None:
        params.append(("providerId", str(validated.provider_id)))

    result = await client.request_json("GET", "/oidc/trust-relationships", params=params)

    return {"ok": True, "endpoint": "GET /oidc/trust-relationships", "data": result}


async def get_oidc_trust_relationship(ctx: Context, trust_relationship_id: int) -> dict[str, Any]:
    """
    Show one OIDC trust relationship: the issuer, the service account it grants,
    the accepted audiences, and the claims a token must carry.

    Read-only. FOSSA answers 401 rather than 404 for a relationship that does not
    exist or belongs to another organization.
    """
    validated = OidcTrustRelationshipReadInput(trust_relationship_id=trust_relationship_id)

    client: FossaClient = ctx.request_context.lifespan_context["client"]
    result = await client.request_json(
        "GET", f"/oidc/trust-relationships/{validated.trust_relationship_id}"
    )

    return {"ok": True, "endpoint": "GET /oidc/trust-relationships/{id}", "data": result}


# --- OIDC writes -------------------------------------------------------------


async def create_oidc_provider(
    ctx: Context,
    issuer: str,
    scope: OidcScope = "org",
    scope_id: int | None = None,
) -> dict[str, Any]:
    """
    Register an OIDC identity provider that this FOSSA organization will trust.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    This is federated-identity configuration for the whole organization. Adding
    a provider does not by itself let anyone in — a trust relationship does that
    — but it is the first half of a password-less login path, and whoever can
    call this can choose which issuer FOSSA will believe. Enabling the ADMIN
    tier on a deployment that does not authenticate its callers grants that
    ability to every caller.

    `issuer` must be the issuer URL exactly as the provider mints it in the `iss`
    claim. Use `scope="team"` with `scope_id` set to a team id to scope the
    provider to one team; org scope takes no `scope_id`.
    """
    validated = OidcProviderCreateInput(issuer=issuer, scope=scope, scope_id=scope_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_create_oidc_provider")

    payload: dict[str, Any] = {"issuer": validated.issuer, "scope": validated.scope}
    if validated.scope_id is not None:
        payload["scopeId"] = validated.scope_id

    result = await client.request_json("POST", "/oidc/providers", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /oidc/providers",
        "data": {"applied": payload, "provider": result},
    }


async def delete_oidc_provider(ctx: Context, provider_id: int) -> dict[str, Any]:
    """
    Delete an OIDC provider and every trust relationship that points at it.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true, FOSSA_ALLOW_ADMIN=true,
    and FOSSA_ALLOW_DESTRUCTIVE=true.

    The cascade is the point to be careful about: FOSSA deletes the provider's
    trust relationships with it, so every workload authenticating through this
    issuer stops being able to log in. Nothing here restores them — they have to
    be recreated by hand. List them with fossa_list_oidc_trust_relationships
    (filtering on `provider_id`) before deleting, so there is a record of what
    the cascade will take.
    """
    validated = OidcProviderDeleteInput(provider_id=provider_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_delete_oidc_provider")
    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_oidc_provider")

    # 204 with an empty body: request_json would report the empty body as an
    # error regardless of the status.
    body, _ = await client.request_text("DELETE", f"/oidc/providers/{validated.provider_id}")

    return {
        "ok": True,
        "endpoint": "DELETE /oidc/providers/{id}",
        "data": {"deleted_provider_id": validated.provider_id, "response": body or None},
    }


async def create_oidc_trust_relationship(
    ctx: Context,
    user_id: int,
    provider_id: int,
    audiences: list[str],
    required_claims: list[dict[str, Any]],
    scope: OidcScope = "org",
    scope_id: int | None = None,
) -> dict[str, Any]:
    """
    Grant a workload permanent password-less login to FOSSA as a specific
    service account, on the strength of an OIDC token.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    Read that first line literally. After this call, anything that can obtain a
    token from `provider_id` whose claims match `required_claims` can exchange it
    for a FOSSA API token belonging to `user_id`, with that account's
    permissions, indefinitely and without a password. Enabling the ADMIN tier on
    a server that does not authenticate its callers means every caller can
    create such a grant.

    `required_claims` is a list of objects: `claim` (the claim name), `value`
    (string, number, or boolean), and optional `hasWildcards` (when true, `*`
    matches any run of characters and `?` matches one). It must pin `sub` — the
    subject identifying the workload, such as
    `repo:acme/service:ref:refs/heads/main`. A `sub` value consisting only of
    wildcards is refused here, because it would match every subject the issuer
    ever signs. `audiences` lists the `aud` values FOSSA will accept.

    Find `user_id` with fossa_list_oidc_provider_service_accounts. Use
    `scope="team"` with `scope_id` for a team-scoped grant.
    """
    validated = OidcTrustRelationshipCreateInput(
        user_id=user_id,
        provider_id=provider_id,
        audiences=audiences,
        required_claims=_claims(required_claims),
        scope=scope,
        scope_id=scope_id,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_create_oidc_trust_relationship")

    payload: dict[str, Any] = {
        "userId": validated.user_id,
        "providerId": validated.provider_id,
        "scope": validated.scope,
        "audiences": validated.audiences,
        "requiredClaims": _dump_claims(validated.required_claims),
    }
    if validated.scope_id is not None:
        payload["scopeId"] = validated.scope_id

    result = await client.request_json("POST", "/oidc/trust-relationships", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /oidc/trust-relationships",
        "data": {"applied": payload, "trust_relationship": result},
    }


async def update_oidc_trust_relationship(
    ctx: Context,
    trust_relationship_id: int,
    audiences: list[str] | None = None,
    required_claims: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Change which tokens an existing OIDC trust relationship accepts.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    Only `audiences` and `required_claims` can be updated; the user and provider
    are fixed at creation. Each list **replaces** the stored one rather than
    merging into it, so send the complete set — omitting a claim removes it and
    widens what can authenticate. As on create, a `sub` value that is only
    wildcards is refused.
    """
    validated = OidcTrustRelationshipUpdateInput(
        trust_relationship_id=trust_relationship_id,
        audiences=audiences,
        required_claims=_claims(required_claims) if required_claims is not None else None,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_update_oidc_trust_relationship")

    payload: dict[str, Any] = {}
    if validated.audiences is not None:
        payload["audiences"] = validated.audiences
    if validated.required_claims is not None:
        payload["requiredClaims"] = _dump_claims(validated.required_claims)

    result = await client.request_json(
        "PUT",
        f"/oidc/trust-relationships/{validated.trust_relationship_id}",
        json_body=payload,
    )

    return {
        "ok": True,
        "endpoint": "PUT /oidc/trust-relationships/{id}",
        "data": {
            "trust_relationship_id": validated.trust_relationship_id,
            "applied": payload,
            "trust_relationship": result,
        },
    }


async def delete_oidc_trust_relationship(
    ctx: Context, trust_relationship_id: int
) -> dict[str, Any]:
    """
    Revoke one OIDC trust relationship, so tokens matching it no longer buy a
    FOSSA login.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true, FOSSA_ALLOW_ADMIN=true,
    and FOSSA_ALLOW_DESTRUCTIVE=true.

    This is the revocation path for a leaked or over-broad grant, and it is not
    reversible from here: the audiences and claim rules are gone once deleted.
    Read it with fossa_get_oidc_trust_relationship first if it may need to be
    recreated. FOSSA API tokens already minted through it are not invalidated by
    this call; they expire on their own schedule.
    """
    validated = OidcTrustRelationshipDeleteInput(trust_relationship_id=trust_relationship_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_delete_oidc_trust_relationship")
    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_oidc_trust_relationship")

    # 204 with an empty body.
    body, _ = await client.request_text(
        "DELETE", f"/oidc/trust-relationships/{validated.trust_relationship_id}"
    )

    return {
        "ok": True,
        "endpoint": "DELETE /oidc/trust-relationships/{id}",
        "data": {
            "deleted_trust_relationship_id": validated.trust_relationship_id,
            "response": body or None,
        },
    }


async def exchange_oidc_token(
    ctx: Context,
    provider_id: int,
    username: str,
    token: str,
    expires_in: int | None = None,
    is_push_only: bool | None = None,
) -> dict[str, Any]:
    """
    Check that an OIDC trust relationship actually works, by performing the token
    exchange a CI job would perform.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    **The FOSSA API token this mints is deliberately not returned.** What comes
    back is the identity FOSSA resolved (user, provider, issuer, subject) and the
    credential's metadata (whether it is push-only, when it expires) with the
    token itself replaced by a placeholder. A live API token in a tool result is
    a credential in a model's context, a transcript, and every log downstream of
    it; that is not a trade this server makes, and there is no argument that
    turns it back on. A CI job that needs the real token should call
    `POST /oidc/token-exchange` directly.

    So use this to answer "is my trust relationship configured correctly?", not
    to obtain a token. Note that the token is still minted and still valid until
    it expires (15 minutes to 12 hours) even though nobody here can read it.

    `token` is the JWT the identity provider issued; `username` is the FOSSA
    service account to log in as. FOSSA reports an invalid token, an unknown
    provider, and "no matching trust relationship" all as a 400.
    """
    validated = OidcTokenExchangeInput(
        provider_id=provider_id,
        username=username,
        token=token,
        expires_in=expires_in,
        is_push_only=is_push_only,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.ADMIN, "fossa_exchange_oidc_token")

    payload: dict[str, Any] = {
        "providerId": validated.provider_id,
        "username": validated.username,
        "token": validated.token,
    }
    if validated.expires_in is not None:
        payload["expiresIn"] = validated.expires_in
    if validated.is_push_only is not None:
        payload["isPushOnly"] = validated.is_push_only

    result = await client.request_json("POST", "/oidc/token-exchange", json_body=payload)

    return {
        "ok": True,
        "endpoint": "POST /oidc/token-exchange",
        "data": _redact_exchange_result(result),
    }


def _redact_exchange_result(result: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Strip the minted FOSSA API token out of a token-exchange response.

    Allow-list, not deny-list. Only the fields FOSSA documents beside the
    credential are copied through by value; anything else in the response is
    reported by *name* under `undocumented_fields`, so a field added to that
    endpoint later cannot carry a secret into a tool result before anyone has
    looked at it.
    """
    if not isinstance(result, dict):
        return {"redacted": True, "note": "unexpected response shape; withheld"}

    data: dict[str, Any] = {
        field: result[field] for field in _DOCUMENTED_EXCHANGE_FIELDS if field in result
    }

    credential = result.get("credential")
    if isinstance(credential, dict):
        minted = credential.get("token")
        data["credential"] = {
            "token": _REDACTED,
            "token_minted": isinstance(minted, str) and bool(minted),
            "isPushOnly": credential.get("isPushOnly"),
            "expiration": credential.get("expiration"),
        }

    extra = sorted(
        key for key in result if key not in _DOCUMENTED_EXCHANGE_FIELDS and key != "credential"
    )
    if extra:
        data["undocumented_fields"] = extra

    return data


# --- SAML --------------------------------------------------------------------


async def update_saml_settings(
    ctx: Context,
    entry_point: str,
    cert: str,
    audience: str,
    organization_id: int | None = None,
    org_role_management: SamlOrgRoleManagement | None = None,
    team_role_management: SamlTeamRoleManagement | None = None,
    create_missing_teams: bool | None = None,
) -> dict[str, Any]:
    """
    Replace the organization's SAML single sign-on configuration.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and FOSSA_ALLOW_ADMIN=true.

    This is how everyone in the organization logs in. It is a replacement, not a
    merge: the three required fields are always sent, so a call with the wrong
    `entry_point` or a stale `cert` breaks SSO for every user until it is fixed,
    and a call that points `entry_point` at an identity provider someone else
    controls hands them the organization. The API documents no endpoint that
    reads the current settings back, so there is no way to check what was there
    before or to restore it — capture it from the FOSSA web app first.

    `entry_point` is the IdP's SSO URL, `cert` its X.509 signing certificate in
    PEM form, `audience` the SP entity ID. The role-management fields decide
    whether FOSSA or the IdP is authoritative for org roles and teams; leaving
    them unset keeps FOSSA authoritative (FOSSA's own default). `organization_id`
    falls back to FOSSA_ORG_ID.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    validated = SamlSettingsUpdateInput(
        organization_id=_resolve_org_id(settings, organization_id),
        entry_point=entry_point,
        cert=cert,
        audience=audience,
        org_role_management=org_role_management,
        team_role_management=team_role_management,
        create_missing_teams=create_missing_teams,
    )

    require_tier(settings, WriteTier.ADMIN, "fossa_update_saml_settings")

    payload: dict[str, Any] = {
        "entryPoint": validated.entry_point,
        "cert": validated.cert,
        "audience": validated.audience,
    }
    if validated.org_role_management is not None:
        payload["orgRoleManagement"] = validated.org_role_management
    if validated.team_role_management is not None:
        payload["teamRoleManagement"] = validated.team_role_management
    if validated.create_missing_teams is not None:
        payload["createMissingTeams"] = validated.create_missing_teams

    result = await client.request_json(
        "PUT", f"/organizations/{validated.organization_id}/saml", json_body=payload
    )

    return {
        "ok": True,
        "endpoint": "PUT /organizations/{id}/saml",
        "data": {
            "organization_id": validated.organization_id,
            "applied": payload,
            "saml": result,
        },
    }


async def delete_saml_settings(ctx: Context, organization_id: int | None = None) -> dict[str, Any]:
    """
    Remove the organization's SAML single sign-on configuration entirely.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true, FOSSA_ALLOW_ADMIN=true,
    and FOSSA_ALLOW_DESTRUCTIVE=true.

    Every user who signs in through SAML loses that path, and the organization
    domains that authenticate through it go with the configuration. Since the API
    exposes no way to read the settings back, nothing recorded here is enough to
    restore them: copy the entry point, certificate, and audience out of the
    FOSSA web app before running this, and confirm at least one administrator can
    still sign in some other way. `organization_id` falls back to FOSSA_ORG_ID.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    validated = SamlSettingsDeleteInput(organization_id=_resolve_org_id(settings, organization_id))

    require_tier(settings, WriteTier.ADMIN, "fossa_delete_saml_settings")
    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_saml_settings")

    # Documented as a 200 with no content, so the JSON path would fail parsing it.
    body, _ = await client.request_text(
        "DELETE", f"/organizations/{validated.organization_id}/saml"
    )

    return {
        "ok": True,
        "endpoint": "DELETE /organizations/{id}/saml",
        "data": {"organization_id": validated.organization_id, "response": body or None},
    }
