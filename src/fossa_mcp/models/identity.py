"""Input models for the federated-identity tools — OIDC and SAML.

These models carry the validation that decides *who is able to log in to the
organization*, so they are stricter than the API strictly requires in two
places, both deliberate:

* **A trust relationship must pin `sub`.** FOSSA already documents that
  `requiredClaims` has to contain a `sub` entry, but it will accept
  `{"claim": "sub", "value": "*", "hasWildcards": true}` — a rule that matches
  every subject the issuer will ever mint. That is the OIDC equivalent of
  `locators=all` on the bulk project delete, and it is refused here for the same
  reason: it must not be reachable by a model misreading an argument. Wildcards
  that still constrain the subject (`repo:acme/*`) are allowed.
* **Provider scope and `scope_id` are checked against each other.** The spec
  models the create body as a `oneOf` of an org-scoped and a team-scoped
  variant. A flat tool signature cannot express that, so the pairing is enforced
  here rather than left to a `400` from FOSSA.

Field names are the tool's snake_case; the FOSSA body keys they map to are built
in `tools/identity.py`. The one exception is `OidcRequiredClaim`, whose field
names are FOSSA's body keys verbatim so a validated instance dumps straight into
the request body.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Shared enum aliases, reused by the models below and by tool signatures.
OidcScope = Literal["org", "team"]
SamlOrgRoleManagement = Literal["fossa", "idp", "mixed"]
SamlTeamRoleManagement = Literal["fossa", "idp_teams_fossa_roles", "idp", "mixed"]

# FOSSA caps every OIDC page at 50 and every audience list at 100.
_MAX_OIDC_PAGE_SIZE = 50
_MAX_AUDIENCES = 100


class OidcRequiredClaim(BaseModel):
    """One claim a presented OIDC token must carry for the trust to apply.

    The field names are FOSSA's body keys verbatim, so a validated instance
    dumps straight into the request body with no translation step.
    """

    model_config = ConfigDict(extra="forbid")

    claim: str = Field(min_length=1)
    value: bool | int | float | str
    hasWildcards: bool = False  # noqa: N815 - FOSSA body key


def _validate_required_claims(claims: list[OidcRequiredClaim]) -> list[OidcRequiredClaim]:
    """Reject a claim set that would authenticate any subject from the issuer.

    FOSSA requires a `sub` entry; this additionally refuses a `sub` whose value
    is nothing but wildcards, because that grants every workload the issuer can
    sign for. `?` matches one character and `*` matches zero or more, so a value
    that is empty once those are removed constrains nothing.
    """
    if not claims:
        raise ValueError("required_claims must contain at least one claim")

    subjects = [claim for claim in claims if claim.claim == "sub"]
    if not subjects:
        raise ValueError(
            'required_claims must include a claim named "sub" naming the workload '
            "this trust relationship is for"
        )

    for subject in subjects:
        if not subject.hasWildcards or not isinstance(subject.value, str):
            continue
        if not subject.value.replace("*", "").replace("?", "").strip():
            raise ValueError(
                f'the "sub" claim value {subject.value!r} is only wildcards, which would let '
                "any token from this issuer authenticate. Name the subject, or narrow the "
                'pattern (for example "repo:acme/service-*").'
            )

    return claims


class OidcProviderListInput(BaseModel):
    """Input model for fossa_list_oidc_providers."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=10, ge=1, le=_MAX_OIDC_PAGE_SIZE)
    prev: int = Field(default=0, ge=0)
    filter_scope: OidcScope | None = None
    filter_scope_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _validate_scope_filter(self) -> "OidcProviderListInput":
        if self.filter_scope == "team" and self.filter_scope_id is None:
            raise ValueError("filter_scope_id is required when filter_scope is 'team'")
        if self.filter_scope is None and self.filter_scope_id is not None:
            raise ValueError("filter_scope_id requires filter_scope")
        return self


class OidcProviderReadInput(BaseModel):
    """Input model for fossa_get_oidc_provider."""

    model_config = ConfigDict(extra="forbid")

    provider_id: int = Field(ge=1)


class OidcProviderServiceAccountsInput(BaseModel):
    """Input model for fossa_list_oidc_provider_service_accounts."""

    model_config = ConfigDict(extra="forbid")

    provider_id: int = Field(ge=1)
    team_id: int | None = Field(default=None, ge=1)
    page_size: int = Field(default=10, ge=1, le=_MAX_OIDC_PAGE_SIZE)
    prev: int = Field(default=0, ge=0)


class OidcProviderCreateInput(BaseModel):
    """Input model for fossa_create_oidc_provider."""

    model_config = ConfigDict(extra="forbid")

    issuer: str = Field(min_length=1)
    scope: OidcScope = "org"
    scope_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _validate_scope(self) -> "OidcProviderCreateInput":
        if self.scope == "team" and self.scope_id is None:
            raise ValueError("scope_id (the team id) is required when scope is 'team'")
        if self.scope == "org" and self.scope_id is not None:
            raise ValueError("scope_id is not accepted when scope is 'org'")
        return self


class OidcProviderDeleteInput(BaseModel):
    """Input model for fossa_delete_oidc_provider."""

    model_config = ConfigDict(extra="forbid")

    provider_id: int = Field(ge=1)


class OidcTrustRelationshipListInput(BaseModel):
    """Input model for fossa_list_oidc_trust_relationships."""

    model_config = ConfigDict(extra="forbid")

    user_id: int | None = Field(default=None, ge=1)
    provider_id: int | None = Field(default=None, ge=1)
    page_size: int = Field(default=10, ge=1, le=_MAX_OIDC_PAGE_SIZE)
    prev: int = Field(default=0, ge=0)


class OidcTrustRelationshipReadInput(BaseModel):
    """Input model for fossa_get_oidc_trust_relationship."""

    model_config = ConfigDict(extra="forbid")

    trust_relationship_id: int = Field(ge=1)


class OidcTrustRelationshipCreateInput(BaseModel):
    """Input model for fossa_create_oidc_trust_relationship."""

    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(ge=1)
    provider_id: int = Field(ge=1)
    audiences: list[str] = Field(min_length=1, max_length=_MAX_AUDIENCES)
    required_claims: list[OidcRequiredClaim] = Field(min_length=1)
    scope: OidcScope = "org"
    scope_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _validate(self) -> "OidcTrustRelationshipCreateInput":
        if self.scope == "team" and self.scope_id is None:
            raise ValueError("scope_id (the team id) is required when scope is 'team'")
        if self.scope == "org" and self.scope_id is not None:
            raise ValueError("scope_id is not accepted when scope is 'org'")
        if any(not audience.strip() for audience in self.audiences):
            raise ValueError("audiences must not contain blank entries")
        _validate_required_claims(self.required_claims)
        return self


class OidcTrustRelationshipUpdateInput(BaseModel):
    """Input model for fossa_update_oidc_trust_relationship."""

    model_config = ConfigDict(extra="forbid")

    trust_relationship_id: int = Field(ge=1)
    audiences: list[str] | None = Field(default=None, min_length=1, max_length=_MAX_AUDIENCES)
    required_claims: list[OidcRequiredClaim] | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _validate(self) -> "OidcTrustRelationshipUpdateInput":
        if self.audiences is None and self.required_claims is None:
            raise ValueError("supply audiences, required_claims, or both")
        if self.audiences is not None and any(not a.strip() for a in self.audiences):
            raise ValueError("audiences must not contain blank entries")
        if self.required_claims is not None:
            _validate_required_claims(self.required_claims)
        return self


class OidcTrustRelationshipDeleteInput(BaseModel):
    """Input model for fossa_delete_oidc_trust_relationship."""

    model_config = ConfigDict(extra="forbid")

    trust_relationship_id: int = Field(ge=1)


class OidcTokenExchangeInput(BaseModel):
    """Input model for fossa_exchange_oidc_token."""

    model_config = ConfigDict(extra="forbid")

    provider_id: int = Field(ge=1)
    username: str = Field(min_length=1)
    token: str = Field(min_length=1)
    # FOSSA's documented bounds: 15 minutes to 12 hours.
    expires_in: int | None = Field(default=None, ge=900, le=43200)
    is_push_only: bool | None = None


class SamlSettingsUpdateInput(BaseModel):
    """Input model for fossa_update_saml_settings."""

    model_config = ConfigDict(extra="forbid")

    organization_id: int = Field(ge=1)
    entry_point: str = Field(min_length=1)
    cert: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    org_role_management: SamlOrgRoleManagement | None = None
    team_role_management: SamlTeamRoleManagement | None = None
    create_missing_teams: bool | None = None


class SamlSettingsDeleteInput(BaseModel):
    """Input model for fossa_delete_saml_settings."""

    model_config = ConfigDict(extra="forbid")

    organization_id: int = Field(ge=1)
