"""Endpoint contract tests for the organization settings and limits tools.

Covers the HTTP shape of the grouped organization settings tools: the path each
section resolves to, the exact JSON body each action sends, the closure of the
`Literal` section lists against the tables that back them, and the refusals that
must fire before any request leaves the process — an unknown section, a missing
`FOSSA_ORG_ID`, and each of the three write tiers with that tier off.

The tier assertions are the point of this file. `fossa_update_org_settings`
spans three tiers because its sections do, so every tier is exercised through
the same tool: an ordinary section under WRITE, an authentication section that
must not be reachable without ADMIN, and a propagate that must not be reachable
without DESTRUCTIVE.
"""

import json
from typing import cast

import httpx
import pytest
from pydantic import ValidationError

from fossa_mcp.client import FossaClient
from fossa_mcp.config import Settings
from fossa_mcp.errors import FossaConfigurationError, FossaWriteNotPermittedError
from fossa_mcp.models.org_settings import (
    ORG_LIMIT_PATHS,
    ORG_SETTINGS_DELETE_PATHS,
    ORG_SETTINGS_PROPAGATE_FIELDS,
    ORG_SETTINGS_READ_PATHS,
    ORG_SETTINGS_WRITE_SECTIONS,
    OrgLimit,
    OrgSettingsDeleteTarget,
    OrgSettingsSection,
    OrgSettingsWritableSection,
)
from fossa_mcp.tools import org_settings

BASE = "https://app.fossa.com/api"
ORG_ID = 4242
ORG = f"{BASE}/organizations/{ORG_ID}"


def _literal_members(alias) -> set[str]:
    """Return the string members of a `Literal[...]` alias."""
    return set(alias.__args__)


@pytest.fixture
def org_settings_config(settings) -> Settings:
    """Read-only settings with an organization id, which every path needs."""
    return settings.model_copy(update={"fossa_org_id": ORG_ID})


@pytest.fixture
def writable_settings(org_settings_config) -> Settings:
    return org_settings_config.model_copy(update={"fossa_allow_writes": True})


@pytest.fixture
def admin_settings(writable_settings) -> Settings:
    return writable_settings.model_copy(update={"fossa_allow_admin": True})


@pytest.fixture
def destructive_settings(writable_settings) -> Settings:
    return writable_settings.model_copy(update={"fossa_allow_destructive": True})


@pytest.fixture
def full_settings(writable_settings) -> Settings:
    return writable_settings.model_copy(
        update={"fossa_allow_destructive": True, "fossa_allow_admin": True}
    )


def _body(request: httpx.Request) -> object:
    return json.loads(request.content.decode())


# --- the Literals and the tables must agree ----------------------------------


def test_every_readable_section_has_a_path():
    assert _literal_members(OrgSettingsSection) == set(ORG_SETTINGS_READ_PATHS)


def test_every_writable_section_has_a_spec():
    assert _literal_members(OrgSettingsWritableSection) == set(ORG_SETTINGS_WRITE_SECTIONS)


def test_every_propagatable_section_is_writable():
    assert set(ORG_SETTINGS_PROPAGATE_FIELDS) <= _literal_members(OrgSettingsWritableSection)


def test_every_limit_and_delete_target_has_a_path():
    assert _literal_members(OrgLimit) == set(ORG_LIMIT_PATHS)
    assert _literal_members(OrgSettingsDeleteTarget) == set(ORG_SETTINGS_DELETE_PATHS)


def test_the_only_read_only_section_is_slack():
    """`integrations-slack` is the one section the API exposes without a PUT."""
    read_only = _literal_members(OrgSettingsSection) - _literal_members(OrgSettingsWritableSection)
    assert read_only == {"integrations-slack"}


def test_the_only_write_only_section_is_sbom_defaults():
    """`saml` used to be the other one; it moved to tools/identity.py."""
    write_only = _literal_members(OrgSettingsWritableSection) - _literal_members(OrgSettingsSection)
    assert write_only == {"sbom-report-defaults"}


def test_saml_is_not_reachable_from_the_org_settings_tools():
    """PUT and DELETE /organizations/{id}/saml belong to tools/identity.py.

    Both agents that built this parity surface claimed them, because the spec
    tags them `Organization Settings`. The dedicated tools won: typed `cert` and
    `entry_point` arguments beat a free-form `values` dict for a configuration
    that decides who can log in. This pins the de-duplication so a future
    spec-derived regeneration cannot quietly hand SAML back to the grouped tool.
    """
    assert "saml" not in _literal_members(OrgSettingsWritableSection)
    assert "saml" not in _literal_members(OrgSettingsDeleteTarget)
    assert "saml" not in ORG_SETTINGS_WRITE_SECTIONS
    assert "saml" not in ORG_SETTINGS_DELETE_PATHS


def test_notifications_propagates_fewer_fields_than_it_accepts():
    """A real spec asymmetry: five keys on PUT, three propagatable on PATCH."""
    section = ORG_SETTINGS_WRITE_SECTIONS["projects-notifications"]
    assert set(ORG_SETTINGS_PROPAGATE_FIELDS["projects-notifications"]) < set(section.keys)


# --- reads -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_one_section(org_settings_config, respx_mock, make_context):
    payload = {"defaultSecurityPolicyId": 12, "projectDefaultStatusCheckFilterVulnerability": 3}
    route = respx_mock.get(f"{ORG}/settings/projects/issues/security").mock(
        return_value=httpx.Response(200, json=payload)
    )

    client = FossaClient(org_settings_config)
    result = await org_settings.get_org_settings(
        make_context(client, org_settings_config), ["projects-issues-security"]
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert route.calls.last.request.method == "GET"
    assert result["endpoint"] == ("GET /organizations/{id}/settings/projects/issues/security")
    assert result["data"] == {"projects-issues-security": payload}


@pytest.mark.asyncio
async def test_read_sections_fan_out_deduped_and_in_order(
    org_settings_config, respx_mock, make_context
):
    auth = respx_mock.get(f"{ORG}/settings/authentication").mock(
        return_value=httpx.Response(200, json={"subdomain": "acme", "saml": True})
    )
    general = respx_mock.get(f"{ORG}/settings/general").mock(
        return_value=httpx.Response(200, json={"title": "Acme"})
    )
    pod = respx_mock.get(f"{ORG}/settings/languages/pod").mock(
        return_value=httpx.Response(200, json=["https://cdn.cocoapods.org"])
    )

    client = FossaClient(org_settings_config)
    result = await org_settings.get_org_settings(
        make_context(client, org_settings_config),
        ["languages-pod", "authentication", "general", "authentication"],
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 3
    assert auth.called and general.called and pod.called
    assert list(result["data"]) == ["languages-pod", "authentication", "general"]
    assert result["endpoint"] == (
        "GET /organizations/{id}/settings/languages/pod, "
        "GET /organizations/{id}/settings/authentication, "
        "GET /organizations/{id}/settings/general"
    )


@pytest.mark.asyncio
async def test_every_readable_section_resolves_to_its_spec_path(
    org_settings_config, respx_mock, make_context
):
    """Each of the 22 sections must hit the path the vendored spec declares."""
    for suffix in ORG_SETTINGS_READ_PATHS.values():
        respx_mock.get(f"{ORG}{suffix}").mock(return_value=httpx.Response(200, json={"ok": True}))

    every_section = cast(list[OrgSettingsSection], list(ORG_SETTINGS_READ_PATHS))

    client = FossaClient(org_settings_config)
    result = await org_settings.get_org_settings(
        make_context(client, org_settings_config), every_section
    )
    await client.aclose()

    assert respx_mock.calls.call_count == len(ORG_SETTINGS_READ_PATHS)
    assert set(result["data"]) == set(ORG_SETTINGS_READ_PATHS)


@pytest.mark.asyncio
async def test_limits_default_to_both(org_settings_config, respx_mock, make_context):
    contributors = respx_mock.get(f"{ORG}/limits/contributors").mock(
        return_value=httpx.Response(200, json={"usage": 12, "max": 50, "unlimited": False})
    )
    release_groups = respx_mock.get(f"{ORG}/limits/release-groups").mock(
        return_value=httpx.Response(200, json={"usage": 3, "max": 10, "unlimited": False})
    )

    client = FossaClient(org_settings_config)
    result = await org_settings.get_org_limits(make_context(client, org_settings_config))
    await client.aclose()

    assert respx_mock.calls.call_count == 2
    assert contributors.called and release_groups.called
    assert list(result["data"]) == ["contributors", "release-groups"]
    assert result["endpoint"] == (
        "GET /organizations/{id}/limits/contributors, GET /organizations/{id}/limits/release-groups"
    )


# --- schema rejection: an unknown section never reaches FOSSA ----------------


@pytest.mark.asyncio
async def test_unknown_read_section_is_rejected_without_a_request(
    org_settings_config, respx_mock, make_context
):
    client = FossaClient(org_settings_config)
    with pytest.raises(ValidationError):
        await org_settings.get_org_settings(
            make_context(client, org_settings_config),
            ["settings/../../projects"],  # type: ignore[list-item]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unknown_write_section_is_rejected_without_a_request(
    full_settings, respx_mock, make_context
):
    client = FossaClient(full_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, full_settings),
            "languages-cargo",  # type: ignore[arg-type]
            values={"registries": []},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unknown_delete_target_is_rejected_without_a_request(
    full_settings, respx_mock, make_context
):
    client = FossaClient(full_settings)
    with pytest.raises(ValidationError):
        await org_settings.delete_org_setting(
            make_context(client, full_settings),
            "organization",  # type: ignore[arg-type]
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unknown_body_key_is_rejected_without_a_request(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, writable_settings),
            "projects-privacy",
            values={"defaultProjectPrivacy": "private", "defaultProjectVisibility": "private"},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_partial_body_for_a_required_section_is_rejected(
    writable_settings, respx_mock, make_context
):
    """The PUT replaces the section, so a partial body would erase the rest."""
    client = FossaClient(writable_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, writable_settings),
            "projects-notifications",
            values={"notificationDefaultEnabled": True},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_unpropagatable_field_is_rejected_without_a_request(
    full_settings, respx_mock, make_context
):
    client = FossaClient(full_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, full_settings),
            "projects-notifications",
            action="propagate",
            fields=["notificationDefaultEnabled"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_propagate_on_a_section_without_one_is_rejected(
    full_settings, respx_mock, make_context
):
    client = FossaClient(full_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, full_settings),
            "languages-npm",
            action="propagate",
            fields=["registries"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_array_bodied_section_refuses_an_object_body(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, writable_settings),
            "languages-pod",
            values={"sources": ["https://cdn.cocoapods.org"]},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_object_bodied_section_refuses_an_array_body(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(ValidationError):
        await org_settings.update_org_settings(
            make_context(client, writable_settings),
            "projects-privacy",
            items=["private"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- FOSSA_ORG_ID ------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_without_an_org_id_refuses_before_requesting(settings, respx_mock, make_context):
    client = FossaClient(settings)
    with pytest.raises(FossaConfigurationError, match="FOSSA_ORG_ID"):
        await org_settings.get_org_settings(make_context(client, settings), ["general"])
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_limits_without_an_org_id_refuses_before_requesting(
    settings, respx_mock, make_context
):
    client = FossaClient(settings)
    with pytest.raises(FossaConfigurationError, match="FOSSA_ORG_ID"):
        await org_settings.get_org_limits(make_context(client, settings))
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_write_without_an_org_id_refuses_before_requesting(
    settings, respx_mock, make_context
):
    no_org = settings.model_copy(update={"fossa_allow_writes": True})

    client = FossaClient(no_org)
    with pytest.raises(FossaConfigurationError, match="FOSSA_ORG_ID"):
        await org_settings.update_org_settings(
            make_context(client, no_org),
            "projects-privacy",
            values={"defaultProjectPrivacy": "private"},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


# --- writes: happy paths -----------------------------------------------------


@pytest.mark.asyncio
async def test_replace_an_object_section(writable_settings, respx_mock, make_context):
    route = respx_mock.put(f"{ORG}/settings/projects/issues/security").mock(
        return_value=httpx.Response(200, json={"defaultSecurityPolicyId": 12})
    )

    body = {
        "defaultSecurityPolicyId": 12,
        "projectDefaultSecurityIssueScanningEnabled": True,
        "projectDefaultSecurityStatusCheckEnabled": True,
        # An undocumented integer scale, carried through verbatim per DECISIONS §6.
        "projectDefaultStatusCheckFilterVulnerability": 3,
    }

    client = FossaClient(writable_settings)
    result = await org_settings.update_org_settings(
        make_context(client, writable_settings), "projects-issues-security", values=body
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    request = route.calls.last.request
    assert request.method == "PUT"
    assert _body(request) == body
    assert result["endpoint"] == "PUT /organizations/{id}/settings/projects/issues/security"
    assert result["data"]["action"] == "replace"
    assert result["data"]["applied"] == body


@pytest.mark.asyncio
async def test_replace_a_string_array_section(writable_settings, respx_mock, make_context):
    route = respx_mock.put(f"{ORG}/settings/languages/pod").mock(return_value=httpx.Response(204))

    sources = ["https://cdn.cocoapods.org", "https://pods.acme.internal"]

    client = FossaClient(writable_settings)
    result = await org_settings.update_org_settings(
        make_context(client, writable_settings), "languages-pod", items=sources
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _body(route.calls.last.request) == sources
    # A 204 with no body is a success, not the parse failure request_json reports.
    assert result["ok"] is True
    assert result["data"]["settings"] is None


@pytest.mark.asyncio
async def test_replace_an_object_array_section(writable_settings, respx_mock, make_context):
    route = respx_mock.put(f"{ORG}/settings/integrations/custom-license-scans").mock(
        return_value=httpx.Response(204)
    )

    scans = [{"name": "Acme internal", "matchCriteria": "ACME-INTERNAL-1\\.0"}]

    client = FossaClient(writable_settings)
    result = await org_settings.update_org_settings(
        make_context(client, writable_settings),
        "integrations-custom-license-scans",
        items=scans,
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _body(route.calls.last.request) == scans
    assert result["endpoint"] == (
        "PUT /organizations/{id}/settings/integrations/custom-license-scans"
    )


@pytest.mark.asyncio
async def test_replace_sbom_report_defaults_uses_its_non_settings_path(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{ORG}/sbomReportDefaults").mock(
        return_value=httpx.Response(200, json={"sbomReportSupplier": "Acme"})
    )

    client = FossaClient(writable_settings)
    result = await org_settings.update_org_settings(
        make_context(client, writable_settings),
        "sbom-report-defaults",
        values={"sbomReportSupplier": "Acme"},
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _body(route.calls.last.request) == {"sbomReportSupplier": "Acme"}
    assert result["endpoint"] == "PUT /organizations/{id}/sbomReportDefaults"


@pytest.mark.asyncio
async def test_propagate_sends_the_field_list_as_a_bare_array(
    destructive_settings, respx_mock, make_context
):
    route = respx_mock.patch(f"{ORG}/settings/projects/issues/security").mock(
        return_value=httpx.Response(204)
    )

    client = FossaClient(destructive_settings)
    result = await org_settings.update_org_settings(
        make_context(client, destructive_settings),
        "projects-issues-security",
        action="propagate",
        fields=["defaultSecurityPolicyId", "defaultSecurityPolicyId"],
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    request = route.calls.last.request
    assert request.method == "PATCH"
    assert _body(request) == ["defaultSecurityPolicyId"]
    assert result["endpoint"] == "PATCH /organizations/{id}/settings/projects/issues/security"
    assert result["data"]["action"] == "propagate"


@pytest.mark.asyncio
async def test_replace_an_admin_section_succeeds_once_admin_is_enabled(
    admin_settings, respx_mock, make_context
):
    """The ADMIN happy path. `saml` used to stand in for this; it moved out."""
    route = respx_mock.put(f"{ORG}/settings/authentication").mock(
        return_value=httpx.Response(200, json={"subdomain": "acme", "disableInvite": True})
    )

    body = {"subdomain": "acme", "disableInvite": True}

    client = FossaClient(admin_settings)
    result = await org_settings.update_org_settings(
        make_context(client, admin_settings), "authentication", values=body
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _body(route.calls.last.request) == body
    assert result["endpoint"] == "PUT /organizations/{id}/settings/authentication"


@pytest.mark.asyncio
async def test_general_without_access_control_keys_needs_only_write(
    writable_settings, respx_mock, make_context
):
    route = respx_mock.put(f"{ORG}/settings/general").mock(
        return_value=httpx.Response(200, json={"title": "Acme"})
    )

    client = FossaClient(writable_settings)
    await org_settings.update_org_settings(
        make_context(client, writable_settings), "general", values={"title": "Acme"}
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert _body(route.calls.last.request) == {"title": "Acme"}


@pytest.mark.asyncio
async def test_delete_logo(destructive_settings, respx_mock, make_context):
    route = respx_mock.delete(f"{ORG}/logo").mock(
        return_value=httpx.Response(200, json={"success": True})
    )

    client = FossaClient(destructive_settings)
    result = await org_settings.delete_org_setting(
        make_context(client, destructive_settings), "logo"
    )
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert route.calls.last.request.method == "DELETE"
    assert result["endpoint"] == "DELETE /organizations/{id}/logo"
    assert result["data"]["deleted"] is True


@pytest.mark.asyncio
async def test_delete_logo_tolerates_an_empty_body(full_settings, respx_mock, make_context):
    respx_mock.delete(f"{ORG}/logo").mock(return_value=httpx.Response(204))

    client = FossaClient(full_settings)
    result = await org_settings.delete_org_setting(make_context(client, full_settings), "logo")
    await client.aclose()

    assert respx_mock.calls.call_count == 1
    assert result["ok"] is True
    assert result["data"]["response"] is None


# --- refusals: one per tier, each proving zero HTTP calls --------------------


@pytest.mark.asyncio
async def test_write_tier_off_refuses_before_requesting(
    org_settings_config, respx_mock, make_context
):
    client = FossaClient(org_settings_config)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await org_settings.update_org_settings(
            make_context(client, org_settings_config),
            "projects-privacy",
            values={"defaultProjectPrivacy": "private"},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_admin_section_is_not_reachable_through_the_write_tier(
    writable_settings, respx_mock, make_context
):
    """An ADMIN section must refuse even with FOSSA_ALLOW_WRITES on."""
    client = FossaClient(writable_settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_ADMIN"):
        await org_settings.update_org_settings(
            make_context(client, writable_settings),
            "authentication",
            values={"disableInvite": True},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_general_escalates_to_admin_for_access_control_keys(
    writable_settings, respx_mock, make_context
):
    """`defaultRoleId` decides what every new member may do, so it is ADMIN."""
    client = FossaClient(writable_settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_ADMIN"):
        await org_settings.update_org_settings(
            make_context(client, writable_settings), "general", values={"defaultRoleId": 3}
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_propagate_is_not_reachable_through_the_write_tier(
    writable_settings, respx_mock, make_context
):
    """Propagate rewrites every project in the organization, so it is DESTRUCTIVE."""
    client = FossaClient(writable_settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await org_settings.update_org_settings(
            make_context(client, writable_settings),
            "projects-privacy",
            action="propagate",
            fields=["defaultProjectPrivacy"],
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_delete_with_destructive_off_refuses_before_requesting(
    writable_settings, respx_mock, make_context
):
    client = FossaClient(writable_settings)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_DESTRUCTIVE"):
        await org_settings.delete_org_setting(make_context(client, writable_settings), "logo")
    await client.aclose()

    assert respx_mock.calls.call_count == 0


@pytest.mark.asyncio
async def test_every_tier_refuses_when_writes_are_off(
    org_settings_config, respx_mock, make_context
):
    """FOSSA_ALLOW_DESTRUCTIVE/ADMIN alone grant nothing; writes must be on too."""
    half_configured = org_settings_config.model_copy(
        update={"fossa_allow_destructive": True, "fossa_allow_admin": True}
    )

    client = FossaClient(half_configured)
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await org_settings.delete_org_setting(make_context(client, half_configured), "logo")
    with pytest.raises(FossaWriteNotPermittedError, match="FOSSA_ALLOW_WRITES"):
        await org_settings.update_org_settings(
            make_context(client, half_configured),
            "authentication",
            values={"disableInvite": True},
        )
    await client.aclose()

    assert respx_mock.calls.call_count == 0
