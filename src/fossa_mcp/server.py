"""FOSSA MCP server implementation."""

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from . import __version__
from .client import FossaClient
from .config import Settings
from .tools import (
    dependencies,
    identity,
    integrations,
    inventory,
    issues,
    labels,
    org_settings,
    policies,
    posture,
    projects,
    release_groups,
    reports,
    revisions,
    teams,
)

logger = logging.getLogger(__name__)

settings = Settings()


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Own the single FOSSA HTTP client for the life of the server process."""
    client = FossaClient(settings)
    try:
        yield {"client": client, "settings": settings}
    finally:
        await client.aclose()


mcp = FastMCP(
    "FOSSA",
    instructions=(
        "Access to a FOSSA organization across most of its API. The domains are: "
        "projects and their settings; revisions and the attribution reports built "
        "from them; dependencies and the package inventory behind them; issues "
        "(licensing, vulnerability, and quality, together with the exceptions, "
        "disputes, and saved filters around them); release groups; package and "
        "organization labels; organization settings and plan limits; teams, team "
        "groups, roles, and users; federated identity (OIDC and SAML); "
        "integrations (Jira, fossabot, saved report presets, custom risk scores, "
        "snippet review); and the long-tail reads — binary decomposition, audit "
        "logs, SBOM sharing, builds, the CVE catalog, and remediation guidance. "
        "Security policy assignment and evaluation sit on top.\n\n"
        "Roughly half the tools only read. Every tool that changes FOSSA state "
        "says so on the second line of its description and names the environment "
        "variables it needs. Writes are tiered and every tier is off by "
        "default:\n"
        "- FOSSA_ALLOW_WRITES=true permits creates and updates. Nothing writes "
        "without it, whatever else is set.\n"
        "- FOSSA_ALLOW_DESTRUCTIVE=true additionally permits deletes, the writes "
        "that replace state wholesale rather than merging into it, and the bulk "
        "operations whose target set is a filter rather than an explicit list.\n"
        "- FOSSA_ALLOW_ADMIN=true additionally permits the identity, "
        "authentication, and access-control writes: teams, team groups, roles, "
        "service accounts, OIDC, and SAML.\n"
        "A tool whose tier is disabled refuses before it constructs a request, so "
        "nothing reaches FOSSA. Some tools need two tiers at once — deleting a "
        "team needs admin and destructive both — and some decide per call, so the "
        "same tool can be permitted with one set of arguments and refused with "
        "another.\n\n"
        "A tool advertising destructiveHint=true removes state or replaces it "
        "wholesale, and FOSSA has no undo. Read before you write, passing the "
        "same arguments each time: fossa_list_issues before fossa_update_issues, "
        "fossa_get_issue_exceptions before fossa_delete_issue_exceptions, "
        "fossa_list_projects before fossa_delete_projects, fossa_get_team before "
        "fossa_update_team_assignments, fossa_org_settings before "
        "fossa_update_org_settings (its writes replace a section rather than "
        "merging, so send the whole section), and fossa_evaluate_security_policy "
        "before fossa_enable_security_policy.\n\n"
        "Two addressing notes. Release groups are addressed by numeric id only; "
        "there is no list-release-groups endpoint, so find the id in the release "
        "group's FOSSA URL or through fossa_get_project_associations. The "
        "organization settings, limits, and SAML tools address "
        "/organizations/{id}/... and need FOSSA_ORG_ID set."
    ),
    lifespan=lifespan,
    host=settings.fossa_http_host,
    port=settings.fossa_http_port,
)


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> PlainTextResponse:
    """Liveness endpoint for the streamable-http transport."""
    return PlainTextResponse("ok")


# These five constants are the whole annotation vocabulary. Every tool in every
# domain is registered with one of them, and nothing is annotated inline: the
# parity branches each invented their own set, the same name meant different
# things in different branches, and collapsing them here is what stops a client
# from seeing two tools that behave alike advertise different hints.
#
# The axis that decides between them is blast radius, not the HTTP verb — the
# same rule the write tiers follow (DECISIONS.md §7). A PATCH that rewrites
# every project in the organization is destructive; a POST that mints one record
# is not.
_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=True)

# A write that converges. These set named fields on a named target (PUT/PATCH,
# or a PUT over an explicit list of locators): re-applying the same call leaves
# FOSSA in the state the first call produced, so idempotentHint is True and a
# client may retry a timeout. Nothing is removed and no target set is implied
# by a filter, so destructiveHint is False.
_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

# Security policy assignment has exactly the profile above — re-applying the
# same policy id converges rather than destroying anything — and keeps its own
# name because DECISIONS.md §5 addresses these two tools specifically.
_POLICY_WRITE = _WRITE

# A write that accumulates. Calls that mint a record, queue a background job,
# send mail, or regenerate a URL: the second call is a second dispute, a second
# export job, a second email — not a no-op — so idempotentHint is False and a
# client must not retry blindly. They still remove nothing, so destructiveHint
# stays False even where the effect is externally visible.
_WRITE_ACCUMULATING = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

# Removes state, or replaces it wholesale. Deletes are the obvious members; so
# are the reconciling PUTs whose body is a desired state and which silently drop
# whatever it does not mention, and the organization-settings PATCH that
# overwrites the setting on every project at once. destructiveHint is reserved
# for these and for the unbounded case below, so that a client treating the hint
# as a confirmation prompt is prompted wherever FOSSA offers no undo. Repeating
# the call removes nothing further, so idempotentHint is True.
#
# Every tool annotated with this — or with _DESTRUCTIVE_UNBOUNDED — reaches
# `require_tier(..., WriteTier.DESTRUCTIVE, ...)` on the path that destroys, in
# addition to any ADMIN requirement. The hint and the gate say the same thing.
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=True,
)

# The above, plus a second call is not a no-op. Two shapes land here: a tool
# whose target set is a filter rather than a named list and which also creates
# durable state (fossa_update_issues, whose issueException action writes an
# ignore rule), and the create/update/delete multiplexers, where a static
# annotation has to advertise the worst action it can be asked to perform.
_DESTRUCTIVE_UNBOUNDED = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

# --- projects ----------------------------------------------------------------
mcp.tool(name="fossa_list_projects", annotations=_READ_ONLY)(projects.list_projects)
mcp.tool(name="fossa_get_project", annotations=_READ_ONLY)(projects.get_project)
mcp.tool(name="fossa_get_projects_summary", annotations=_READ_ONLY)(projects.get_projects_summary)
mcp.tool(name="fossa_get_project_associations", annotations=_READ_ONLY)(
    projects.get_project_associations
)
mcp.tool(name="fossa_export_project_issues", annotations=_READ_ONLY)(projects.export_project_issues)
mcp.tool(name="fossa_update_project", annotations=_WRITE)(projects.update_project)
mcp.tool(name="fossa_apply_project_label", annotations=_WRITE)(projects.apply_project_label)
# Regenerating the slug mints a new one and breaks every previously shared
# report link, so it is not idempotent. It is still not destructiveHint=True:
# that hint is kept for deletes and unbounded targets, and the link breakage is
# spelled out in the tool's own description.
mcp.tool(name="fossa_generate_project_attribution_slug", annotations=_WRITE_ACCUMULATING)(
    projects.generate_project_attribution_slug
)
mcp.tool(name="fossa_delete_project_attribution_slug", annotations=_DESTRUCTIVE)(
    projects.delete_project_attribution_slug
)
mcp.tool(name="fossa_delete_project", annotations=_DESTRUCTIVE)(projects.delete_project)
mcp.tool(name="fossa_delete_projects", annotations=_DESTRUCTIVE)(projects.delete_projects)

# --- revisions ---------------------------------------------------------------
mcp.tool(name="fossa_list_project_revisions", annotations=_READ_ONLY)(
    revisions.list_project_revisions
)
mcp.tool(name="fossa_list_revision_scans", annotations=_READ_ONLY)(revisions.list_revision_scans)
mcp.tool(name="fossa_get_revision_notice_files", annotations=_READ_ONLY)(
    revisions.get_revision_notice_files
)
mcp.tool(name="fossa_get_revision_sbom", annotations=_READ_ONLY)(revisions.get_revision_sbom)
mcp.tool(name="fossa_get_revision_remediation_guidance", annotations=_READ_ONLY)(
    revisions.get_revision_remediation_guidance
)
mcp.tool(name="fossa_get_revision_attribution_json", annotations=_READ_ONLY)(
    revisions.get_revision_attribution_json
)
mcp.tool(name="fossa_render_revision_attribution", annotations=_READ_ONLY)(
    revisions.render_revision_attribution
)
mcp.tool(name="fossa_list_revision_dependencies_v1", annotations=_READ_ONLY)(
    revisions.list_revision_dependencies_v1
)
mcp.tool(name="fossa_update_revision", annotations=_WRITE)(revisions.update_revision)
# Two GETs that are writes in effect: one queues an outbound email, the other
# publishes an unauthenticated URL onto the dependency inventory. Each call has
# a fresh external effect, so neither is idempotent.
mcp.tool(name="fossa_email_revision_attribution", annotations=_WRITE_ACCUMULATING)(
    revisions.email_revision_attribution
)
mcp.tool(name="fossa_create_public_attribution_report", annotations=_WRITE_ACCUMULATING)(
    revisions.create_public_attribution_report
)

# --- dependencies ------------------------------------------------------------
mcp.tool(name="fossa_list_dependencies", annotations=_READ_ONLY)(dependencies.list_dependencies)
mcp.tool(name="fossa_get_dependency", annotations=_READ_ONLY)(dependencies.get_dependency)

# --- issues, issue overview, and saved issue filters -------------------------
mcp.tool(name="fossa_list_issues", annotations=_READ_ONLY)(issues.list_issues)
mcp.tool(name="fossa_get_issue", annotations=_READ_ONLY)(issues.get_issue)
mcp.tool(name="fossa_get_issue_facets", annotations=_READ_ONLY)(issues.get_issue_facets)
mcp.tool(name="fossa_list_issue_revisions", annotations=_READ_ONLY)(issues.list_issue_revisions)
mcp.tool(name="fossa_compare_issue_summaries", annotations=_READ_ONLY)(
    issues.compare_issue_summaries
)
mcp.tool(name="fossa_get_issue_affected_projects", annotations=_READ_ONLY)(
    issues.get_issue_affected_projects
)
mcp.tool(name="fossa_export_global_issues_csv", annotations=_READ_ONLY)(
    issues.export_global_issues_csv
)
mcp.tool(name="fossa_get_issue_exceptions", annotations=_READ_ONLY)(issues.get_issue_exceptions)
mcp.tool(name="fossa_get_issue_overview", annotations=_READ_ONLY)(issues.get_issue_overview)
mcp.tool(name="fossa_get_issue_filters", annotations=_READ_ONLY)(issues.get_issue_filters)
mcp.tool(name="fossa_update_issues", annotations=_DESTRUCTIVE_UNBOUNDED)(issues.update_issues)
mcp.tool(name="fossa_extend_issue_exception", annotations=_WRITE)(issues.extend_issue_exception)
mcp.tool(name="fossa_delete_issue_exceptions", annotations=_DESTRUCTIVE)(
    issues.delete_issue_exceptions
)
mcp.tool(name="fossa_create_issue_dispute", annotations=_WRITE_ACCUMULATING)(
    issues.create_issue_dispute
)
# Reads nothing back: it queues a background export job in the organization and
# returns a token, so a retry is a second job.
mcp.tool(name="fossa_export_issue_overview", annotations=_WRITE_ACCUMULATING)(
    issues.export_issue_overview
)
# Create-or-update behind one tool: without filter_id it POSTs a new saved
# filter every time, so the annotation follows the create branch.
mcp.tool(name="fossa_save_issue_filter", annotations=_WRITE_ACCUMULATING)(issues.save_issue_filter)
mcp.tool(name="fossa_delete_issue_filter", annotations=_DESTRUCTIVE)(issues.delete_issue_filter)

# --- release groups ----------------------------------------------------------
mcp.tool(name="fossa_get_release_group", annotations=_READ_ONLY)(release_groups.get_release_group)
mcp.tool(name="fossa_list_release_group_releases", annotations=_READ_ONLY)(
    release_groups.list_release_group_releases
)
mcp.tool(name="fossa_get_release_group_release", annotations=_READ_ONLY)(
    release_groups.get_release_group_release
)
mcp.tool(name="fossa_get_release_group_attribution_report", annotations=_READ_ONLY)(
    release_groups.get_release_group_attribution_report
)
mcp.tool(name="fossa_get_release_group_attribution_status", annotations=_READ_ONLY)(
    release_groups.get_release_group_attribution_status
)
mcp.tool(name="fossa_create_release_group", annotations=_WRITE_ACCUMULATING)(
    release_groups.create_release_group
)
mcp.tool(name="fossa_update_release_group", annotations=_WRITE)(release_groups.update_release_group)
mcp.tool(name="fossa_delete_release_group", annotations=_DESTRUCTIVE)(
    release_groups.delete_release_group
)
mcp.tool(name="fossa_create_release_group_release", annotations=_WRITE_ACCUMULATING)(
    release_groups.create_release_group_release
)
mcp.tool(name="fossa_update_release_group_release", annotations=_WRITE)(
    release_groups.update_release_group_release
)
mcp.tool(name="fossa_delete_release_group_release", annotations=_DESTRUCTIVE)(
    release_groups.delete_release_group_release
)
# Queues a job and, with is_publishing set, pushes the report onto the SBOM
# portal. The synchronous v2 read is fossa_get_release_group_attribution_report.
mcp.tool(name="fossa_queue_release_group_attribution_report", annotations=_WRITE_ACCUMULATING)(
    release_groups.queue_release_group_attribution_report
)

# --- posture and reports -----------------------------------------------------
mcp.tool(name="fossa_project_posture", annotations=_READ_ONLY)(posture.project_posture)
mcp.tool(name="fossa_get_attribution_report", annotations=_READ_ONLY)(
    reports.get_attribution_report
)

# --- security policy ---------------------------------------------------------
mcp.tool(name="fossa_get_security_policy", annotations=_READ_ONLY)(policies.get_security_policy)
mcp.tool(name="fossa_evaluate_security_policy", annotations=_READ_ONLY)(
    policies.evaluate_security_policy
)
mcp.tool(name="fossa_enable_security_policy", annotations=_POLICY_WRITE)(
    policies.enable_security_policy
)
mcp.tool(name="fossa_assign_security_policy_to_projects", annotations=_POLICY_WRITE)(
    policies.assign_security_policy_to_projects
)

# --- teams, team groups, roles, and users ------------------------------------
# FOSSA's access-control surface. Every write is WriteTier.ADMIN; the ones that
# take something away are additionally WriteTier.DESTRUCTIVE.
mcp.tool(name="fossa_list_teams", annotations=_READ_ONLY)(teams.list_teams)
mcp.tool(name="fossa_get_team", annotations=_READ_ONLY)(teams.get_team)
mcp.tool(name="fossa_list_addable_team_targets", annotations=_READ_ONLY)(
    teams.list_addable_team_targets
)
mcp.tool(name="fossa_get_team_groups", annotations=_READ_ONLY)(teams.get_team_groups)
mcp.tool(name="fossa_list_roles", annotations=_READ_ONLY)(teams.list_roles)
mcp.tool(name="fossa_list_users", annotations=_READ_ONLY)(teams.list_users)
mcp.tool(name="fossa_create_team", annotations=_WRITE_ACCUMULATING)(teams.create_team)
mcp.tool(name="fossa_update_team", annotations=_WRITE)(teams.update_team)
mcp.tool(name="fossa_delete_team", annotations=_DESTRUCTIVE)(teams.delete_team)
# Membership as an action over a list: "replace" sets the collection to exactly
# what is named and drops the rest, and the projects target accepts "all" or a
# server-resolved filter.
mcp.tool(name="fossa_update_team_assignments", annotations=_DESTRUCTIVE)(
    teams.update_team_assignments
)
# Create/update/delete behind one tool, so the annotation advertises delete.
mcp.tool(name="fossa_manage_team_group", annotations=_DESTRUCTIVE_UNBOUNDED)(
    teams.manage_team_group
)
mcp.tool(name="fossa_update_team_group_assignments", annotations=_DESTRUCTIVE)(
    teams.update_team_group_assignments
)
mcp.tool(name="fossa_manage_role", annotations=_DESTRUCTIVE_UNBOUNDED)(teams.manage_role)
mcp.tool(name="fossa_create_service_account", annotations=_WRITE_ACCUMULATING)(
    teams.create_service_account
)

# --- package labels, label assignments, and organization labels --------------
mcp.tool(name="fossa_list_package_labels", annotations=_READ_ONLY)(labels.list_package_labels)
mcp.tool(name="fossa_list_package_label_assignments", annotations=_READ_ONLY)(
    labels.list_package_label_assignments
)
mcp.tool(name="fossa_list_organization_labels", annotations=_READ_ONLY)(
    labels.list_organization_labels
)
mcp.tool(name="fossa_create_package_labels", annotations=_WRITE_ACCUMULATING)(
    labels.create_package_labels
)
mcp.tool(name="fossa_delete_package_labels", annotations=_DESTRUCTIVE)(labels.delete_package_labels)
mcp.tool(name="fossa_assign_package_labels", annotations=_WRITE_ACCUMULATING)(
    labels.assign_package_labels
)
mcp.tool(name="fossa_bulk_assign_package_label", annotations=_WRITE_ACCUMULATING)(
    labels.bulk_assign_package_label
)
# A reconcile, not an add: the map it is given becomes the whole assignment set
# and anything absent from it is removed, which is why the verb is misleading.
mcp.tool(name="fossa_set_package_label_assignments", annotations=_DESTRUCTIVE)(
    labels.set_package_label_assignments
)
mcp.tool(name="fossa_unassign_package_labels", annotations=_DESTRUCTIVE)(
    labels.unassign_package_labels
)
mcp.tool(name="fossa_create_organization_label", annotations=_WRITE_ACCUMULATING)(
    labels.create_organization_label
)
mcp.tool(name="fossa_delete_organization_label", annotations=_DESTRUCTIVE)(
    labels.delete_organization_label
)

# --- organization settings and limits ----------------------------------------
# Grouped: a section name selects the endpoint and an action selects the verb.
# The SAML operations the spec files under this tag are in the identity group.
mcp.tool(name="fossa_org_settings", annotations=_READ_ONLY)(org_settings.get_org_settings)
mcp.tool(name="fossa_org_limits", annotations=_READ_ONLY)(org_settings.get_org_limits)
# Destructive on two counts: the PUTs replace a section wholesale rather than
# merging, and action="propagate" pushes the organization default onto every
# existing project in one call.
mcp.tool(name="fossa_update_org_settings", annotations=_DESTRUCTIVE)(
    org_settings.update_org_settings
)
mcp.tool(name="fossa_delete_org_setting", annotations=_DESTRUCTIVE)(org_settings.delete_org_setting)

# --- federated identity: OIDC and SAML ---------------------------------------
# Every write is WriteTier.ADMIN; the three deletes are also DESTRUCTIVE.
mcp.tool(name="fossa_list_oidc_providers", annotations=_READ_ONLY)(identity.list_oidc_providers)
mcp.tool(name="fossa_get_oidc_provider", annotations=_READ_ONLY)(identity.get_oidc_provider)
mcp.tool(name="fossa_list_oidc_provider_service_accounts", annotations=_READ_ONLY)(
    identity.list_oidc_provider_service_accounts
)
mcp.tool(name="fossa_list_oidc_trust_relationships", annotations=_READ_ONLY)(
    identity.list_oidc_trust_relationships
)
mcp.tool(name="fossa_get_oidc_trust_relationship", annotations=_READ_ONLY)(
    identity.get_oidc_trust_relationship
)
mcp.tool(name="fossa_create_oidc_provider", annotations=_WRITE_ACCUMULATING)(
    identity.create_oidc_provider
)
mcp.tool(name="fossa_delete_oidc_provider", annotations=_DESTRUCTIVE)(identity.delete_oidc_provider)
mcp.tool(name="fossa_create_oidc_trust_relationship", annotations=_WRITE_ACCUMULATING)(
    identity.create_oidc_trust_relationship
)
mcp.tool(name="fossa_update_oidc_trust_relationship", annotations=_WRITE)(
    identity.update_oidc_trust_relationship
)
mcp.tool(name="fossa_delete_oidc_trust_relationship", annotations=_DESTRUCTIVE)(
    identity.delete_oidc_trust_relationship
)
# Mints a live FOSSA API token on every call. The tool redacts it, but the
# credential exists in FOSSA afterwards, so a retry is a second credential.
mcp.tool(name="fossa_exchange_oidc_token", annotations=_WRITE_ACCUMULATING)(
    identity.exchange_oidc_token
)
mcp.tool(name="fossa_update_saml_settings", annotations=_WRITE)(identity.update_saml_settings)
mcp.tool(name="fossa_delete_saml_settings", annotations=_DESTRUCTIVE)(identity.delete_saml_settings)

# --- integrations: Jira, fossabot, report options, risk scores, snippets ------
mcp.tool(name="fossa_get_jira_configurations", annotations=_READ_ONLY)(
    integrations.get_jira_configurations
)
mcp.tool(name="fossa_get_fossabot_status", annotations=_READ_ONLY)(integrations.get_fossabot_status)
mcp.tool(name="fossa_list_fossabot_upgrade_prs", annotations=_READ_ONLY)(
    integrations.list_fossabot_upgrade_prs
)
mcp.tool(name="fossa_get_fossabot_upgrade_pr", annotations=_READ_ONLY)(
    integrations.get_fossabot_upgrade_pr
)
mcp.tool(name="fossa_list_report_options", annotations=_READ_ONLY)(integrations.list_report_options)
mcp.tool(name="fossa_list_snippets", annotations=_READ_ONLY)(integrations.list_snippets)
mcp.tool(name="fossa_get_snippet", annotations=_READ_ONLY)(integrations.get_snippet)
mcp.tool(name="fossa_save_jira_configuration", annotations=_WRITE_ACCUMULATING)(
    integrations.save_jira_configuration
)
mcp.tool(name="fossa_delete_jira_configuration", annotations=_DESTRUCTIVE)(
    integrations.delete_jira_configuration
)
mcp.tool(name="fossa_request_fossabot_upgrade_pr", annotations=_WRITE_ACCUMULATING)(
    integrations.request_fossabot_upgrade_pr
)
mcp.tool(name="fossa_save_report_option", annotations=_WRITE_ACCUMULATING)(
    integrations.save_report_option
)
mcp.tool(name="fossa_delete_report_option", annotations=_DESTRUCTIVE)(
    integrations.delete_report_option
)
mcp.tool(name="fossa_set_custom_risk_score", annotations=_WRITE_ACCUMULATING)(
    integrations.set_custom_risk_score
)
mcp.tool(name="fossa_delete_custom_risk_score", annotations=_DESTRUCTIVE)(
    integrations.delete_custom_risk_score
)
# Takes a filter, not a list: path="/" alone suppresses every snippet match in
# the revision, so the tier is picked at call time and the hint advertises the
# worse branch.
mcp.tool(name="fossa_set_snippet_rejection", annotations=_DESTRUCTIVE)(
    integrations.set_snippet_rejection
)

# --- inventory: binaries, packages, components, audit, SBOM, builds, vulns ----
mcp.tool(name="fossa_binary_components", annotations=_READ_ONLY)(inventory.binary_components)
mcp.tool(name="fossa_binary_dependency_confidence", annotations=_READ_ONLY)(
    inventory.binary_dependency_confidence
)
mcp.tool(name="fossa_binary_revision_detail", annotations=_READ_ONLY)(
    inventory.binary_revision_detail
)
mcp.tool(name="fossa_list_packages", annotations=_READ_ONLY)(inventory.list_packages)
mcp.tool(name="fossa_package_observability", annotations=_READ_ONLY)(
    inventory.package_observability
)
mcp.tool(name="fossa_export_package_index", annotations=_READ_ONLY)(inventory.export_package_index)
mcp.tool(name="fossa_get_component_upload_url", annotations=_READ_ONLY)(
    inventory.get_component_upload_url
)
mcp.tool(name="fossa_get_audit_logs", annotations=_READ_ONLY)(inventory.get_audit_logs)
mcp.tool(name="fossa_get_sbom_sharing", annotations=_READ_ONLY)(inventory.get_sbom_sharing)
mcp.tool(name="fossa_get_builds", annotations=_READ_ONLY)(inventory.get_builds)
mcp.tool(name="fossa_search_cves", annotations=_READ_ONLY)(inventory.search_cves)
mcp.tool(name="fossa_get_vulnerability_remediation", annotations=_READ_ONLY)(
    inventory.get_vulnerability_remediation
)
mcp.tool(name="fossa_get_cli_organization", annotations=_READ_ONLY)(inventory.get_cli_organization)
mcp.tool(name="fossa_get_github_app_installation_url", annotations=_READ_ONLY)(
    inventory.get_github_app_installation_url
)
# A read in intent, but a PURL FOSSA has not analyzed yet is queued for a build.
mcp.tool(name="fossa_resolve_purls", annotations=_WRITE_ACCUMULATING)(inventory.resolve_purls)
mcp.tool(name="fossa_build_component", annotations=_WRITE_ACCUMULATING)(inventory.build_component)
mcp.tool(name="fossa_export_audit_logs", annotations=_WRITE_ACCUMULATING)(
    inventory.export_audit_logs
)
mcp.tool(name="fossa_share_sbom_revision", annotations=_WRITE_ACCUMULATING)(
    inventory.share_sbom_revision
)
# Unconcluding removes a conclusion, and concluding at organization scope
# re-licenses a dependency for every project in one call.
mcp.tool(name="fossa_set_license_conclusion", annotations=_DESTRUCTIVE)(
    inventory.set_license_conclusion
)


def _forbid_unexpected_tool_arguments(server: FastMCP) -> None:
    """Make tools reject unknown arguments instead of silently dropping them.

    FastMCP 1.28 generates each tool's argument model with Pydantic's default
    `extra="ignore"`, so a client that passes a misspelled or invented argument
    gets a successful call with that argument discarded — an easy way for a
    model to believe it applied a filter that never reached FOSSA. Tighten every
    generated model and republish its JSON schema so `additionalProperties:
    false` is advertised too.

    This reaches into the tool manager because 1.28 exposes no public hook. Fold
    it into tool registration when moving to the 2.x SDK (see DECISIONS.md).
    """
    for tool in server._tool_manager._tools.values():
        arg_model = tool.fn_metadata.arg_model
        arg_model.model_config["extra"] = "forbid"
        arg_model.model_rebuild(force=True)
        tool.parameters = arg_model.model_json_schema(by_alias=True)


_forbid_unexpected_tool_arguments(mcp)

_ALLOWED_TRANSPORTS = ("stdio", "streamable-http")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for the FOSSA MCP server."""
    args = sys.argv[1:] if argv is None else argv
    transport = "stdio"

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--transport":
            if idx + 1 >= len(args):
                raise ValueError("Missing transport value after --transport")
            transport = args[idx + 1]
            if transport not in _ALLOWED_TRANSPORTS:
                raise ValueError(f"Unknown transport: {transport}")
            idx += 2
        elif arg == "--version":
            print(f"fossa-mcp version {__version__}")
            return
        else:
            raise ValueError(f"Unknown argument: {arg}")

    logging.basicConfig(
        level=settings.log_level_int,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    logger.info("Starting FOSSA MCP server with transport: %s", transport)

    # mcp.run() is synchronous: it drives its own anyio event loop.
    mcp.run(transport=transport)
