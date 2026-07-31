"""Integration and configuration tools for the FOSSA MCP server.

Five domains that configure FOSSA rather than describe a codebase: Jira sites
(`/jira`), fossabot dependency-upgrade pull requests (`/fossabot/...`), saved
report options (`/report-options`), custom risk scores
(`/custom-risk-scores/{issueId}`), and snippet review state
(`/revisions/{locator}/snippets/...`).

Three things about this module are worth stating up front:

* **Jira configuration is the only place in this server where a caller hands
  over someone else's credentials.** FOSSA stores a Jira username and password
  (or an API token in an arbitrary header) so it can open tickets. Those values
  have to be sendable or the integration cannot be configured, but no tool here
  ever returns one: `_redact_jira_configuration` strips `credentials`,
  `headers` and `webhookURL` from every response and reports presence instead.
  `webhookURL` is redacted for the same reason as the other two — it is a
  capability URL that authenticates whoever holds it.
* **Custom risk scores are FOSSA's own.** These tools write the `score` FOSSA
  stores against a vulnerability issue in a project or release-group scope, and
  it is that stored value which surfaces as `customRiskScore` on an issue. It
  has nothing to do with the independent impact score this repo's
  `fossa-suggest-score` skill computes, which never writes to FOSSA.
* **Rejecting snippets is tiered by blast radius.** `POST .../snippets/reject`
  takes a filter, not a list, and a filter of `path="/"` alone suppresses every
  snippet match in a revision. Naming `snippet_ids` or `package_ids` makes the
  target set explicit and the call is `WRITE`; a filter-shaped call is
  `DESTRUCTIVE`, the same rule the bulk issue update follows.
"""

import json
from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models.integrations import (
    REPORT_OPTION_DEPENDENCY_FIELDS,
    REPORT_OPTION_SECTIONS,
    CustomRiskScoreDeleteInput,
    CustomRiskScoreSaveInput,
    FossabotFix,
    FossabotIssuePRInput,
    FossabotPRSort,
    FossabotPRState,
    FossabotStatusInput,
    FossabotUpgradePRListInput,
    FossabotUpgradePRRequestInput,
    JiraClearableField,
    JiraComponent,
    JiraConfigurationDeleteInput,
    JiraConfigurationSaveInput,
    JiraCustomField,
    ReportOptionDeleteInput,
    ReportOptionDependencyField,
    ReportOptionSaveInput,
    ReportOptionSection,
    RiskScoreAction,
    RiskScoreScope,
    SnippetChangeStatus,
    SnippetFilters,
    SnippetListInput,
    SnippetReadInput,
    SnippetRejectionInput,
    SnippetRejectionStatus,
    SnippetSort,
    SnippetVendoredMatch,
    SnippetView,
)
from ..query import split_revision_locator
from ..writes import WriteTier, require_tier

# --- shared helpers ----------------------------------------------------------


def _revision_path_locator(project_locator: str, revision_locator: str) -> tuple[str, str]:
    """Return `(full_locator, url_encoded_locator)` for a revision path segment."""
    full_locator, _ = split_revision_locator(project_locator, revision_locator)
    return full_locator, quote(full_locator, safe="")


# --- Jira --------------------------------------------------------------------

_JIRA_SECRET_KEYS = ("credentials", "headers", "webhookURL")


def _redact_jira_configuration(config: Any) -> Any:
    """Strip every credential-bearing field from a Jira configuration.

    Three fields authenticate FOSSA to a customer's Jira and never leave this
    function: `credentials.basic` (username and password), `headers` (where an
    API token is normally carried), and `webhookURL` (a capability URL). Each is
    replaced by a presence flag so a caller can still see whether the site is
    configured. Header *names* are kept because they are not secret and make a
    misconfiguration diagnosable; header values are not.

    FOSSA documents the password as "obfuscated when retrieved". This does not
    rely on that.
    """
    if not isinstance(config, dict):
        return config

    redacted = {key: value for key, value in config.items() if key not in _JIRA_SECRET_KEYS}

    credentials = config.get("credentials")
    basic = credentials.get("basic") if isinstance(credentials, dict) else None
    redacted["credentials_redacted"] = {
        "username_set": bool(isinstance(basic, dict) and basic.get("username")),
        "password_set": bool(isinstance(basic, dict) and basic.get("password")),
    }

    headers = config.get("headers")
    redacted["headers_redacted"] = {
        "header_names": sorted(headers) if isinstance(headers, dict) else [],
    }

    redacted["webhook_url_set"] = bool(config.get("webhookURL"))
    return redacted


async def get_jira_configurations(ctx: Context) -> dict[str, Any]:
    """
    List every Jira site this FOSSA organization is configured to export issues
    to.

    Read-only. Credentials, request headers, and the inbound webhook URL are
    replaced by presence flags — this tool never returns a secret, so use the
    FOSSA web app if you need to read one back.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    result = await client.request_json("GET", "/jira")
    configurations = result if isinstance(result, list) else []

    return {
        "ok": True,
        "endpoint": "GET /jira",
        "data": {
            "configurations": [_redact_jira_configuration(item) for item in configurations],
            "count": len(configurations),
            "redacted_fields": list(_JIRA_SECRET_KEYS),
        },
    }


def _jira_components(components: list[dict[str, Any]] | None) -> list[JiraComponent] | None:
    """Validate the raw component entries a tool received.

    The tool signature takes plain objects so FastMCP builds the schema from the
    signature alone; the strictness (`id` and `displayName` required, unknown
    keys rejected) lives in the model.
    """
    if components is None:
        return None
    return [JiraComponent.model_validate(component) for component in components]


def _jira_custom_fields(
    custom_fields: dict[str, dict[str, Any]] | None,
) -> dict[str, JiraCustomField] | None:
    """Validate the raw custom-field entries a tool received."""
    if custom_fields is None:
        return None
    return {key: JiraCustomField.model_validate(value) for key, value in custom_fields.items()}


def _jira_payload(validated: JiraConfigurationSaveInput) -> dict[str, Any]:
    """Build the Jira request body from the validated input."""
    payload: dict[str, Any] = {}

    if validated.name is not None:
        payload["name"] = validated.name
    if validated.enabled is not None:
        payload["enabled"] = validated.enabled
    if validated.base_url is not None:
        payload["base_url"] = validated.base_url
    if validated.resolved_statuses is not None:
        payload["resolved_statuses"] = validated.resolved_statuses
    if validated.resolved_statuses_enabled is not None:
        payload["resolvedStatusesEnabled"] = validated.resolved_statuses_enabled
    if validated.username is not None and validated.password is not None:
        payload["credentials"] = {
            "basic": {"username": validated.username, "password": validated.password}
        }
    if validated.headers is not None:
        payload["headers"] = validated.headers
    if validated.issue_types is not None:
        payload["issueTypes"] = validated.issue_types
    if validated.labels is not None:
        payload["labels"] = validated.labels
    if validated.components is not None:
        payload["components"] = [
            component.model_dump(mode="json") for component in validated.components
        ]
    if validated.jira_project_ids is not None:
        payload["jiraProjectIds"] = validated.jira_project_ids
    if validated.custom_fields is not None:
        payload["customFields"] = {
            key: field.model_dump(mode="json") for key, field in validated.custom_fields.items()
        }
    if validated.default_licensing_project is not None:
        payload["defaultLicensingProject"] = validated.default_licensing_project
    if validated.default_security_project is not None:
        payload["defaultSecurityProject"] = validated.default_security_project
    if validated.default_quality_project is not None:
        payload["defaultQualityProject"] = validated.default_quality_project
    if validated.default_unique_tickets is not None:
        payload["defaultUniqueTickets"] = validated.default_unique_tickets

    for field in validated.clear_fields or []:
        payload[field] = None

    return payload


async def save_jira_configuration(
    ctx: Context,
    jira_id: int | None = None,
    name: str | None = None,
    enabled: bool | None = None,
    base_url: str | None = None,
    resolved_statuses: list[str] | None = None,
    resolved_statuses_enabled: bool | None = None,
    username: str | None = None,
    password: str | None = None,
    headers: dict[str, str] | None = None,
    issue_types: list[str] | None = None,
    labels: list[str] | None = None,
    components: list[dict[str, Any]] | None = None,
    jira_project_ids: list[str] | None = None,
    custom_fields: dict[str, dict[str, Any]] | None = None,
    default_licensing_project: str | None = None,
    default_security_project: str | None = None,
    default_quality_project: str | None = None,
    default_unique_tickets: bool | None = None,
    clear_fields: list[JiraClearableField] | None = None,
) -> dict[str, Any]:
    """
    Create a Jira site configuration, or update an existing one.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true. Requires a premium FOSSA
    subscription.

    Omit `jira_id` to create; supply it to update, in which case only the fields
    you name change. Fields FOSSA allows to be null are cleared through
    `clear_fields`, because a flat signature cannot distinguish "leave this
    alone" from "set this to null".

    CREDENTIALS: `username`/`password` and `headers` are sent to FOSSA and
    stored there so it can authenticate to your Jira. They travel through this
    tool call, which means they land in the transcript of whatever client made
    it — prefer configuring credentials in the FOSSA web app and using this tool
    for everything else. Nothing is echoed back: the response reports only
    whether each credential field is set.
    """
    validated = JiraConfigurationSaveInput(
        jira_id=jira_id,
        name=name,
        enabled=enabled,
        base_url=base_url,
        resolved_statuses=resolved_statuses,
        resolved_statuses_enabled=resolved_statuses_enabled,
        username=username,
        password=password,
        headers=headers,
        issue_types=issue_types,
        labels=labels,
        components=_jira_components(components),
        jira_project_ids=jira_project_ids,
        custom_fields=_jira_custom_fields(custom_fields),
        default_licensing_project=default_licensing_project,
        default_security_project=default_security_project,
        default_quality_project=default_quality_project,
        default_unique_tickets=default_unique_tickets,
        clear_fields=clear_fields,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_save_jira_configuration")

    payload = _jira_payload(validated)

    if validated.jira_id is None:
        endpoint = "POST /jira"
        result = await client.request_json_optional("POST", "/jira", json_body=payload)
    else:
        endpoint = "PATCH /jira/{id}"
        # A successful patch answers 204 with no body.
        result = await client.request_json_optional(
            "PATCH", f"/jira/{validated.jira_id}", json_body=payload
        )

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {
            "jira_id": validated.jira_id,
            "applied": _redact_jira_configuration(payload),
            "configuration": _redact_jira_configuration(result),
        },
    }


async def delete_jira_configuration(ctx: Context, jira_id: int) -> dict[str, Any]:
    """
    Delete a Jira site configuration.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    The stored credentials for the site go with it, and issues already exported
    to Jira stop being tracked back to FOSSA. List the sites first — the id is
    not the Jira site name.
    """
    validated = JiraConfigurationDeleteInput(jira_id=jira_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_jira_configuration")

    result = await client.request_json_optional("DELETE", f"/jira/{validated.jira_id}")

    # FOSSA answers 200 with `{"id": ..., "deleted": false}` when the delete did
    # not happen, so report its own verdict rather than assuming success.
    deleted = result.get("deleted") if isinstance(result, dict) else None

    return {
        "ok": True,
        "endpoint": "DELETE /jira/{id}",
        "data": {"jira_id": validated.jira_id, "deleted": deleted, "response": result},
    }


# --- fossabot ----------------------------------------------------------------


async def get_fossabot_status(
    ctx: Context,
    project_locator: str | None = None,
) -> dict[str, Any]:
    """
    Report whether fossabot is connected to this organization and how many
    analysis credits are left.

    Read-only. Pass `project_locator` to check the connection for one project's
    repository rather than the organization as a whole.
    """
    validated = FossabotStatusInput(project_locator=project_locator)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = []
    if validated.project_locator is not None:
        params.append(("projectLocator", validated.project_locator))

    result = await client.request_json("GET", "/fossabot/status", params=params or None)

    return {"ok": True, "endpoint": "GET /fossabot/status", "data": result}


async def list_fossabot_upgrade_prs(
    ctx: Context,
    project_locator: str,
    first: int | None = None,
    after: str | None = None,
    last: int | None = None,
    before: str | None = None,
    state: FossabotPRState | None = None,
    search: str | None = None,
    sort: FossabotPRSort | None = None,
    include_counts: bool = False,
) -> dict[str, Any]:
    """
    List the dependency-upgrade pull requests fossabot has opened against a
    project's repository.

    Read-only. Cursor-paginated: `first` (with `after`) walks forward and `last`
    (with `before`) walks backward; the two directions cannot be mixed. Cursors
    come from `pageInfo` on a previous slice. Set `include_counts=True` to also
    fetch the PR counts by state and analysis verdict.

    A project that is not a fossabot-connected GitHub repository reads as an
    empty result rather than an error.
    """
    validated = FossabotUpgradePRListInput(
        project_locator=project_locator,
        first=first,
        after=after,
        last=last,
        before=before,
        state=state,
        search=search,
        sort=sort,
        include_counts=include_counts,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = [("projectLocator", validated.project_locator)]
    if validated.first is not None:
        params.append(("first", str(validated.first)))
    if validated.after is not None:
        params.append(("after", validated.after))
    if validated.last is not None:
        params.append(("last", str(validated.last)))
    if validated.before is not None:
        params.append(("before", validated.before))
    if validated.state is not None:
        params.append(("state", validated.state))
    if validated.search is not None:
        params.append(("search", validated.search))
    if validated.sort is not None:
        params.append(("sort", validated.sort))

    result = await client.request_json("GET", "/fossabot/dependency-upgrade-prs", params=params)

    endpoint = "GET /fossabot/dependency-upgrade-prs"
    data: dict[str, Any] = {"prs": result}

    if validated.include_counts:
        counts = await client.request_json(
            "GET",
            "/fossabot/dependency-upgrade-prs/counts",
            params=[("projectLocator", validated.project_locator)],
        )
        data["counts"] = counts
        endpoint = f"{endpoint}, GET /fossabot/dependency-upgrade-prs/counts"

    return {"ok": True, "endpoint": endpoint, "data": data}


async def get_fossabot_upgrade_pr(
    ctx: Context,
    issue_id: int,
    project_locator: str | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """
    Show the state of the fossabot dependency-upgrade PR for one issue:
    creation progress, analysis progress, and the PR link once it exists.

    Read-only. `project_locator` is only needed when the issue affects more than
    one project. Pass the `job_id` returned by a create call to see why that
    specific attempt failed — a failed creation job is only reportable by its
    id.
    """
    validated = FossabotIssuePRInput(
        issue_id=issue_id, project_locator=project_locator, job_id=job_id
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    params: list[tuple[str, str]] = []
    if validated.project_locator is not None:
        params.append(("projectLocator", validated.project_locator))
    if validated.job_id is not None:
        params.append(("jobId", validated.job_id))

    result = await client.request_json(
        "GET",
        f"/fossabot/issues/{validated.issue_id}/dependency-upgrade-pr",
        params=params or None,
    )

    return {
        "ok": True,
        "endpoint": "GET /fossabot/issues/{issueId}/dependency-upgrade-pr",
        "data": result,
    }


async def request_fossabot_upgrade_pr(
    ctx: Context,
    issue_id: int,
    project_locator: str | None = None,
    fix: FossabotFix | None = None,
    retry_analysis: bool = False,
) -> dict[str, Any]:
    """
    Ask fossabot to open a dependency-upgrade pull request for an issue, or to
    re-run the analysis on the PR it already opened.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This opens a real pull request on the connected repository. It is
    asynchronous — the response is usually `creating`, and
    fossa_get_fossabot_upgrade_pr with the returned `jobId` tracks it. Asking
    again while a PR is in flight returns the existing state rather than opening
    a second one.

    `fix` chooses the remediation target: `complete` (FOSSA's default) upgrades
    far enough to clear the issue, `partial` upgrades as far as the dependency
    graph allows. Set `retry_analysis=True` for the "analysis delayed" retry
    instead; that re-runs analysis on the existing PR and consumes fossabot
    credits.
    """
    validated = FossabotUpgradePRRequestInput(
        issue_id=issue_id,
        project_locator=project_locator,
        fix=fix,
        retry_analysis=retry_analysis,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_request_fossabot_upgrade_pr")

    payload: dict[str, Any] = {}
    if validated.project_locator is not None:
        payload["projectLocator"] = validated.project_locator

    base = f"/fossabot/issues/{validated.issue_id}/dependency-upgrade-pr"
    if validated.retry_analysis:
        path = f"{base}/retry"
        endpoint = "POST /fossabot/issues/{issueId}/dependency-upgrade-pr/retry"
    else:
        path = base
        endpoint = "POST /fossabot/issues/{issueId}/dependency-upgrade-pr"
        if validated.fix is not None:
            payload["fix"] = validated.fix

    result = await client.request_json("POST", path, json_body=payload)

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {"issue_id": validated.issue_id, "applied": payload, "pr": result},
    }


# --- report options ----------------------------------------------------------


async def list_report_options(ctx: Context) -> dict[str, Any]:
    """
    List the saved report option presets for this organization.

    Read-only. A report option is a named bundle of attribution-report switches
    — which sections to include, which dependency fields to show — that FOSSA
    reuses when generating reports.
    """
    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    result = await client.request_json("GET", "/report-options")

    return {"ok": True, "endpoint": "GET /report-options", "data": result}


def _report_option_options(validated: ReportOptionSaveInput) -> dict[str, Any]:
    """Expand the tool's on-lists into FOSSA's nested boolean object.

    Only groups the caller supplied appear. `PUT /report-options/{id}` deep
    merges, so an omitted group is left as it was, while a supplied group is
    sent in full — every switch in it, on or off.
    """
    options: dict[str, Any] = {}

    if validated.sections is not None:
        enabled = set(validated.sections)
        options["sections"] = {name: name in enabled for name in REPORT_OPTION_SECTIONS}
    if validated.use_hash_and_version_data is not None:
        options["toggles"] = {"useHashAndVersionData": validated.use_hash_and_version_data}
    if validated.exclude_package_labels is not None:
        options["excludeFields"] = {"packageLabels": validated.exclude_package_labels}
    if validated.dependency_data is not None:
        enabled_fields = set(validated.dependency_data)
        options["dependencyData"] = {
            name: name in enabled_fields for name in REPORT_OPTION_DEPENDENCY_FIELDS
        }

    return options


async def save_report_option(
    ctx: Context,
    report_option_id: int | None = None,
    name: str | None = None,
    sections: list[ReportOptionSection] | None = None,
    dependency_data: list[ReportOptionDependencyField] | None = None,
    use_hash_and_version_data: bool | None = None,
    exclude_package_labels: list[int] | None = None,
) -> dict[str, Any]:
    """
    Create a saved report option preset, or update an existing one.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    `sections` and `dependency_data` name the switches that should be ON; every
    other switch in that group is sent as OFF. Pass an empty list to turn a
    whole group off. A group you omit entirely is not sent at all, which on an
    update leaves it as it was — FOSSA deep merges. Creating requires all four
    groups plus a name.

    This changes a preset, not a report. Reports already generated are
    untouched.
    """
    validated = ReportOptionSaveInput(
        report_option_id=report_option_id,
        name=name,
        sections=sections,
        dependency_data=dependency_data,
        use_hash_and_version_data=use_hash_and_version_data,
        exclude_package_labels=exclude_package_labels,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_save_report_option")

    payload: dict[str, Any] = {}
    if validated.name is not None:
        payload["name"] = validated.name
    options = _report_option_options(validated)
    if options:
        payload["options"] = options

    if validated.report_option_id is None:
        endpoint = "POST /report-options"
        result = await client.request_json("POST", "/report-options", json_body=payload)
    else:
        endpoint = "PUT /report-options/{id}"
        result = await client.request_json(
            "PUT", f"/report-options/{validated.report_option_id}", json_body=payload
        )

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {
            "report_option_id": validated.report_option_id,
            "applied": payload,
            "report_option": result,
        },
    }


async def delete_report_option(ctx: Context, report_option_id: int) -> dict[str, Any]:
    """
    Delete a saved report option preset.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    The preset is gone for the whole organization, not just the caller. Reports
    already generated from it are unaffected.
    """
    validated = ReportOptionDeleteInput(report_option_id=report_option_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_report_option")

    # 204 with no body.
    result = await client.request_json_optional(
        "DELETE", f"/report-options/{validated.report_option_id}"
    )

    return {
        "ok": True,
        "endpoint": "DELETE /report-options/{id}",
        "data": {"report_option_id": validated.report_option_id, "response": result},
    }


# --- custom risk scores ------------------------------------------------------


def _risk_score_scope_params(scope_type: RiskScoreScope, scope_id: str) -> list[tuple[str, str]]:
    """Serialize the scope every custom risk score operation is qualified by."""
    return [("scope[type]", scope_type), ("scope[id]", scope_id)]


async def set_custom_risk_score(
    ctx: Context,
    action: RiskScoreAction,
    issue_id: int,
    scope_type: RiskScoreScope,
    scope_id: str,
    score: int,
    reason: str | None = None,
) -> dict[str, Any]:
    """
    Set FOSSA's own custom risk score (0-100) on a vulnerability issue, within
    one project or release group.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    This overrides how FOSSA ranks the issue for everyone in the organization
    who looks at that scope. It is FOSSA's stored `customRiskScore` field, which
    is null on every issue until something sets it — unrelated to any risk score
    this server or its skills compute locally.

    `action` must be stated: FOSSA publishes no endpoint that reads a custom
    risk score back, so the tool cannot tell whether one already exists.
    `create` on an issue that already has one, or `update` on an issue that does
    not, is an error from FOSSA. `scope_id` is a project locator when
    `scope_type` is `project`, and a release group id when it is
    `release_group`.
    """
    validated = CustomRiskScoreSaveInput(
        action=action,
        issue_id=issue_id,
        scope_type=scope_type,
        scope_id=scope_id,
        score=score,
        reason=reason,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_set_custom_risk_score")

    params = _risk_score_scope_params(validated.scope_type, validated.scope_id)
    payload: dict[str, Any] = {"score": validated.score}
    if validated.reason is not None:
        payload["reason"] = validated.reason

    method = "POST" if validated.action == "create" else "PATCH"
    result = await client.request_json(
        method,
        f"/custom-risk-scores/{validated.issue_id}",
        params=params,
        json_body=payload,
    )

    return {
        "ok": True,
        "endpoint": f"{method} /custom-risk-scores/{{issueId}}",
        "data": {
            "issue_id": validated.issue_id,
            "scope": {"type": validated.scope_type, "id": validated.scope_id},
            "applied": payload,
            "custom_risk_score": result,
        },
    }


async def delete_custom_risk_score(
    ctx: Context,
    issue_id: int,
    scope_type: RiskScoreScope,
    scope_id: str,
) -> dict[str, Any]:
    """
    Remove the custom risk score from a vulnerability issue in one scope, so
    FOSSA ranks it by its standard severity again.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    The score and its stated reason are both gone; there is no read endpoint to
    recover them from afterwards.
    """
    validated = CustomRiskScoreDeleteInput(
        issue_id=issue_id, scope_type=scope_type, scope_id=scope_id
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_delete_custom_risk_score")

    params = _risk_score_scope_params(validated.scope_type, validated.scope_id)
    # 204 with no body.
    result = await client.request_json_optional(
        "DELETE", f"/custom-risk-scores/{validated.issue_id}", params=params
    )

    return {
        "ok": True,
        "endpoint": "DELETE /custom-risk-scores/{issueId}",
        "data": {
            "issue_id": validated.issue_id,
            "scope": {"type": validated.scope_type, "id": validated.scope_id},
            "response": result,
        },
    }


# --- snippets ----------------------------------------------------------------

# Which view maps to which path suffix. `count` has no comparison form: FOSSA
# publishes no compare/count endpoint, and the model refuses that combination.
_SNIPPET_VIEW_SUFFIX: dict[SnippetView, str] = {
    "snippets": "",
    "packages": "/packages",
    "paths": "/paths",
    "count": "/count",
}

# Only the paginated views accept sort and paging; `paths` and `count` do not.
_SNIPPET_PAGINATED_VIEWS = ("snippets", "packages")


def _snippet_filter_params(filters: SnippetFilters) -> list[tuple[str, str]]:
    """Serialize the shared snippet filters as query pairs.

    None of these keys carry the `[]` suffix. Where FOSSA wants the bracketed
    `qs` form the vendored spec names the parameter with the brackets in it;
    these are named plainly, so they repeat plainly.
    """
    params: list[tuple[str, str]] = []
    if filters.path is not None:
        params.append(("path", filters.path))
    for snippet_id in filters.snippet_ids or []:
        params.append(("ids", snippet_id))
    for package_id in filters.package_ids or []:
        params.append(("packageIds", package_id))
    if filters.search is not None:
        params.append(("search", filters.search))
    for status in filters.rejection_status or []:
        params.append(("rejectionStatus", status))
    for label in filters.package_labels or []:
        params.append(("packageLabels", label))
    for match in filters.vendored_match or []:
        params.append(("vendoredMatch", match))
    return params


async def list_snippets(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    view: SnippetView = "snippets",
    path: str | None = None,
    compare_to_revision: str | None = None,
    change_status: SnippetChangeStatus | None = None,
    snippet_ids: list[str] | None = None,
    package_ids: list[str] | None = None,
    search: str | None = None,
    rejection_status: list[SnippetRejectionStatus] | None = None,
    package_labels: list[str] | None = None,
    vendored_match: list[SnippetVendoredMatch] | None = None,
    sort: SnippetSort | None = None,
    page: int = 1,
    page_size: int = 10,
) -> dict[str, Any]:
    """
    List the code snippets FOSSA matched in a revision, or roll them up by
    package or by path.

    Read-only. `view` picks the shape: `snippets` is one row per matched
    snippet, `packages` groups them by upstream package, `paths` is the file
    tree with a match count per node, and `count` is just the total. Every view
    except `paths` requires `path` ("/" for the whole tree).

    Set `compare_to_revision` together with `change_status` to diff two
    revisions of the same project and see only the snippets that are `new`,
    `removed`, or `unchanged`. The comparison has no `count` view.

    `vendored_match` filters on whether a snippet is already vendored or has
    been converted to a vendored dependency; `exVendored` and `exConverted`
    exclude rather than include.
    """
    validated = SnippetListInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        view=view,
        path=path,
        compare_to_revision=compare_to_revision,
        change_status=change_status,
        snippet_ids=snippet_ids,
        package_ids=package_ids,
        search=search,
        rejection_status=rejection_status,
        package_labels=package_labels,
        vendored_match=vendored_match,
        sort=sort,
        page=page,
        page_size=page_size,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]

    _, encoded_locator = _revision_path_locator(
        validated.project_locator, validated.revision_locator
    )
    suffix = _SNIPPET_VIEW_SUFFIX[validated.view]

    if validated.compare_to_revision is None:
        request_path = f"/revisions/{encoded_locator}/snippets{suffix}"
        endpoint = f"GET /revisions/{{locator}}/snippets{suffix}"
    else:
        _, encoded_older = _revision_path_locator(
            validated.project_locator, validated.compare_to_revision
        )
        request_path = (
            f"/revisions/{encoded_locator}/snippets/compare/"
            f"{encoded_older}/{validated.change_status}{suffix}"
        )
        endpoint = (
            "GET /revisions/{locator}/snippets/compare/"
            f"{{olderRevisionLocator}}/{{status}}{suffix}"
        )

    params = _snippet_filter_params(validated)
    if validated.view in _SNIPPET_PAGINATED_VIEWS:
        if validated.sort is not None:
            params.append(("sort", validated.sort))
        params.append(("page", str(validated.page)))
        params.append(("pageSize", str(validated.page_size)))

    result = await client.request_json("GET", request_path, params=params)

    return {
        "ok": True,
        "endpoint": endpoint,
        "data": {"view": validated.view, "results": result},
    }


async def get_snippet(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    snippet_id: str,
    path: str | None = None,
    include_match_details: bool = False,
) -> dict[str, Any]:
    """
    Show one matched snippet: the upstream package it came from, its licenses,
    its issue counts, and every file path it was matched in.

    Read-only. Pass `path` to hydrate the match details for that file. Set
    `include_match_details=True` (which needs `path`) to also fetch the matched
    source lines themselves — the reference text and the detected text.

    Match details are capped at FOSSA_REPORT_MAX_CHARS. When the cap bites,
    `match_details` is returned as truncated JSON text rather than an object,
    with `truncated` set.
    """
    validated = SnippetReadInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        snippet_id=snippet_id,
        path=path,
        include_match_details=include_match_details,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    _, encoded_locator = _revision_path_locator(
        validated.project_locator, validated.revision_locator
    )
    encoded_snippet = quote(validated.snippet_id, safe="")

    params: list[tuple[str, str]] = []
    if validated.path is not None:
        params.append(("path", validated.path))

    snippet = await client.request_json(
        "GET",
        f"/revisions/{encoded_locator}/snippets/{encoded_snippet}",
        params=params or None,
    )

    endpoint = "GET /revisions/{locator}/snippets/{snippetId}"
    data: dict[str, Any] = {"snippet": snippet}

    if validated.include_match_details and validated.path is not None:
        encoded_path = quote(validated.path, safe="")
        match_details = await client.request_json(
            "GET",
            f"/revisions/{encoded_locator}/snippets/{encoded_snippet}/matches/{encoded_path}",
        )
        endpoint = f"{endpoint}, GET /revisions/{{locator}}/snippets/{{snippetId}}/matches/{{path}}"

        # Matched source lines are the one unbounded payload in this domain.
        serialized = json.dumps(match_details)
        limit = settings.fossa_report_max_chars
        if len(serialized) > limit:
            data["match_details"] = serialized[:limit]
            data["truncated"] = True
            data["original_char_count"] = len(serialized)
        else:
            data["match_details"] = match_details
            data["truncated"] = False

    return {"ok": True, "endpoint": endpoint, "data": data}


async def set_snippet_rejection(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    rejected: bool,
    path: str,
    snippet_ids: list[str] | None = None,
    package_ids: list[str] | None = None,
    search: str | None = None,
    rejection_status: list[SnippetRejectionStatus] | None = None,
    package_labels: list[str] | None = None,
    vendored_match: list[SnippetVendoredMatch] | None = None,
) -> dict[str, Any]:
    """
    Reject snippet matches so FOSSA stops counting them, or unreject ones that
    were rejected before.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true, and additionally
    FOSSA_ALLOW_DESTRUCTIVE=true unless `snippet_ids` or `package_ids` names the
    snippets explicitly.

    Rejecting is how a false-positive snippet match is dismissed, and it
    suppresses the licensing issues that match raised. FOSSA takes a filter, not
    a list: `path="/"` with nothing else rejects every snippet match in the
    revision, which is why an unnarrowed call needs the destructive tier. Naming
    ids keeps the target set visible and stays at the write tier.

    Set `rejected=False` to reverse a rejection; the same filter rules apply.
    """
    validated = SnippetRejectionInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        rejected=rejected,
        path=path,
        snippet_ids=snippet_ids,
        package_ids=package_ids,
        search=search,
        rejection_status=rejection_status,
        package_labels=package_labels,
        vendored_match=vendored_match,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    tier = WriteTier.WRITE if validated.names_an_explicit_target_set else WriteTier.DESTRUCTIVE
    require_tier(settings, tier, "fossa_set_snippet_rejection")

    _, encoded_locator = _revision_path_locator(
        validated.project_locator, validated.revision_locator
    )
    action = "reject" if validated.rejected else "unreject"

    payload: dict[str, Any] = {"path": validated.path}
    if validated.snippet_ids is not None:
        payload["ids"] = validated.snippet_ids
    if validated.package_ids is not None:
        payload["packageIds"] = validated.package_ids
    if validated.search is not None:
        payload["search"] = validated.search
    if validated.rejection_status is not None:
        payload["rejectionStatus"] = list(validated.rejection_status)
    if validated.package_labels is not None:
        payload["packageLabels"] = validated.package_labels
    if validated.vendored_match is not None:
        payload["vendoredMatch"] = list(validated.vendored_match)

    # 204 with no body.
    result = await client.request_json_optional(
        "POST",
        f"/revisions/{encoded_locator}/snippets/{action}",
        json_body=payload,
    )

    return {
        "ok": True,
        "endpoint": f"POST /revisions/{{locator}}/snippets/{action}",
        "data": {
            "rejected": validated.rejected,
            "tier": tier.value,
            "applied": payload,
            "response": result,
        },
    }
