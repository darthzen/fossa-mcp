"""Security policy tools for the FOSSA MCP server.

This module holds the only tools in the server that modify FOSSA state. They
are gated on `FOSSA_ALLOW_WRITES` and refuse before issuing a request when it
is off. See DECISIONS.md §5 for why the read-only guarantee was dropped.

What FOSSA's API actually supports, which is what shapes these tools:

* A policy is authored in the FOSSA web app. There is no create-policy endpoint
  and no list-policies endpoint in the vendored OpenAPI spec, so a policy is
  addressed here by the numeric id shown in its FOSSA URL.
* There is no per-package "block" primitive. FOSSA blocks a package by raising
  a vulnerability issue against it under an assigned security policy, and then
  failing the CI status check. `enable_security_policy` turns exactly that
  combination on; it is the block.
"""

from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..models import (
    DependencyDepth,
    PolicyEnableInput,
    PolicyEvaluateInput,
    SecurityPolicyReadInput,
)
from ..policy import (
    FossaSecurityBaseline,
    PolicyEvaluation,
    evaluate_dependencies,
    load_policy_document,
)
from ..writes import WriteTier, require_tier


async def _fetch_baseline(
    client: FossaClient, settings: Settings, project_locator: str
) -> FossaSecurityBaseline:
    """Read FOSSA's currently-configured security enforcement for one project.

    The org-level default is only fetched when `FOSSA_ORG_ID` is configured;
    without it the project's own assignment still resolves, and
    `org_default_security_policy_id` is reported as unknown rather than guessed.
    """
    encoded_locator = quote(project_locator, safe="")
    project = await client.request_json("GET", f"/projects/{encoded_locator}")
    project_data = project if isinstance(project, dict) else {}

    org_default_policy_id: int | None = None
    status_check_filter: int | None = None

    if settings.fossa_org_id is not None:
        org_settings = await client.request_json(
            "GET", f"/organizations/{settings.fossa_org_id}/settings/projects/issues/security"
        )
        if isinstance(org_settings, dict):
            org_default_policy_id = _as_int(org_settings.get("defaultSecurityPolicyId"))
            status_check_filter = _as_int(
                org_settings.get("projectDefaultStatusCheckFilterVulnerability")
            )

    return FossaSecurityBaseline(
        project_locator=project_locator,
        security_policy_id=_as_int(project_data.get("securityPolicyId")),
        org_default_security_policy_id=org_default_policy_id,
        security_issue_scanning_enabled=_as_bool(project_data.get("securityIssueScanningEnabled")),
        security_status_check_enabled=_as_bool(project_data.get("securityStatusCheckEnabled")),
        status_check_filter_vulnerability=status_check_filter,
    )


def _as_int(value: Any) -> int | None:
    """Coerce a FOSSA JSON value to `int`, or `None` if it is absent or not one."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _as_bool(value: Any) -> bool | None:
    """Coerce a FOSSA JSON value to `bool`, or `None` if it is absent or not one."""
    return value if isinstance(value, bool) else None


async def get_security_policy(
    ctx: Context,
    project_locator: str,
) -> dict[str, Any]:
    """
    Show the security policy in force for a project: what FOSSA is configured to
    enforce, plus the local overlay layered on top of it.

    Read-only. The overlay can only make enforcement stricter, never looser.
    """
    validated = SecurityPolicyReadInput(project_locator=project_locator)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    baseline = await _fetch_baseline(client, settings, validated.project_locator)
    document = load_policy_document(settings.fossa_policy_file)

    overlay: dict[str, Any] = {
        "policy_file": settings.fossa_policy_file,
        "loaded": document is not None,
        "policies": [
            policy.model_dump(mode="json") for policy in (document.security if document else [])
        ],
    }

    return {
        "ok": True,
        "endpoint": (
            "GET /projects/{locator} + GET /organizations/{id}/settings/projects/issues/security"
        ),
        "data": {
            "baseline": baseline.model_dump(mode="json"),
            "effective_fossa_policy_id": baseline.effective_policy_id,
            "overlay": overlay,
        },
    }


async def evaluate_security_policy(
    ctx: Context,
    project_locator: str,
    revision_locator: str,
    depths: list[DependencyDepth] | None = None,
    count: int = 100,
) -> PolicyEvaluation:
    """
    Evaluate every dependency in a revision against the effective security
    policy and return an allow/warn/block verdict per package.

    Read-only: this reports what the policy says, it does not apply anything to
    FOSSA. A FOSSA-raised vulnerability always blocks and cannot be cleared by a
    local exception.
    """
    validated = PolicyEvaluateInput(
        project_locator=project_locator,
        revision_locator=revision_locator,
        depths=depths,
        count=count,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    if not (1 <= validated.count <= settings.fossa_max_page_size):
        raise ValueError(f"Count must be between 1 and {settings.fossa_max_page_size}")

    # Load and validate the overlay before spending any HTTP calls, so a broken
    # policy file fails fast rather than after a page of dependencies.
    document = load_policy_document(settings.fossa_policy_file)

    baseline = await _fetch_baseline(client, settings, validated.project_locator)

    full_revision_locator = _full_revision_locator(
        validated.project_locator, validated.revision_locator
    )
    encoded_locator = quote(full_revision_locator, safe="")

    params: list[tuple[str, str]] = [("page", "1"), ("count", str(validated.count))]
    for depth in validated.depths or []:
        params.append(("depth[]", depth))

    body = await client.request_json(
        "GET", f"/v2/revisions/{encoded_locator}/dependencies", params=params
    )
    dependencies = body.get("dependencies", []) if isinstance(body, dict) else []

    return evaluate_dependencies(
        revision_locator=full_revision_locator,
        dependencies=[dep for dep in dependencies if isinstance(dep, dict)],
        baseline=baseline,
        document=document,
        today=_today(),
    )


def _today() -> date:
    """Today in UTC, for exception expiry comparisons."""
    return datetime.now(UTC).date()


def _full_revision_locator(project_locator: str, revision_locator: str) -> str:
    """Return the full `project$revision` locator the dependencies path wants."""
    prefix = f"{project_locator}$"
    if revision_locator.startswith(prefix):
        return revision_locator
    return f"{project_locator}${revision_locator}"


async def enable_security_policy(
    ctx: Context,
    project_locator: str,
    security_policy_id: int,
    enable_scanning: bool = True,
    enable_status_check: bool = True,
) -> dict[str, Any]:
    """
    Assign a FOSSA security policy to a project and turn on the enforcement that
    blocks packages violating it.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Blocking in FOSSA is the combination of an assigned security policy (which
    decides what counts as a violation), security issue scanning (which finds
    violations), and the security status check (which fails the build). This
    tool sets all three. `security_policy_id` is the numeric id from the
    policy's FOSSA URL; the API exposes no way to list policies.
    """
    validated = PolicyEnableInput(
        project_locator=project_locator,
        security_policy_id=security_policy_id,
        enable_scanning=enable_scanning,
        enable_status_check=enable_status_check,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_enable_security_policy")

    before = await _fetch_baseline(client, settings, validated.project_locator)

    payload: dict[str, Any] = {
        "securityPolicyId": validated.security_policy_id,
        "securityIssueScanningEnabled": validated.enable_scanning,
        "securityStatusCheckEnabled": validated.enable_status_check,
    }

    encoded_locator = quote(validated.project_locator, safe="")
    result = await client.request_json("PUT", f"/projects/{encoded_locator}", json_body=payload)

    after = await _fetch_baseline(client, settings, validated.project_locator)

    return {
        "ok": True,
        "endpoint": "PUT /projects/{locator}",
        "data": {
            "applied": payload,
            "before": before.model_dump(mode="json"),
            "after": after.model_dump(mode="json"),
            "project": result,
        },
    }


async def assign_security_policy_to_projects(
    ctx: Context,
    security_policy_id: int,
    project_locators: list[str],
) -> dict[str, Any]:
    """
    Assign one FOSSA security policy to several projects at once.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    Assignment only. Unlike fossa_enable_security_policy this does not touch
    scanning or the status check, because the bulk endpoint cannot set them —
    a project that has scanning switched off will take the policy and still
    block nothing.

    This tool deliberately does not expose the endpoint's "apply to all projects
    matching these filters" mode. Every target must be named explicitly.
    """
    if security_policy_id < 1:
        raise ValueError("security_policy_id must be >= 1")
    if not project_locators:
        raise ValueError("project_locators must name at least one project")
    if any(not locator.strip() for locator in project_locators):
        raise ValueError("project_locators must not contain blank entries")

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_assign_security_policy_to_projects")

    params: list[tuple[str, str]] = [("policyId", str(security_policy_id))]
    for locator in project_locators:
        params.append(("locators[]", locator))

    result = await client.request_json("PUT", "/v2/projects/policy", params=params)

    # The endpoint answers with a map of locator -> error for the ones that
    # failed, and an empty object when everything succeeded. Surface that
    # distinction rather than reporting a blanket success.
    failures = result if isinstance(result, dict) else {}

    return {
        "ok": True,
        "endpoint": "PUT /v2/projects/policy",
        "data": {
            "security_policy_id": security_policy_id,
            "requested": project_locators,
            "failures": failures,
            "succeeded": [locator for locator in project_locators if locator not in failures],
        },
    }
