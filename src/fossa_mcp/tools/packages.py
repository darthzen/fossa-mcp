"""Package block/unblock tools for the FOSSA MCP server.

These two tools sit on endpoints FOSSA does not document. They were captured
from the FOSSA web app's own traffic and verified against the live API. FOSSA
owes no stability on them: the contract tests in this repo pin *our* request
shape and cannot detect FOSSA changing its side, so both tools fail loudly
rather than degrade quietly when a response stops matching.

The request schemas below are the verified ones, so this docstring is the
contract. The capture notes behind them — the reasoning, and what was tried and
rejected on the way — are kept outside this repository.

What the API actually does, and why the two tools are not mirror images:

* **Block is package-scoped and additive.** `POST /packages/{locator}/rules`
  attaches a `blacklisted_dependency` rule to each named policy. Re-posting an
  identical block reuses the same rule id rather than duplicating it, so the
  operation is idempotent.
* **Unblock is policy-scoped and replaces the policy's entire rule set.**
  There is no delete for a single rule — `DELETE /packages/{locator}/rules` is
  a 404. `PUT /policies/{policyId}/rules` takes a bare top-level array of the
  rules that should survive, which is the policy editor's Save. Removing one
  block therefore means read-modify-write over every rule the policy has.

That last point is the design constraint of this module. FOSSA offers no ETag,
`If-Match`, or version precondition — `rulesHash` is returned but not accepted —
so two callers unblocking different packages at the same time silently clobber
each other, and the last writer reinstates whatever the other removed. Unblock
consequently reads the policy immediately before writing, reports the rule set
it is about to send, and is gated at the `DESTRUCTIVE` tier rather than `WRITE`.

Blocking lives on **quality** policies, not security policies. A block rule
cannot attach to a licensing, security, or SBOM policy at all. DECISIONS.md §5's
original claim that FOSSA has no per-package block primitive is wrong — see the
correction recorded there — and the security policy tools in `policies.py` are
not the blocking mechanism.
"""

from typing import Any
from urllib.parse import quote

from mcp.server.fastmcp import Context

from ..client import FossaClient
from ..config import Settings
from ..errors import FossaApiError
from ..models import PackageBlockInput, PackageUnblockInput
from ..writes import WriteTier, require_tier

# The rule type FOSSA creates for a blocked package. Every other rule type on a
# quality policy (outdated_dependency, risk_abandonware, …) is unrelated and
# must survive an unblock untouched.
BLOCK_RULE_TYPE = "blacklisted_dependency"


def _rule_summary(rule: dict[str, Any]) -> dict[str, Any]:
    """Condense one FOSSA rule to the fields that identify it.

    Rule objects are wide and a licensing policy can carry over a thousand of
    them, so the full objects are sent to FOSSA but only this summary is
    returned to the caller.
    """
    return {
        "rule_id": rule.get("ruleId"),
        "type": rule.get("type"),
        "package_locator": rule.get("packageProjectLocator"),
        "version_type": rule.get("dependencyFilterVersionType"),
        "enabled": rule.get("enabled"),
    }


def _policy_rules(policy: Any, path: str) -> list[dict[str, Any]]:
    """Extract the rule array from a policy body, or fail loudly.

    A silent `[]` here would send an empty rule set to `PUT /rules` and wipe
    every rule the policy has, so an unrecognized shape must raise instead.
    """
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise FossaApiError(
            status_code=200,
            message=(
                "FOSSA returned a policy without a 'rules' array. This endpoint is undocumented "
                "and may have changed; refusing to rewrite the policy's rules from a response "
                "that is not understood."
            ),
            method="GET",
            path=path,
            error_name="UnexpectedResponse",
        )

    rules = policy["rules"]
    if any(not isinstance(rule, dict) for rule in rules):
        raise FossaApiError(
            status_code=200,
            message="FOSSA returned a policy whose 'rules' array contains a non-object entry.",
            method="GET",
            path=path,
            error_name="UnexpectedResponse",
        )
    return rules


async def block_package(
    ctx: Context,
    package_locator: str,
    policy_ids: list[int],
    versions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Block a package by adding a blocked-dependency rule to one or more FOSSA
    quality policies.

    WRITES TO FOSSA. Requires FOSSA_ALLOW_WRITES=true.

    `package_locator` is the versionless locator, e.g. `pip+aiofile` or
    `npm+left-pad`. Omit `versions` to block every version; pass
    `versions=["3.11.1"]` to block only those. `policy_ids` are the numeric ids
    of QUALITY policies — a block rule cannot attach to a licensing, security,
    or SBOM policy. Use fossa_unblock_package to reverse it.

    Idempotent: re-blocking the same package on the same policy reuses the
    existing rule instead of adding a second one.

    This uses an endpoint FOSSA does not document, captured from its web app.
    It may change without notice.
    """
    validated = PackageBlockInput(
        package_locator=package_locator,
        policy_ids=policy_ids,
        versions=versions,
    )

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.WRITE, "fossa_block_package")

    # "ALL" is FOSSA's own spelling for every version. An empty array is also
    # accepted by the API and means the same thing, but the input model rejects
    # it so that "every version" is always an explicit choice.
    payload: dict[str, Any] = {
        "policyIds": validated.policy_ids,
        "versions": validated.versions if validated.versions is not None else "ALL",
    }

    encoded_locator = quote(validated.package_locator, safe="")
    result = await client.request_json(
        "POST", f"/packages/{encoded_locator}/rules", json_body=payload
    )

    return {
        "ok": True,
        "endpoint": "POST /packages/{locator}/rules",
        "data": {
            "package_locator": validated.package_locator,
            "policy_ids": validated.policy_ids,
            "versions": payload["versions"],
            "request_body": payload,
            "policy_versions": result,
        },
    }


async def unblock_package(
    ctx: Context,
    package_locator: str,
    policy_id: int,
) -> dict[str, Any]:
    """
    Remove a package's blocked-dependency rule from one FOSSA quality policy.

    WRITES TO FOSSA, DESTRUCTIVELY. Requires FOSSA_ALLOW_WRITES=true and
    FOSSA_ALLOW_DESTRUCTIVE=true.

    FOSSA has no delete for a single rule. Unblocking rewrites the policy's
    entire rule set with the rules that should survive, and the API offers no
    precondition to make that safe — a second caller editing the same policy
    concurrently will silently undo this change, or have theirs undone. The
    surviving rules this tool is about to send are reported in
    `data.rules_sent`.

    Every rule that is not a block on `package_locator` is preserved. If the
    policy carries no such block, nothing is sent and the policy is left alone.

    This uses an endpoint FOSSA does not document, captured from its web app.
    It may change without notice.
    """
    validated = PackageUnblockInput(package_locator=package_locator, policy_id=policy_id)

    lifespan_ctx = ctx.request_context.lifespan_context
    client: FossaClient = lifespan_ctx["client"]
    settings: Settings = lifespan_ctx["settings"]

    require_tier(settings, WriteTier.DESTRUCTIVE, "fossa_unblock_package")

    # Read immediately before the write. The window between this GET and the PUT
    # is the whole of the concurrency risk, so nothing goes between them.
    policy_path = f"/policies/{validated.policy_id}"
    policy = await client.request_json("GET", policy_path)
    rules = _policy_rules(policy, policy_path)

    removed: list[dict[str, Any]] = []
    survivors: list[dict[str, Any]] = []
    for rule in rules:
        is_block = (
            rule.get("type") == BLOCK_RULE_TYPE
            and rule.get("packageProjectLocator") == validated.package_locator
        )
        (removed if is_block else survivors).append(rule)

    if not removed:
        blocked = sorted(
            str(rule.get("packageProjectLocator"))
            for rule in rules
            if rule.get("type") == BLOCK_RULE_TYPE
        )
        return {
            "ok": True,
            "endpoint": "GET /policies/{policyId}",
            "message": (
                f"Policy {validated.policy_id} has no block rule for "
                f"{validated.package_locator}; nothing was changed."
            ),
            "data": {
                "package_locator": validated.package_locator,
                "policy_id": validated.policy_id,
                "removed": [],
                "packages_blocked_by_this_policy": blocked,
            },
        }

    # The surviving rules go back exactly as FOSSA returned them, join object,
    # timestamps, and null fields included. The UI's own Save does the same, and
    # a trimmed rule object is not known to round-trip.
    result = await client.request_json("PUT", f"{policy_path}/rules", json_body=survivors)

    return {
        "ok": True,
        "endpoint": "PUT /policies/{policyId}/rules",
        "data": {
            "package_locator": validated.package_locator,
            "policy_id": validated.policy_id,
            "removed": [_rule_summary(rule) for rule in removed],
            "rules_sent_count": len(survivors),
            "rules_sent": [_rule_summary(rule) for rule in survivors],
            "policy_versions": result,
        },
    }
