# FOSSA MCP Server
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp?ref=badge_shield)


A Model Context Protocol server for the FOSSA API that allows AI assistants to inspect FOSSA organizations and answer practical software composition analysis questions.

> **Unofficial project.** Not affiliated with, endorsed by, or supported by FOSSA, Inc. "FOSSA" is a
> trademark of FOSSA, Inc., used here only to identify the API this software interoperates with. For
> the official product and support, see [fossa.com](https://fossa.com).

## Safety Statement

**Almost every tool is read-only. Four are not.**

`fossa_enable_security_policy` and `fossa_assign_security_policy_to_projects` change which FOSSA
security policy governs a project and whether it blocks builds. `fossa_block_package` and
`fossa_unblock_package` add and remove blocked-dependency rules on a quality policy. Every other
tool only reads.

Writes are **off by default**. Every write tool refuses before issuing any request unless the
operator sets `FOSSA_ALLOW_WRITES=true`, and `fossa_unblock_package` additionally requires
`FOSSA_ALLOW_DESTRUCTIVE=true`. Leave them off on any instance that does not need to change FOSSA
state — under the single-tenant model below, everyone who reaches this server shares one token and
therefore its write access too.

See [DECISIONS.md](DECISIONS.md) §5 for why the earlier read-only guarantee was dropped, and
[Write operations](#write-operations) for what each tier permits.

## Deployment model — single-tenant

**This server is designed to be run by one operator with one FOSSA API token.** You run your own
instance; there is no multi-user mode.

⚠️ **The server executes every request using the single `FOSSA_API_TOKEN` it was started with.** It
does not authenticate callers or scope requests per user. If you expose the HTTP transport to other
people, every one of them gets the full access of that token — including anything it can read across
your FOSSA organization.

- `stdio` is the default transport and the intended deployment shape: your MCP client launches the
  process, and the token stays local to it.
- `streamable-http` binds `127.0.0.1` by default and is intended for local or sidecar use. Do not
  put it on a shared network interface without an authenticating proxy in front of it.

## Requirements

- Python 3.13+
- `uv`
- Full FOSSA API token for live calls
- Node/npm only when launching MCP Inspector through `mcp dev`

## Setup

```bash
git clone <repo>
cd fossa-mcp
uv sync
cp .env.example .env
```

Then edit `.env` and add your FOSSA API token:

```dotenv
FOSSA_API_TOKEN=<your-full-api-token>
```

## Validate

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

`pytest` never touches the network; the live smoke test is opt-in via `uv run pytest -m live` and
needs a real `FOSSA_API_TOKEN`.

## MCP Inspector

```bash
uv run mcp dev src/fossa_mcp/server.py
```

## stdio

```bash
uv run fossa-mcp
```

## Streamable HTTP

```bash
uv run fossa-mcp --transport streamable-http
```

## Container

```bash
docker run --rm -i -e FOSSA_API_TOKEN=<your-full-api-token> rashford/fossa-mcp:0.1
```

For `streamable-http`, publish the port and override the default `CMD`:

```bash
docker run --rm -p 8000:8000 -e FOSSA_API_TOKEN=<your-full-api-token> \
  rashford/fossa-mcp:0.1 --transport streamable-http
```

Images are tagged `:0.1.0` and `:0.1`. `:latest` is intentionally not published until a release has
soaked — see [DECISIONS.md](DECISIONS.md).

Every image ships `LICENSE`, `NOTICE`, and a consolidated `/app/THIRD_PARTY_LICENSES.txt` covering
every runtime dependency actually installed in that image, generated at build time by
`scripts/generate_third_party_licenses.py`.

## Tools

| Tool | Description |
|------|-------------|
| `fossa_list_projects` | List FOSSA projects visible to the current account |
| `fossa_get_project` | Get detailed metadata about exactly one FOSSA project |
| `fossa_list_project_revisions` | List analyzed revisions, branches, or tags for a project |
| `fossa_list_dependencies` | List dependencies detected in a specific project revision |
| `fossa_get_dependency` | Get the richer detail record for one dependency in one revision |
| `fossa_list_issues` | Query licensing, vulnerability, or quality issues globally or for one project revision |
| `fossa_get_issue` | Retrieve complete detail for one issue |
| `fossa_project_posture` | Provide one high-value, model-friendly view of a project revision's current FOSSA issue posture |
| `fossa_get_attribution_report` | Retrieve a text-friendly FOSSA attribution/SBOM report for a revision |
| `fossa_get_security_policy` | Show the security policy in force for a project: FOSSA's baseline plus the local overlay |
| `fossa_evaluate_security_policy` | Return an allow/warn/block verdict per dependency for a revision |
| `fossa_enable_security_policy` | **Writes.** Assign a security policy to a project and enable the enforcement that blocks violating packages |
| `fossa_assign_security_policy_to_projects` | **Writes.** Assign one security policy to several named projects |
| `fossa_block_package` | **Writes.** Add a blocked-dependency rule for a package to one or more quality policies |
| `fossa_unblock_package` | **Writes, destructively.** Remove a package's blocked-dependency rule from a quality policy |

## Write operations

Write access is off by default and tiered. Each tier is enabled independently, and the higher ones
do not imply the lower: `FOSSA_ALLOW_DESTRUCTIVE=true` on its own grants nothing, so a
half-configured deployment stays safe rather than becoming partly writable.

| Env var | Permits |
|---------|---------|
| `FOSSA_ALLOW_WRITES` | Create and update. Required by every write tool. |
| `FOSSA_ALLOW_DESTRUCTIVE` | Deletes, and operations whose target set is unbounded. Requires `FOSSA_ALLOW_WRITES` as well. |

| Tool | Tier | Endpoint |
|------|------|----------|
| `fossa_enable_security_policy` | write | `PUT /projects/{locator}` |
| `fossa_assign_security_policy_to_projects` | write | `PUT /v2/projects/policy` |
| `fossa_block_package` | write | `POST /packages/{locator}/rules` |
| `fossa_unblock_package` | write + destructive | `GET /policies/{id}` then `PUT /policies/{id}/rules` |

The gate is checked inside the tool body before any request is constructed, so a refused call sends
nothing to FOSSA.

```bash
FOSSA_ALLOW_WRITES=true FOSSA_ALLOW_DESTRUCTIVE=true uv run fossa-mcp
```

### Blocking a package

`fossa_block_package` takes a **versionless** locator (`pip+aiofile`, not `pip+aiofile$1.2.3`) and
one or more QUALITY policy ids — a block rule cannot attach to a licensing, security, or SBOM
policy. Omit `versions` to block every version, or pass `versions=["3.11.1"]` to block only those.
Re-blocking is idempotent: FOSSA reuses the existing rule rather than adding a second one.

`fossa_unblock_package` reverses it, and is gated at the destructive tier for a reason. FOSSA has no
delete for a single rule — the only way to remove one is `PUT /policies/{id}/rules`, which replaces
the policy's **entire** rule set, and the API offers no ETag, `If-Match`, or version precondition to
make that safe. Two callers unblocking different packages at the same time silently clobber each
other. The tool reads the policy immediately before writing and reports the surviving rule set it
sent in `data.rules_sent`. If the policy has no matching block rule it changes nothing rather than
rewriting the rule set for no reason.

> ⚠️ **Both tools use endpoints FOSSA does not document**, captured from its web app's own traffic
> and verified against the live API. FOSSA owes no stability on them: they can change without notice
> or a version bump. The contract tests in this repo pin *our* request shape and cannot detect FOSSA
> changing its side, so both tools fail loudly rather than degrade quietly if a response stops
> matching. The verified request schemas are documented in `src/fossa_mcp/tools/packages.py` and
> pinned by `tests/test_package_tools.py`.

## Security policies

An assigned **security policy** (what counts as a violation), **security issue scanning** (finding
violations), and the **security status check** (failing the build) are what make a vulnerability
fail a build. `fossa_enable_security_policy` sets all three.

That is distinct from blocking a specific package, which is a `blacklisted_dependency` rule on a
**quality** policy — see [Blocking a package](#blocking-a-package). The security policy tools do not
block packages by name.

Policies are authored in the FOSSA web app and addressed here by the numeric id in their FOSSA URL.
The vendored OpenAPI spec has no create-policy or list-policies operation, though the live API does
serve `GET /api/policies`; no tool wraps it yet.

### Local overlay

`FOSSA_POLICY_FILE` points at a JSON file of local rules layered on top of FOSSA's own findings.
The overlay is **tighten-only**: it can block packages FOSSA currently allows, and it can never
clear a package FOSSA has raised an active vulnerability against.

```json
{
  "version": 1,
  "security": [
    {
      "id": "no-high-severity",
      "description": "Stricter than the org-wide FOSSA policy",
      "enabled": true,
      "rules": {
        "max_cvss": 7.0,
        "warn_cvss": 4.0,
        "deny_severity": ["critical"],
        "denied_cves": ["CVE-2025-53365"],
        "denied_packages": ["left-pad", "npm+event-stream"]
      },
      "exceptions": [
        {
          "package": "pip+requests$2.31",
          "reason": "Vendored fork, patch applied out of band",
          "expires": "2026-12-31"
        }
      ]
    }
  ]
}
```

`denied_packages` and `exceptions[].package` accept a full locator (`pip+mcp$1.6.0`, that version
only), a fetcher-qualified name (`pip+mcp`, any version), or a bare name (`mcp`, any fetcher).

An exception requires a `reason` and suppresses only overlay-introduced blocks. Once `expires`
passes it stops applying and is reported on the verdict, so a package never silently reverts to
blocked without explanation. A configured-but-unreadable policy file is an error, not a fallback to
"no policy".

### Turning enforcement on

```bash
FOSSA_ALLOW_WRITES=true uv run fossa-mcp
```

Check what a policy would do before enabling it — `fossa_evaluate_security_policy` is read-only and
answers exactly that.

## Example Prompts

```text
List my FOSSA projects sorted by security issues, highest first.
```

```text
Show active critical and high vulnerabilities for revision <REVISION_LOCATOR>.
```

```text
Compare revision <NEW_REVISION> with <OLD_REVISION> and show only new vulnerability issues.
```

```text
Give me the FOSSA risk posture for project <PROJECT_LOCATOR> at revision <REVISION_LOCATOR>.
```

```text
Generate the Markdown attribution report for revision <REVISION_LOCATOR>.
```

```text
Which packages in <REVISION_LOCATOR> would my security policy block?
```

```text
What security policy is <PROJECT_LOCATOR> using, and is the status check on?
```

```text
Apply security policy 7 to <PROJECT_LOCATOR> and turn on blocking.
```

```text
Block pip+aiofile on quality policy <POLICY_ID>, every version.
```

```text
Unblock pip+aiofile on quality policy <POLICY_ID> and show me which rules you kept.
```

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp?ref=badge_large)

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution,
the trademark disclaimer, and third-party license information.

All runtime dependencies are under permissive licenses (MIT, BSD, Apache-2.0, ISC, PSF) with the
exception of `certifi`, which is MPL-2.0 and is redistributed unmodified.

Container images are built on SUSE Base Container Images, which carry SUSE's own license terms
separate from this project's.

Project decisions — including the deliberate `mcp` version pin and the single-tenant constraint —
are recorded in [DECISIONS.md](DECISIONS.md).

