# FOSSA MCP Server

A Model Context Protocol server for the FOSSA API that allows AI assistants to inspect FOSSA organizations and answer practical software composition analysis questions.

> **Unofficial project.** Not affiliated with, endorsed by, or supported by FOSSA, Inc. "FOSSA" is a
> trademark of FOSSA, Inc., used here only to identify the API this software interoperates with. For
> the official product and support, see [fossa.com](https://fossa.com).

## Safety Statement

This version is read-only and does not modify FOSSA state.

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

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attribution,
the trademark disclaimer, and third-party license information.

All runtime dependencies are under permissive licenses (MIT, BSD, Apache-2.0, ISC, PSF) with the
exception of `certifi`, which is MPL-2.0 and is redistributed unmodified.

Container images are built on SUSE Base Container Images, which carry SUSE's own license terms
separate from this project's.

Project decisions — including the deliberate `mcp` version pin and the single-tenant constraint —
are recorded in [DECISIONS.md](DECISIONS.md).