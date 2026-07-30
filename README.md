# FOSSA MCP Server
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp?ref=badge_shield)


A Model Context Protocol server for the FOSSA API that allows AI assistants to inspect FOSSA organizations and answer practical software composition analysis questions.

This version is read-only and does not modify FOSSA state.

## Safety Statement

This version is read-only and does not modify FOSSA state.

## Requirements

- Python 3.11+
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
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdarthzen%2Ffossa-mcp?ref=badge_large)