# FOSSA MCP Server — Implementation Scope and Acceptance Specification

**Status:** Implementation-ready  
**Audience:** Qwen3-Coder:30B or a human engineer  
**Language:** Python 3.11+  
**MCP SDK:** Official MCP Python SDK v2.x  
**FOSSA contract:** FOSSA public OpenAPI, version 4.34.54 observed 2026-07-29  
**Primary transport:** stdio  
**Secondary transport:** Streamable HTTP  
**Repository name:** `fossa-mcp`  
**Python package:** `fossa_mcp`

---

## 1. Objective

Implement a production-quality, **read-only** Model Context Protocol server for the FOSSA API.

The server should demonstrate:

1. Correct use of the current MCP Python SDK v2.
2. Correct use of FOSSA API authentication and endpoint semantics.
3. Correct handling of FOSSA locators containing reserved URL characters.
4. Correct handling of FOSSA's repeated, bracketed query parameters.
5. Strong typed MCP tool contracts.
6. Useful FOSSA domain workflows rather than a mechanical API mirror.
7. Safe credential and error handling.
8. Deterministic, offline automated tests.
9. A polished demonstration flow appropriate for an engineering technical screen.

The implementation must be complete enough to run against a real FOSSA organization using a Full API token, while automated tests must not require a network connection or real credentials.

---

## 2. Product Description

`fossa-mcp` allows an MCP-capable AI assistant to inspect a FOSSA organization and answer practical software-composition-analysis questions such as:

- Which projects have the most security issues?
- What is the latest analyzed revision of a project?
- Which direct dependencies have active issues?
- Which critical and high vulnerabilities affect a revision?
- What licensing or quality issues are active?
- Which issues are new or remediated between revisions?
- What is the current risk posture of a project revision?
- Can I generate a Markdown attribution report for a revision?

The v1 server **must not modify FOSSA state**.

---

## 3. Scope

### 3.1 Required MCP tools

Implement exactly these nine tools:

1. `fossa_list_projects`
2. `fossa_get_project`
3. `fossa_list_project_revisions`
4. `fossa_list_dependencies`
5. `fossa_get_dependency`
6. `fossa_list_issues`
7. `fossa_get_issue`
8. `fossa_project_posture`
9. `fossa_get_attribution_report`

### 3.2 Required infrastructure

Implement:

- stdio transport.
- Streamable HTTP transport.
- Environment-variable configuration.
- One reusable asynchronous FOSSA API client.
- Safe structured exception handling.
- stderr logging.
- Unit tests.
- Mock HTTP contract tests.
- In-memory MCP integration tests.
- Optional live smoke tests.
- A script to refresh the vendored FOSSA OpenAPI specification.
- README setup and demo documentation.

### 3.3 Explicitly out of scope

Do **not** implement:

- ignoring or unignoring issues,
- project deletion,
- project creation or updates,
- policy modification,
- label modification,
- license conclusions,
- disputes,
- Jira ticket creation,
- user/team administration,
- binary uploads,
- SBOM uploads,
- execution of the FOSSA CLI,
- OAuth/OIDC authentication,
- a web UI,
- a database,
- persistent caching,
- background workers,
- legacy SSE deployment,
- arbitrary URL fetching,
- arbitrary FOSSA endpoint proxying,
- a generic `fossa_request` tool.

Read-only behavior is an intentional product and security decision.

---

## 4. Sources of Truth

### 4.1 FOSSA OpenAPI

The canonical API contract is:

`https://app.fossa.com/api/api-docs/swagger.json`

At scope creation time:

- OpenAPI: `3.1.0`
- API title: `FOSSA API`
- API spec version: `4.34.54`
- production server: `https://app.fossa.com/api`

Vendor a copy at:

`spec/fossa-openapi.json`

Create:

`spec/README.md`

containing:

- retrieval date/time in UTC,
- OpenAPI `info.version`,
- source URL,
- SHA-256 of the vendored JSON.

**Hard implementation rule:** Never invent an endpoint, parameter, enum, or query key that does not exist in the vendored OpenAPI contract.

If this scope conflicts with the vendored OpenAPI specification, prefer the vendored specification and document the discrepancy under `README.md -> API contract notes`.

### 4.2 MCP SDK

Use the official MCP Python SDK **v2**, not v1.

Required server import style:

```python
from mcp.server import MCPServer
```

Do not use the legacy v1 `FastMCP` import path.

Use typed Python parameters/Pydantic models to generate tool schemas.

---

## 5. Dependency and Tooling Requirements

Use `uv`.

Recommended runtime dependencies:

```toml
[project]
requires-python = ">=3.11"

dependencies = [
  "mcp[cli]>=2,<3",
  "httpx>=0.28,<1",
  "pydantic>=2.11,<3",
  "pydantic-settings>=2.10,<3",
]
```

Recommended development dependencies:

```toml
[dependency-groups]
dev = [
  "pytest>=8,<9",
  "pytest-asyncio>=1,<2",
  "respx>=0.22,<1",
  "ruff>=0.12,<1",
  "pyright>=1.1,<2",
]
```

Do not use synchronous `requests`.

---

## 6. Repository Layout

Use this logical structure:

```text
fossa-mcp/
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml
├── uv.lock
├── spec/
│   ├── README.md
│   └── fossa-openapi.json
├── scripts/
│   └── update_openapi.py
├── src/
│   └── fossa_mcp/
│       ├── __init__.py
│       ├── __main__.py
│       ├── client.py
│       ├── config.py
│       ├── errors.py
│       ├── models.py
│       ├── query.py
│       ├── server.py
│       └── tools/
│           ├── __init__.py
│           ├── projects.py
│           ├── revisions.py
│           ├── dependencies.py
│           ├── issues.py
│           ├── posture.py
│           └── reports.py
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── projects.json
    │   ├── project.json
    │   ├── revisions.json
    │   ├── dependencies.json
    │   ├── dependency.json
    │   ├── vulnerability_issues.json
    │   ├── licensing_issues.json
    │   ├── quality_issues.json
    │   ├── issue.json
    │   ├── issue_categories.json
    │   └── attribution.md
    ├── test_client.py
    ├── test_query.py
    ├── test_tools_projects.py
    ├── test_tools_revisions.py
    ├── test_tools_dependencies.py
    ├── test_tools_issues.py
    ├── test_tools_posture.py
    ├── test_tools_reports.py
    ├── test_mcp_integration.py
    └── test_live.py
```

Small structural changes are acceptable if the behavior remains identical. Do not collapse the project into one file.

---

## 7. Runtime Configuration

Create a Pydantic settings class named `Settings`.

Environment variables:

| Variable | Required | Default | Validation |
|---|---:|---|---|
| `FOSSA_API_TOKEN` | For live API calls | none | secret string |
| `FOSSA_BASE_URL` | No | `https://app.fossa.com/api` | strip trailing slash |
| `FOSSA_TIMEOUT_SECONDS` | No | `20.0` | `> 0` |
| `FOSSA_VERIFY_TLS` | No | `true` | boolean |
| `FOSSA_MAX_PAGE_SIZE` | No | `100` | 1..1000 |
| `FOSSA_REPORT_MAX_CHARS` | No | `200000` | 1000..1000000 |
| `FOSSA_LOG_LEVEL` | No | `INFO` | valid Python log level |
| `FOSSA_HTTP_HOST` | No | `127.0.0.1` | string |
| `FOSSA_HTTP_PORT` | No | `8000` | 1..65535 |

`.env.example`:

```dotenv
FOSSA_API_TOKEN=
FOSSA_BASE_URL=https://app.fossa.com/api
FOSSA_TIMEOUT_SECONDS=20
FOSSA_VERIFY_TLS=true
FOSSA_MAX_PAGE_SIZE=100
FOSSA_REPORT_MAX_CHARS=200000
FOSSA_LOG_LEVEL=INFO
FOSSA_HTTP_HOST=127.0.0.1
FOSSA_HTTP_PORT=8000
```

Rules:

- Do not accept an API token as an MCP tool argument.
- Do not print the token.
- Do not include it in an exception.
- Do not include it in fixtures.
- Do not store it in MCP resources.
- Do not place a real token in README examples.
- Do not initialize a required token at module import in a way that prevents unit tests from importing the package without credentials.

---

## 8. FOSSA Authentication

Every live FOSSA request must include:

```http
Authorization: Bearer <FOSSA_API_TOKEN>
User-Agent: fossa-mcp/<package-version>
Accept: application/json
```

For text-report endpoints, `Accept` may be adjusted if necessary.

Use a **Full** FOSSA API token for read operations.

Do not use:

- Basic Auth,
- query-string tokens,
- the legacy `Authorization: token ...` format.

Production requests must use HTTPS. HTTP is only acceptable when the configured base URL is localhost for test/dev use.

---

## 9. HTTP Client

Implement:

```python
class FossaClient:
    ...
```

It owns one reusable `httpx.AsyncClient`.

Constructor:

```python
FossaClient(
    settings: Settings,
    transport: httpx.AsyncBaseTransport | None = None,
)
```

The optional transport exists to permit deterministic tests.

Required public methods:

```python
async def request_json(
    self,
    method: str,
    path: str,
    *,
    params: list[tuple[str, str]] | None = None,
) -> dict[str, Any] | list[Any]:
    ...

async def request_text(
    self,
    method: str,
    path: str,
    *,
    params: list[tuple[str, str]] | None = None,
) -> tuple[str, str | None]:
    ...

async def aclose(self) -> None:
    ...
```

### 9.1 URL construction

`FOSSA_BASE_URL` already contains `/api`.

Example:

```text
base = https://app.fossa.com/api
path = /v2/projects

result = https://app.fossa.com/api/v2/projects
```

Never create:

- `/api/api/v2/...`
- a missing `/api`,
- unintended double slashes.

### 9.2 FOSSA locator path encoding

Locators commonly contain:

- `+`
- `/`
- `$`

For **path parameters**, encode the locator exactly once:

```python
from urllib.parse import quote

encoded = quote(locator, safe="")
```

For **query parameter values**, pass the original raw locator to `httpx` via `params`. Do not pre-encode query values.

Mandatory tests must prove no double encoding such as `%252F`.

### 9.3 Repeated bracketed query parameters

FOSSA uses parameters such as:

```text
type[]=container&type[]=sbom
filter[severity][]=critical&filter[severity][]=high
refs[]=main&refs[]=develop
```

Implement in `query.py`:

```python
def add_repeated(
    params: list[tuple[str, str]],
    key: str,
    values: Sequence[str] | None,
) -> None:
    ...
```

Rules:

- Append one `(key, value)` tuple per item.
- Omit the key when values are `None` or empty.
- Never comma-join.
- Never JSON-encode a list into one query-string value.

### 9.4 Booleans

Pass booleans consistently as lowercase query strings:

```text
true
false
```

Create a helper if needed.

### 9.5 Timeouts

Use `FOSSA_TIMEOUT_SECONDS`.

Timeout error text should be model-actionable and secret-safe, e.g.:

```text
FOSSA request timed out after 20.0 seconds while calling GET /v2/projects.
```

### 9.6 HTTP response handling

- HTTP 200–299 is transport success.
- `202` returned from issue-related endpoints can mean analysis/build processing and must not automatically be treated as a failure.
- 4xx/5xx responses should attempt to parse FOSSA's documented JSON error shape.

Common FOSSA error body:

```json
{
  "uuid": "...",
  "code": 2004,
  "message": "...",
  "name": "NotFoundError",
  "httpStatusCode": 404
}
```

Do not assume every field is present.

---

## 10. Error Model

Create:

```python
class FossaError(Exception):
    pass

class FossaConfigurationError(FossaError):
    pass

class FossaApiError(FossaError):
    status_code: int
    message: str
    error_name: str | None
    fossa_code: int | None
    reference_uuid: str | None
    method: str
    path: str
```

Example safe messages:

```text
FOSSA API returned 401 Unauthorized. Check FOSSA_API_TOKEN.
```

```text
FOSSA API returned 403 Forbidden. The token does not have permission for this resource.
```

```text
FOSSA API returned 404 NotFoundError: Project not found.
```

Never include:

- Authorization headers,
- token values,
- full raw request dumps.

### MCP error behavior

For normal tool execution errors, raise a normal Python exception and allow the MCP SDK to expose an MCP tool result with `is_error=True`.

Do not return this as a successful payload:

```json
{"error": "something failed"}
```

Use protocol-level MCP errors only for non-recoverable server/protocol state, not ordinary bad API inputs.

---

## 11. Retry Policy

Retry only:

- connection errors,
- read timeouts,
- HTTP 502,
- HTTP 503,
- HTTP 504.

Maximum:

- initial attempt + 2 retries.

Backoff:

1. 0.25 seconds
2. 0.75 seconds

Do not retry:

- 400,
- 401,
- 403,
- 404,
- 409,
- 422.

Honor `Retry-After` only if its value can be interpreted safely and is <= 10 seconds.

Use `asyncio.sleep`.

---

## 12. Common MCP Tool Rules

All nine tools must:

- be `async def`,
- expose typed parameters,
- use `Literal[...]` for closed enums,
- use Pydantic/`Annotated`/`Field` bounds and descriptions,
- reject unexpected fields,
- contain tool-selection-oriented docstrings,
- be marked read-only via MCP `ToolAnnotations`,
- make network calls only through `FossaClient`,
- return JSON-serializable data,
- never mutate FOSSA state.

For larger tool inputs, define Pydantic models with:

```python
model_config = ConfigDict(extra="forbid")
```

Required input models:

- `ProjectListInput`
- `RevisionListInput`
- `DependencyListInput`
- `IssueListInput`
- `PostureInput`
- `AttributionReportInput`

Do not create rigid complete response models for FOSSA. Preserve API evolution by retaining raw response fields.

### Standard result envelope

For direct JSON-backed tools:

```python
{
    "ok": True,
    "endpoint": "GET /v2/projects",
    "data": raw_fossa_body,
}
```

Optional metadata is allowed:

```python
"meta": {
    "page": 1,
    "count": 20,
}
```

---

# 13. Tool Specifications

## 13.1 `fossa_list_projects`

### Intent

List/filter FOSSA projects visible to the current token. Use this as the primary discovery tool when the user names a project informally or wants organization-wide project inventory.

### FOSSA endpoint

```http
GET /v2/projects
```

Operation ID:

```text
getProjects
```

### Inputs

```python
title: str | None = None

types: list[
    Literal[
        "container",
        "archive",
        "provided",
        "autobuild",
        "sbom",
        "binary",
    ]
] | None = None

is_public: bool | None = None
labels: list[str] | None = None
team_ids: list[str] | None = None
latest_scan_days: int | None = None
last_revision_within_days: int | None = None
locators: list[str] | None = None
include_shared_projects: bool | None = None
only_include_shared_projects: bool | None = None

inventory: list[
    Literal["snippet", "vendored"]
] | None = None

sort: Literal[
    "title_asc",
    "title_desc",
    "issues-total_asc",
    "issues-total_desc",
    "latest-scan_asc",
    "latest-scan_desc",
    "last-analyzed_asc",
    "last-analyzed_desc",
    "issues-licensing_asc",
    "issues-licensing_desc",
    "issues-security_asc",
    "issues-security_desc",
    "issues-quality_asc",
    "issues-quality_desc",
] | None = None

page: int = 1
count: int = 20
```

Validation:

- `page >= 1`
- `1 <= count <= settings.max_page_size`
- `latest_scan_days >= 0` if set
- `last_revision_within_days >= 0` if set

### Query mapping

| MCP | FOSSA |
|---|---|
| `title` | `title` |
| `types` | repeated `type[]` |
| `is_public` | `isPublic` |
| `labels` | repeated `labels[]` |
| `team_ids` | repeated `teamId[]` |
| `latest_scan_days` | `latestScan` |
| `last_revision_within_days` | `lastRevisionWithin` |
| `locators` | repeated `locators[]` |
| `include_shared_projects` | `includeSharedProjects` |
| `only_include_shared_projects` | `onlyIncludeSharedProjects` |
| `inventory` | repeated `inventory[]` |
| `sort` | `sort` |
| `page` | `page` |
| `count` | `count` |

### Output

Return raw FOSSA response within the standard envelope.

---

## 13.2 `fossa_get_project`

### Intent

Get detailed metadata about exactly one FOSSA project.

### Endpoint

```http
GET /projects/{locator}
```

Operation ID:

```text
getProject
```

### Inputs

```python
project_locator: str
ref: str | None = None
ref_type: Literal["branch", "tag"] = "branch"
```

Rules:

- `project_locator` must not be blank.
- Encode it exactly once in the URL path.
- If `ref` is unset, omit both `ref` and `ref_type` from the query if practical.
- If `ref` is set, send:
  - `ref`
  - `ref_type`

Tool argument description for `project_locator` must say:

> Use the exact FOSSA locator returned by another FOSSA MCP tool. Do not guess it from a repository name.

Return raw FOSSA response.

---

## 13.3 `fossa_list_project_revisions`

### Intent

List analyzed revisions, branches, or tags for a project.

### Endpoint

```http
GET /projects/{locator}/revisions
```

Operation ID:

```text
getProjectRevisions
```

### Inputs

```python
project_locator: str
offset: int = 0
count: int = 20
resolved_only: bool = True
refs: list[str] | None = None
refs_type: Literal["branch", "tag"] | None = None
source: Literal[
    "github",
    "gitlab",
    "bitbucket",
    "azure",
    "cli",
    "archive",
    "container",
    "sbom",
    "binary",
] | None = None
minimal: bool = True
locator_contains: str | None = None
```

Validation:

- `offset >= 0`
- `1 <= count <= min(settings.max_page_size, 1000)`

### Mapping

| MCP | FOSSA |
|---|---|
| `offset` | `offset` |
| `count` | `count` |
| `resolved_only` | `resolved` |
| `refs` | repeated `refs[]` |
| `refs_type` | `refs_type` |
| `source` | `source` |
| `minimal` | `isMinimal` |
| `locator_contains` | `locator` |

Return raw FOSSA response.

For revision arguments elsewhere, descriptions must say:

> Use the full revision locator returned by FOSSA, including any `$revision` suffix.

---

## 13.4 `fossa_list_dependencies`

### Intent

List dependencies detected in a specific project revision, with filters useful for licensing/security investigation.

### Endpoint

```http
GET /v2/revisions/{locator}/dependencies
```

Operation ID:

```text
getProjectDependencies
```

### Inputs

```python
revision_locator: str
dependency_locators: list[str] | None = None
title: str | None = None

statuses: list[
    Literal["analyzing", "analyzed", "failed", "unknown"]
] | None = None

depths: list[
    Literal["direct", "transitive"]
] | None = None

layer_depths: list[
    Literal["base", "other"]
] | None = None

has_issues: list[
    Literal[
        "hasIssues",
        "hasLicensingIssues",
        "hasQualityIssues",
        "hasVulnIssues",
        "noIssues",
    ]
] | None = None

licenses: list[str] | None = None
fetchers: list[str] | None = None
show_ignored: bool = False

confidence: list[
    Literal["High", "Medium", "Low", "Unknown"]
] | None = None

sources: list[
    Literal["managed", "vendored"]
] | None = None

package_labels: list[str] | None = None
vendored_path: str | None = None

include_resolution_notes: bool = False
include_license_text: bool = False
include_copyright: bool = False
include_matches: bool = False
include_download_url: bool = False

page: int = 1
count: int = 20
```

### Mapping

| MCP | FOSSA |
|---|---|
| `dependency_locators` | repeated `locators[]` |
| `title` | `title` |
| `statuses` | repeated `status[]` |
| `depths` | repeated `depth[]` |
| `layer_depths` | repeated `layerDepth[]` |
| `has_issues` | repeated `hasIssues[]` |
| `licenses` | repeated `licenses[]` |
| `fetchers` | repeated `fetchers[]` |
| `show_ignored` | `showIgnored` |
| `confidence` | repeated `confidence[]` |
| `sources` | repeated `sources[]` |
| `package_labels` | repeated `packageLabels[]` |
| `vendored_path` | `vendoredPath` |
| `include_resolution_notes` | `includeResolutionNotes` |
| `include_license_text` | `includeLicenseText` |
| `include_copyright` | `includeCopyright` |
| `include_matches` | `includeMatches` |
| `include_download_url` | `includeDownloadUrl` |
| `page` | `page` |
| `count` | `count` |

Default expensive/full-text fields to false.

Return raw FOSSA response.

---

## 13.5 `fossa_get_dependency`

### Intent

Get the richer detail record for one dependency in one revision.

### Endpoint

```http
GET /v2/revisions/{locator}/dependencies/{dependencyRevisionLocator}
```

Operation ID:

```text
getProjectDependency
```

### Inputs

```python
revision_locator: str
dependency_revision_locator: str
include_resolution_notes: bool = True
include_license_text: bool = False
include_copyright: bool = False
include_matches: bool = False
include_download_url: bool = False
```

Encode both locator path parameters exactly once.

Mapping:

- `include_resolution_notes` -> `includeResolutionNotes`
- `include_license_text` -> `includeLicenseText`
- `include_copyright` -> `includeCopyright`
- `include_matches` -> `includeMatches`
- `include_download_url` -> `includeDownloadUrl`

Tool description for `dependency_revision_locator`:

> Use the exact dependency revision locator returned by `fossa_list_dependencies`.

Do not strip richer response fields such as authors, description, URL, individual/grouped licenses, source type, publication date, root-project details, or issue notes.

---

## 13.6 `fossa_list_issues`

### Intent

Query licensing, vulnerability, or quality issues globally or for one project revision. Supports comparing issues between revisions.

### Endpoint

```http
GET /v2/issues
```

Operation ID:

```text
getIssues
```

### Inputs

```python
category: Literal[
    "licensing",
    "vulnerability",
    "quality",
]

status: Literal[
    "active",
    "ignored",
] = "active"

scope_type: Literal[
    "global",
    "project",
] = "global"

project_locator: str | None = None
revision_locator: str | None = None

compare_to_revision: str | None = None
change_status: Literal[
    "new",
    "remediated",
    "unchanged",
] | None = None

issue_ids: list[int] | None = None
search: str | None = None

depths: list[
    Literal["direct", "deep"]
] | None = None

issue_types: list[str] | None = None
package_managers: list[str] | None = None
cwes: list[str] | None = None
project_labels: list[str] | None = None

severity: list[
    Literal["critical", "high", "medium", "low", "unknown"]
] | None = None

severity_source: list[
    Literal["standard", "custom"]
] | None = None

found_before: datetime | None = None
found_after: datetime | None = None

issue_source: list[str] | None = None

sort: Literal[
    "package_asc",
    "package_desc",
    "created_at_asc",
    "created_at_desc",
    "severity_asc",
    "severity_desc",
    "epss_asc",
    "epss_desc",
] | None = None

include_direct_dependency_origin_paths: bool = False

page: int = 1
count: int = 20
```

### Validation

Implement model-level validation.

1. If `scope_type == "global"`:
   - `project_locator` must be `None`.
   - `revision_locator` must be `None`.
   - `compare_to_revision` must be `None`.
   - `change_status` must be `None`.

2. If `scope_type == "project"`:
   - `project_locator` is required.
   - `revision_locator` is required in this MCP v1 for deterministic results.

3. `compare_to_revision` and `change_status` must be set together or both unset.

4. Revision comparison is allowed only for project scope.

5. `severity`, `severity_source`, and `cwes` are allowed only for vulnerability category.

6. `issue_types` is rejected for vulnerability category to keep the MCP contract deterministic.

7. `page >= 1`.

8. `1 <= count <= settings.max_page_size`.

### Required base query

Always send:

```text
category=<category>
status=<status>
scope[type]=<scope_type>
page=<page>
count=<count>
```

Project scope:

```text
scope[id]=<project_locator>
scope[revision]=<revision_locator>
```

Comparison:

```text
scope[compareTo][revision]=<compare_to_revision>
scope[compareTo][changeStatus]=<change_status>
```

### Filter mapping

| MCP | FOSSA |
|---|---|
| `issue_ids` | repeated `ids[]` |
| `search` | `filter[search]` |
| `depths` | repeated `filter[depths][]` |
| `issue_types` | repeated `filter[type][]` |
| `package_managers` | repeated `filter[packageManagers][]` |
| `cwes` | repeated `filter[cwes][]` |
| `project_labels` | repeated `filter[projectLabels][]` |
| `severity` | repeated `filter[severity][]` |
| `severity_source` | repeated `filter[severitySource][]` |
| `found_before` | `filter[foundBefore]`, ISO 8601 |
| `found_after` | `filter[foundAfter]`, ISO 8601 |
| `issue_source` | repeated `filter[issueSource][]` |
| `sort` | `sort` |
| `include_direct_dependency_origin_paths` | `includeDirectDependencyOriginPaths` |

Do not set CSV mode.

### Response behavior

For HTTP 200, return normal envelope.

For HTTP 202, return:

```python
{
    "ok": True,
    "endpoint": "GET /v2/issues",
    "state": "analysis_in_progress",
    "message": <FOSSA message if supplied>,
    "data": <raw response>,
}
```

Do not convert 202 into a fake empty issues list.

---

## 13.7 `fossa_get_issue`

### Intent

Retrieve complete detail for one issue.

### Endpoint

```http
GET /v2/issues/{issueId}
```

Operation ID:

```text
getIssue
```

### Inputs

```python
issue_id: int
category: Literal[
    "licensing",
    "vulnerability",
    "quality",
]

scope_type: Literal[
    "global",
    "project",
] = "global"

project_locator: str | None = None
revision_locator: str | None = None
```

Validation:

- `issue_id >= 1`
- global scope may not include project/revision locators.
- project scope requires both project and revision locators.

Query mapping:

Global:

```text
category=<category>
scope[type]=global
```

Project:

```text
category=<category>
scope[type]=project
scope[id]=<project_locator>
scope[revision]=<revision_locator>
```

Return raw FOSSA response.

---

## 13.8 `fossa_project_posture`

### Intent

Provide one high-value, model-friendly view of a project revision's current FOSSA issue posture.

This is a composite MCP workflow and is the centerpiece demo tool.

### Inputs

```python
project_locator: str
revision_locator: str
top_issue_count: int = 10
```

Validation:

- locators must not be blank.
- `1 <= top_issue_count <= 25`.

### Required upstream calls

Execute independent requests concurrently.

#### Call 1: issue-category counts

```http
GET /v2/issues/categories
```

Query:

```text
scope[type]=project
scope[id]=<project_locator>
scope[revision]=<revision_locator>
```

Expected body shape:

```json
{
  "licensing": 0,
  "quality": 0,
  "vulnerability": 0
}
```

#### Call 2: top vulnerabilities

```http
GET /v2/issues
category=vulnerability
status=active
scope[type]=project
scope[id]=<project_locator>
scope[revision]=<revision_locator>
sort=severity_desc
page=1
count=<top_issue_count>
```

#### Call 3: top licensing issues

```http
GET /v2/issues
category=licensing
status=active
scope[type]=project
scope[id]=<project_locator>
scope[revision]=<revision_locator>
sort=created_at_desc
page=1
count=<top_issue_count>
```

#### Call 4: top quality issues

```http
GET /v2/issues
category=quality
status=active
scope[type]=project
scope[id]=<project_locator>
scope[revision]=<revision_locator>
sort=created_at_desc
page=1
count=<top_issue_count>
```

#### Call 5: direct dependencies with issues

```http
GET /v2/revisions/{revision_locator}/dependencies
depth[]=direct
hasIssues[]=hasIssues
page=1
count=<top_issue_count>
```

### Required output

Return exactly these top-level fields:

```python
{
    "ok": True,
    "project_locator": project_locator,
    "revision_locator": revision_locator,
    "issue_counts": {
        "licensing": int,
        "vulnerability": int,
        "quality": int,
    },
    "top_vulnerability_issues": list,
    "top_licensing_issues": list,
    "top_quality_issues": list,
    "direct_dependencies_with_issues": list,
    "analysis_state": "complete" | "in_progress",
}
```

Rules:

- Extract issue arrays without discarding their fields.
- Extract the dependency array without discarding fields.
- If any applicable issue endpoint returns HTTP 202, set `analysis_state="in_progress"`.
- If any call returns 401, 403, or 404, fail the entire tool.
- Never silently replace an upstream failure with an empty list.
- Do not invent a numeric “risk score.”
- Do not call a project “safe,” “unsafe,” or “compliant.”
- Present facts; allow the LLM to reason about them.

Exactly five upstream calls should be made by this tool.

---

## 13.9 `fossa_get_attribution_report`

### Intent

Retrieve a text-friendly FOSSA attribution/SBOM report for a revision.

### Endpoint

```http
GET /v2/revisions/{locator}/attribution/download
```

Operation ID:

```text
getRevisionAttributionDownloadV2
```

### Inputs

```python
revision_locator: str

format: Literal[
    "MD",
    "TXT",
    "SPDX_JSON",
    "CYCLONEDX_JSON",
] = "MD"

include_deep_dependencies: bool = True
include_direct_dependencies: bool = True
include_license_list: bool = True
include_license_scan: bool = False
include_project_license: bool = True
include_copyright_list: bool = False
include_file_matches: bool = False
include_open_vulnerabilities: bool = False
include_closed_vulnerabilities: bool = False
include_dependency_summary: bool = True
include_license_headers: bool = False
include_package_labels: bool = False
include_hash_and_version_data: bool = False
```

Do not expose PDF, HTML, CSV, or XML in v1 because they are poor default MCP text payloads.

### Query mapping

Use exact API keys:

- `format`
- `includeDeepDependencies`
- `includeDirectDependencies`
- `includeLicenseList`
- `includeLicenseScan`
- `includeProjectLicense`
- `includeCopyrightList`
- `includeFileMatches`
- `includeOpenVulnerabilities`
- `includeClosedVulnerabilities`
- `includeDependencySummary`
- `includeLicenseHeaders`
- `includePackageLabels`
- `includeHashAndVersionData`

### Output behavior

For `MD` and `TXT`:

```python
{
    "ok": True,
    "format": "MD",
    "content_type": <response content type or None>,
    "truncated": False,
    "content": "...",
}
```

For `SPDX_JSON` and `CYCLONEDX_JSON`:

- Attempt `json.loads`.
- If it succeeds, put parsed JSON in `content`.
- If parsing fails, return text and set:

```python
"json_parse_error": True
```

### Size protection

If returned text exceeds `settings.report_max_chars`:

- keep only first `report_max_chars` characters,
- set `truncated=True`,
- add:

```python
"original_char_count": <integer>
```

Do not write report output to disk from the MCP tool.

---

# 14. MCP Server Construction

Create one server instance:

```python
from mcp.server import MCPServer

mcp = MCPServer(
    "FOSSA",
    version=<package version>,
    instructions=(
        "Read-only access to FOSSA projects, revisions, dependencies, "
        "licensing issues, vulnerability issues, quality issues, and "
        "attribution reports. No tool mutates FOSSA state."
    ),
)
```

Register exactly the nine tools.

Do not add aliases.

Do not add:

- generic REST tools,
- arbitrary HTTP tools,
- arbitrary path tools.

The tool catalog itself is part of the security design.

Every tool must use MCP annotations equivalent to:

```python
ToolAnnotations(
    read_only_hint=True,
    open_world_hint=True,
)
```

If the v2 SDK uses different field naming at the installed minor version, follow the current v2 type definition while preserving the same semantics.

---

## 15. Client Lifecycle

Requirements:

- One reusable `httpx.AsyncClient` per server process.
- Clean close on MCP server shutdown.
- No new HTTP client for each tool call.
- Tests can inject a mock transport.
- Do not patch private `httpx` internals.

Use the MCP v2 lifespan/dependency mechanism if it reduces complexity. A lazy shared client is also acceptable if cleanup is deterministic.

---

## 16. Transports

### 16.1 stdio

Default:

```bash
python -m fossa_mcp
```

or:

```bash
uv run fossa-mcp
```

No logging to stdout.

### 16.2 Streamable HTTP

Support:

```bash
uv run fossa-mcp --transport streamable-http
```

Use configured host/port.

Expected endpoint by default:

```text
http://127.0.0.1:8000/mcp
```

Do not build a new legacy SSE deployment path.

---

## 17. CLI

Expose:

```toml
[project.scripts]
fossa-mcp = "fossa_mcp.__main__:main"
```

Required usage:

```text
fossa-mcp
fossa-mcp --transport stdio
fossa-mcp --transport streamable-http
fossa-mcp --version
```

Allowed transport values:

- `stdio`
- `streamable-http`

Default:

- `stdio`

Keep CLI implementation simple.

---

## 18. Logging

Use standard Python logging.

Log:

- server startup transport,
- FOSSA method and path,
- status code,
- elapsed milliseconds,
- retry attempts.

Example:

```text
INFO fossa_mcp.client FOSSA GET /v2/projects -> 200 in 184ms
```

Never log:

- API token,
- Authorization header,
- report content,
- full FOSSA response bodies,
- dependency license text.

When using stdio, logging must go to stderr.

---

# 19. Tests

All non-live tests must pass with no internet access:

```bash
uv run pytest
```

## 19.1 Query serialization tests

Mandatory.

### Repeated severity

Input:

```python
severity=["critical", "high"]
```

Expected semantic query:

```text
filter[severity][]=critical
filter[severity][]=high
```

### Project types

Input:

```python
types=["container", "sbom"]
```

Expected:

```text
type[]=container
type[]=sbom
```

### Revisions refs

Input:

```python
refs=["main", "develop"]
```

Expected:

```text
refs[]=main
refs[]=develop
```

### Empty arrays

`None` and `[]` must omit the query parameter.

## 19.2 Authentication tests

Verify request includes:

```text
Authorization: Bearer test-token
```

Then verify `test-token` never appears in:

- raised exception strings,
- captured logs,
- MCP tool output.

## 19.3 Endpoint contract tests

For every tool verify:

- HTTP method,
- exact URL path,
- exact query keys,
- repeated query values,
- correct standard result envelope,
- raw FOSSA fields are preserved.

Do not test only helper functions.

## 19.4 Error tests

Required cases:

- 400 with FOSSA JSON error,
- 401,
- 403,
- 404,
- 500,
- malformed/non-JSON error body,
- timeout,
- connection error,
- issue endpoint 202.

Assertions:

- correct exception behavior,
- actionable safe text,
- no token leakage.

## 19.5 Locator encoding

Mandatory sample locators:

```text
git+github.com/acme/widget
git+github.com/acme/widget$abc123
npm+lodash$4.17.21
custom+1234/example
```

Verify:

- safe path encoding,
- exact-once encoding,
- no application-created `%252F`,
- query locators are not pre-encoded.

## 19.6 MCP integration tests

Use the official MCP v2 in-memory client API.

Conceptual pattern:

```python
from mcp import Client
from fossa_mcp.server import mcp

async with Client(mcp) as client:
    ...
```

Adapt only if the installed current v2 SDK's test client API differs.

Required assertions:

1. `tools/list` returns exactly nine tools.
2. Tool names exactly match this scope.
3. Each tool is read-only annotated.
4. One mocked tool call returns structured output.
5. Invalid input is rejected before an HTTP request occurs.
6. A FOSSA execution exception appears as an MCP tool error (`is_error=True`), not as successful text.

## 19.7 Posture tests

Mock all five upstream calls.

Verify:

- exactly five calls,
- independent calls execute concurrently,
- issue counts mapped correctly,
- issue records preserved,
- dependencies preserved,
- all-200 => `analysis_state="complete"`,
- any relevant 202 => `analysis_state="in_progress"`,
- 401/403/404 => entire tool fails,
- no invented risk score.

## 19.8 Attribution report tests

Test:

- Markdown content.
- TXT content.
- valid SPDX JSON.
- valid CycloneDX JSON.
- malformed JSON fallback.
- configured text truncation.
- `truncated` flag and original character count.

## 19.9 Live tests

`tests/test_live.py`:

```python
@pytest.mark.live
```

Skip unless:

```text
FOSSA_API_TOKEN
```

is present.

Live smoke behavior:

1. `GET /v2/projects` with `count=1`.
2. If at least one project exists, optionally fetch that one project.
3. Never assume projects exist.
4. Never mutate data.

Normal CI must not require a live token.

---

# 20. Lint, Formatting, and Type Checking

Required commands:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

All must pass.

Suggested Ruff line length:

```text
100
```

Rules:

- no blanket `# type: ignore`,
- avoid `Any` in MCP input models,
- `Any` is acceptable at the raw API-response boundary.

---

# 21. OpenAPI Refresh Script

Implement:

```bash
uv run python scripts/update_openapi.py
```

Behavior:

1. GET:
   `https://app.fossa.com/api/api-docs/swagger.json`
2. Validate JSON parses.
3. Validate `openapi` begins with `3.`
4. Validate `info.title == "FOSSA API"`.
5. Validate `paths` exists and is non-empty.
6. Pretty-print deterministic JSON into `spec/fossa-openapi.json`.
7. Calculate SHA-256.
8. Update `spec/README.md` with:
   - UTC timestamp,
   - `info.version`,
   - SHA-256,
   - source URL.
9. Exit nonzero on any failure.

This public OpenAPI fetch must not require a FOSSA token.

---

# 22. README Requirements

README must include:

## 22.1 Overview

Explain what the server does in one concise paragraph.

## 22.2 Safety statement

Include exactly or substantively:

> This version is read-only and does not modify FOSSA state.

## 22.3 Requirements

- Python 3.11+
- `uv`
- Full FOSSA API token for live calls
- Node/npm only when launching MCP Inspector through `mcp dev`

## 22.4 Setup

```bash
git clone <repo>
cd fossa-mcp
uv sync
cp .env.example .env
```

Then:

```dotenv
FOSSA_API_TOKEN=<your-full-api-token>
```

## 22.5 Validate

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## 22.6 MCP Inspector

Document a tested v2 command, for example:

```bash
uv run mcp dev src/fossa_mcp/server.py
```

If package import layout requires a different command, use the actually tested command.

## 22.7 stdio

```bash
uv run fossa-mcp
```

## 22.8 Streamable HTTP

```bash
uv run fossa-mcp --transport streamable-http
```

## 22.9 Tool table

Provide a compact table of all nine MCP tools.

## 22.10 Example prompts

Include:

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

---

# 23. Security Acceptance Requirements

The implementation fails review if any of the following are true:

- A real API token is committed.
- API token is an MCP tool argument.
- API token appears in logs or output.
- Arbitrary URLs can be fetched by the LLM.
- Arbitrary HTTP methods can be selected by the LLM.
- A generic FOSSA endpoint proxy exists.
- A write endpoint is reachable through a generic escape hatch.
- TLS verification is disabled by default.
- A tool claims that a project is legally compliant or secure based solely on the returned data.
- Report content is logged.
- Raw stack traces containing request internals are returned to the model.
- `shell=True` is used.
- Normal operation requires subprocess invocation.

`.gitignore` must contain at least:

```text
.env
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
.pyright/
```

---

# 24. Performance and Context-Size Requirements

For normal direct tools:

- exactly one FOSSA request per invocation.

For `fossa_project_posture`:

- exactly five FOSSA requests,
- independent requests should execute concurrently.

Do not auto-paginate through an entire organization.

Pagination is caller-controlled.

Do not automatically retrieve license texts or full report documents unless explicitly requested.

These constraints prevent slow calls and accidental context explosions.

---

# 25. Agent Usability Requirements

Tool descriptions must explain **when to use the tool**.

Good:

```python
"""List FOSSA projects visible to the current account.

Use this first when the user names a project informally or asks for an
organization-wide project inventory. Supports sorting by licensing, security,
quality, scan time, and title.
"""
```

Bad:

```python
"""Lists projects."""
```

Mandatory argument-description language:

### Project locator

> Use the exact FOSSA locator returned by another FOSSA MCP tool. Do not guess it from the repository name.

### Revision locator

> Use the full revision locator returned by FOSSA, including any `$revision` suffix.

### Dependency revision locator

> Use the exact dependency revision locator returned by `fossa_list_dependencies`.

The model must never be encouraged to synthesize locators from project titles.

---

# 26. Demo Workflow

The README should provide this recommended technical-screen demonstration.

## Step 1 — Project discovery

Prompt:

```text
Show me the five FOSSA projects with the most security issues.
```

Expected:

```text
fossa_list_projects(sort="issues-security_desc", count=5)
```

## Step 2 — Revision discovery

Prompt:

```text
Show the last five analyzed revisions on the main branch for this project.
```

Expected:

```text
fossa_list_project_revisions(
    project_locator=<locator>,
    resolved_only=True,
    refs=["main"],
    refs_type="branch",
    count=5,
)
```

## Step 3 — Composite posture

Prompt:

```text
Give me the FOSSA posture for this revision.
```

Expected:

```text
fossa_project_posture(...)
```

## Step 4 — Vulnerability triage

Prompt:

```text
Show only critical and high active vulnerabilities, highest severity first.
```

Expected:

```text
fossa_list_issues(
    category="vulnerability",
    scope_type="project",
    project_locator=<project>,
    revision_locator=<revision>,
    severity=["critical", "high"],
    sort="severity_desc",
)
```

## Step 5 — Dependency drill-down

Prompt:

```text
Show direct dependencies that have issues.
```

Expected:

```text
fossa_list_dependencies(
    revision_locator=<revision>,
    depths=["direct"],
    has_issues=["hasIssues"],
)
```

## Step 6 — Compliance artifact

Prompt:

```text
Generate the Markdown attribution report for this revision.
```

Expected:

```text
fossa_get_attribution_report(
    revision_locator=<revision>,
    format="MD",
)
```

The demonstration should show usefulness without changing customer data.

---

# 27. Acceptance Checklist

## Functional

- [ ] Exactly nine MCP tools are exposed.
- [ ] All tools are callable through MCP, not just as Python functions.
- [ ] All tools are read-only.
- [ ] Bearer authentication works.
- [ ] stdio transport works.
- [ ] Streamable HTTP transport works.
- [ ] Path locators are safely encoded exactly once.
- [ ] Repeated bracketed query arrays serialize correctly.
- [ ] Revision comparison works in `fossa_list_issues`.
- [ ] `fossa_project_posture` makes exactly five upstream requests.
- [ ] Attribution Markdown/TXT/JSON modes work.

## API correctness

- [ ] No undocumented endpoint is used.
- [ ] Paths match vendored OpenAPI.
- [ ] Query keys match vendored OpenAPI.
- [ ] Enum values match vendored OpenAPI.
- [ ] FOSSA JSON errors are parsed defensively.
- [ ] Raw API response fields are preserved.
- [ ] HTTP 202 issue-analysis responses are handled explicitly.
- [ ] Token is never exposed.

## Quality

- [ ] `uv run pytest` passes.
- [ ] `uv run ruff check .` passes.
- [ ] `uv run ruff format --check .` passes.
- [ ] `uv run pyright` passes.
- [ ] Normal tests use no network.
- [ ] Live tests are opt-in.
- [ ] README is enough for another engineer to install/run/demo.

## MCP

- [ ] Official MCP Python SDK v2 is used.
- [ ] Typed schemas are generated from Python/Pydantic.
- [ ] Unexpected fields are rejected.
- [ ] Read-only annotations are present.
- [ ] API execution errors become MCP tool errors.
- [ ] No new legacy SSE implementation exists.
- [ ] In-memory MCP integration tests pass.

---

# 28. Strict Instructions to Qwen3-Coder:30B

Follow all rules below.

1. Do not improvise new product functionality.
2. Do not add write endpoints.
3. Do not add a generic request/proxy tool.
4. Do not rename the nine MCP tools.
5. Do not switch languages.
6. Do not use MCP Python SDK v1/FastMCP.
7. Do not replace async `httpx` with `requests`.
8. Do not build rigid Pydantic response models for the full FOSSA API.
9. Do not swallow API errors.
10. Do not return errors as successful tool data.
11. Do not log tokens or report bodies.
12. Do not make normal tests call the internet.
13. Do not auto-paginate complete collections.
14. Before implementing each API method, verify the endpoint and query keys in `spec/fossa-openapi.json`.
15. If this document and the vendored OpenAPI disagree, use the OpenAPI value and document the discrepancy.
16. Prefer the smallest correct abstraction.
17. Do not add an abstraction unless at least two call sites need it, except for security/configuration boundaries.
18. Run Ruff, format check, Pyright, and Pytest before declaring completion.
19. Fix actual failures; do not use `xfail` to manufacture a green build.
20. Do not leave TODOs in required behavior.
21. Do not weaken tests to fit broken implementation behavior.
22. Never claim a validation command passed unless it was actually executed.
23. Preserve API raw fields unless this scope explicitly defines a composite normalized result.
24. Never infer a locator from a project/repository name when a FOSSA-returned locator is required.
25. Keep the server read-only even if the OpenAPI exposes useful write endpoints.

---

# 29. Implementation Order

Implement in this order:

1. `pyproject.toml`, package skeleton, `.gitignore`, `.env.example`.
2. `Settings`.
3. Error classes.
4. Query/encoding helpers.
5. `FossaClient`.
6. Client tests.
7. Project tools.
8. Revision tool.
9. Dependency tools.
10. Issue tools.
11. Composite posture tool.
12. Attribution report tool.
13. MCP server registration.
14. CLI and transports.
15. Fixtures.
16. Per-tool contract tests.
17. MCP integration tests.
18. OpenAPI refresh script.
19. README.
20. Ruff/format.
21. Pyright.
22. Full Pytest.
23. Optional live smoke test.

Do not start by over-building documentation or architecture before the HTTP contract tests pass.

---

# 30. Definition of Done Report

When implementation is complete, report this structure and fill it truthfully:

```text
IMPLEMENTATION COMPLETE

Tools:
- fossa_list_projects
- fossa_get_project
- fossa_list_project_revisions
- fossa_list_dependencies
- fossa_get_dependency
- fossa_list_issues
- fossa_get_issue
- fossa_project_posture
- fossa_get_attribution_report

Validation:
- pytest: PASS | FAIL | NOT RUN
- ruff check: PASS | FAIL | NOT RUN
- ruff format --check: PASS | FAIL | NOT RUN
- pyright: PASS | FAIL | NOT RUN

Transports:
- stdio: PASS | FAIL | NOT RUN
- streamable-http: PASS | FAIL | NOT RUN

Live FOSSA smoke test:
- PASS | FAIL | SKIPPED
```

Never claim PASS for an unexecuted check.

---

# 31. References

Use these sources while implementing:

- FOSSA OpenAPI:
  `https://app.fossa.com/api/api-docs/swagger.json`
- FOSSA API docs:
  `https://docs.fossa.com/docs/api`
- FOSSA authentication:
  `https://docs.fossa.com/docs/api/authentication`
- MCP Python SDK v2:
  `https://py.sdk.modelcontextprotocol.io/`
- MCP Python SDK tools:
  `https://py.sdk.modelcontextprotocol.io/servers/tools/`
- MCP Python SDK error handling:
  `https://py.sdk.modelcontextprotocol.io/servers/handling-errors/`
- MCP Python SDK server execution:
  `https://py.sdk.modelcontextprotocol.io/run/`

---

# 32. Final Design Principle

Treat this project as a **domain-specific MCP adapter**, not an API mirror.

A strong implementation should look like something a FOSSA engineer could review and trust:

- exact API contracts,
- safe credential handling,
- useful model-facing semantics,
- correct FOSSA locator handling,
- deterministic tests,
- explicit handling of analysis-in-progress,
- no write surprises,
- no arbitrary endpoint escape hatch,
- no invented API behavior.
