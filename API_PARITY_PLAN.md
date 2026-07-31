# Full API parity — implementation plan

**Goal:** cover all 271 documented FOSSA operations (157 GET, 114 write) as MCP tools.

**Decided 2026-07-31.** Supersedes the scope in `FOSSA_MCP_IMPLEMENTATION_SCOPE.md` §3.3, which
is a frozen requirements artifact and is deliberately not edited. See DECISIONS.md §5, §6, §7.

Counts here are derived from `spec/fossa-openapi.json` (API 4.34.55). Regenerate them after any
`scripts/update_openapi.py` run rather than trusting this table — the API grows.

---

## Start here

**Superseded as of the `parity/integration` merge.** Every domain in the inventory below is done
except Dependencies. The sections that follow describe the state this plan was written from —
13 registered tools and an uncommitted foundation — and are kept because the pattern, the tier
rules, and the standing constraints still govern new work. The numbers in them do not.

Historical, from 2026-07-31: nothing in the domain inventory below has been started. The foundation
it depends on **is** built, tested, and green (155 passing) — but uncommitted. Read this section
before writing anything.

### What already exists

| Piece | File | State |
|-------|------|-------|
| Tiered write gate | `src/fossa_mcp/writes.py` | Done. `WriteTier` + `require_tier`. Every new write tool calls it. |
| Tier settings | `config.py` | Done. `FOSSA_ALLOW_WRITES` / `_DESTRUCTIVE` / `_ADMIN`, all default false. |
| Method-aware retry | `client.py` | Done. `_IDEMPOTENT_METHODS` — `POST`/`PATCH` are never replayed. |
| JSON body support | `client.py` | Done. `request_json(..., json_body=…)`. |
| Vendored spec | `spec/fossa-openapi.json` | Done. API 4.34.55, 1.4 MB. The source of truth for every signature. |
| Security policy tools | `tools/policies.py` | Done — 4 tools, the worked example of the pattern. |
| Policy overlay engine | `policy.py` | Done. Unrelated to parity; tighten-only local rules. |

Registered tools: **13** (9 original read, 4 policy). Target: ~60.

### Uncommitted work in the tree

Everything above is unstaged. `git status` shows 10 modified, 8 untracked. Commit before starting,
so the parity work has a clean base to diff against:

```bash
git checkout -b api-parity
git add -A ':!.venv'
git commit -m "feat: security policy tools, tiered write gating, vendored OpenAPI spec"
```

`.venv` shows as untracked because it is a symlink and `.gitignore` has `.venv/` — a directory
pattern. Leave it alone or fix the ignore separately; it is not part of this work.

### Copy this pattern

`src/fossa_mcp/tools/policies.py` is the reference implementation. A new write tool is five things:

1. Input model in `models.py` — `ConfigDict(extra="forbid")`, `Field` constraints.
2. Tool function in `tools/<domain>.py` — flat typed params (FastMCP builds the schema from the
   signature), construct the model first to validate, then call `require_tier`, then build the
   request. **Gate before request construction, always.**
3. Registration in `server.py` with annotations matching the tier.
4. respx contract test — method, path, exact query pairs, exact JSON body.
5. Refusal test — tier off, assert `respx_mock.calls.call_count == 0`.

`tests/test_policy_tools.py` shows all of it, including the `writable_settings` fixture.

### First move

Projects, per the order of work below. Ten writes and ten reads, and it exercises every tier:
`PUT /projects/{locator}` is `WRITE`, `DELETE /projects/{locator}` is `DESTRUCTIVE`, and
`DELETE /v2/projects` is `DESTRUCTIVE` with an unbounded filter — the case the tier split exists
for.

Read the spec entry before writing each one. `PUT /projects/{locator}` alone accepts 50 body
fields; do not infer them:

```bash
python3 -c "
import json; s=json.load(open('spec/fossa-openapi.json'))
op=s['paths']['/projects/{locator}']['put']
print(json.dumps(op['requestBody'], indent=2))"
```

### Two known traps

* **`GET /projects/{locator}` documents an empty response schema.** The 200 body has no declared
  properties in the spec, so field names must come from live responses — `securityPolicyId`,
  `securityIssueScanningEnabled` and friends were confirmed against a real call, not the spec.
  Expect the same gap elsewhere; verify reads against a live org before trusting a shape.
* **Locators need `quote(locator, safe="")`.** They contain `+`, `/`, and `$`. Asserting that in a
  test is harder than it looks, and an earlier version of this document got it wrong:

  **Letting the respx route match does not verify encoding, and neither does comparing
  `url.path`.** Both normalize the URL before comparing, so a route registered as
  `/api/projects/pip%2Baiofile` also matches a request that put `pip+aiofile` on the wire
  unescaped — verified directly against respx 0.23.1. A test that registers an encoded route and
  then asserts `route.called` passes whether or not the code encodes anything.

  Assert against `request.url.raw_path`, which is the bytes actually sent. The shared
  `assert_raw_path` fixture in `tests/conftest.py` is the one place that comparison lives; use it
  rather than writing a local variant.

---

## Tool shape: tiered hybrid

Not 1:1. 271 individual tools would exceed what MCP clients handle well, and tool-selection
accuracy degrades long before that. Instead:

* **Individual tools** for domains an operator actually drives by hand — projects, issues,
  revisions, dependencies, release groups, teams, labels, policies. Precise schemas, one tool per
  meaningful action.
* **Grouped action tools** for configuration long tails, where the shape is uniform and the
  endpoint count is dominated by section names rather than distinct behaviors. Organization
  Settings is 57 operations across ~20 near-identical `get/patch/put` triples; that is one
  `fossa_org_settings(section=…, action=…)` tool, not 57.

Target when this was written: **~60 tools** covering 271 operations. What shipped is **135**; see
the note above the domain inventory for why the estimate was low.

Grouped tools must still validate `section` against a `Literal` of known sections, so an invalid
section is a schema error at the client, not a 404 from FOSSA.

---

## Write tiers

Implemented in `src/fossa_mcp/writes.py`. Every write tool declares one; `require_tier` runs in
the tool body before any request is constructed.

| Tier | Env var | Covers |
|------|---------|--------|
| `WRITE` | `FOSSA_ALLOW_WRITES` | Create and update |
| `DESTRUCTIVE` | `FOSSA_ALLOW_DESTRUCTIVE` + writes | Deletes, and bulk endpoints whose target set is a filter rather than a list |
| `ADMIN` | `FOSSA_ALLOW_ADMIN` + writes | SAML, OIDC, roles, service accounts, team membership, auth settings |

Neither higher tier implies `WRITE`; both require it alongside. A half-configured deployment
therefore fails closed.

**Bulk endpoints that accept `"all"` or a filter set are `DESTRUCTIVE` even when the verb is
`PUT`.** `PUT /v2/projects/policy` with `locators=all` re-policies an entire organization from one
tool call. Tier follows blast radius, not HTTP method.

---

## Domain inventory

`Tools` is the estimate this plan was written with, kept as written. What actually shipped is 135
registered tools — 71 read-only, 64 write, 27 of the writes destructive — because several domains
needed a separate tool per delete where the estimate assumed one tool could carry create, update,
and delete together. A tool carries one tier and one set of annotations, so it cannot.

| Domain | GET | Write | DEL | Tools | Shape | Status |
|--------|----:|------:|----:|------:|-------|--------|
| Organization Settings | 22 | 34 | 1 | 3 | grouped | **done** |
| Projects | 10 | 10 | 4 | 9 | individual | **done** |
| Release Groups | 13 | 7 | 2 | 8 | individual | **done** |
| Issues | 14 | 5 | 2 | 8 | individual | **done** |
| Revisions | 14 | 3 | 0 | 7 | individual | **done** |
| Teams | 9 | 7 | 2 | 7 | individual | **done** |
| Dependencies | 11 | 0 | 0 | 4 | individual | partial (2 read) |
| OIDC | 5 | 4 | 2 | 11 | individual | **done** |
| Snippets | 9 | 2 | 0 | 4 | individual | **done** |
| Binary | 10 | 0 | 0 | 3 | grouped | **done** |
| Team Groups | 2 | 6 | 2 | 3 | individual | **done** |
| Package Labels | 2 | 6 | 2 | 3 | individual | **done** |
| Fossabot | 4 | 2 | 0 | 3 | individual | **done** |
| Roles | 3 | 3 | 1 | 2 | individual | **done** |
| Issue Filters | 2 | 3 | 1 | 2 | individual | **done** |
| Package Observability | 5 | 0 | 0 | 2 | grouped | **done** |
| Organization Labels | 2 | 2 | 1 | 2 | individual | **done** |
| Users | 3 | 1 | 0 | 2 | individual | **done** |
| Report Options | 1 | 3 | 1 | 2 | individual | **done** |
| Jira Integration | 1 | 3 | 1 | 2 | individual | **done** |
| Custom Risk Scores | 0 | 3 | 1 | 1 | individual | **done** |
| SBOM | 2 | 1 | 0 | 2 | individual | **done** |
| Audit Logs | 2 | 1 | 0 | 2 | individual | **done** |
| Components | 1 | 2 | 0 | 2 | individual | **done** |
| License Conclusions | 0 | 2 | 0 | 1 | individual | **done** |
| Issue Overview | 1 | 1 | 0 | 1 | individual | **done** |
| Organization Limits | 2 | 0 | 0 | 1 | grouped | **done** |
| Builds | 2 | 0 | 0 | 1 | individual | **done** |
| Vulnerabilities | 2 | 0 | 0 | 2 | individual | **done** |
| GitHub App / CLI / Project Labels | 3 | 0 | 0 | 3 | individual | **done** |
| Security policies | — | — | — | 4 | individual | **done** |

Two corrections to the counts this table shipped with:

* **OIDC is 11 operations, not 13.** The row read 5 / 6 / 2; the spec has 5 GET, 4 write, and 2
  DELETE. It is also individual rather than grouped, and 11 tools rather than the 2 estimated:
  providers, trust relationships, and the token exchange each have a distinct body, so a grouped
  tool would take a union of conditionally-valid arguments — the shape this document says to avoid.
* **`PUT` and `DELETE /organizations/{id}/saml` are counted under OIDC, not Organization
  Settings.** The spec tags them `Organization Settings`, which is why both agents building those
  domains claimed them. They are implemented once, in `tools/identity.py`, as
  `fossa_update_saml_settings` and `fossa_delete_saml_settings` — typed `cert` and `entry_point`
  arguments beat a free-form `values` dict for the configuration that decides who can log in. The
  Organization Settings row is reduced by those two; `tools/identity.py` is 11 OIDC tools plus
  those 2.

Dependencies is the one domain still partial: 2 of its 11 reads have tools.

---

## Order of work

Sequenced by how much a FOSSA operator actually reaches for each domain, not by endpoint count.

1. **Projects** — delete, update, bulk delete, labels, attribution slug, summary, export-issues
2. **Issues** — bulk update, exceptions CRUD, overview, types/statuses
3. **Revisions** — patch, scans, remediation guidance, SBOM analysis, notice files
4. **Release Groups** — full CRUD, releases, obligations, licenses
5. **Teams / Team Groups / Roles / Users** — `ADMIN` tier throughout
6. **Labels** — package labels, assignments, organization labels, project labels
7. **Organization Settings** — the 57-operation grouped tool
8. **OIDC / SAML** — `ADMIN` tier
9. **Long tail** — Jira, Fossabot, report options, risk scores, snippets, binary, components,
   audit logs, observability, builds, vulns

---

## Per-domain definition of done

A domain is not done until all of:

- [ ] Every operation in the domain reachable from a tool
- [ ] Pydantic input model in `models.py`, `extra="forbid"`
- [ ] Write tools declare a tier and call `require_tier` before building a request
- [ ] Tool registered in `server.py` with annotations matching its tier
  (`readOnlyHint` / `destructiveHint` / `idempotentHint`)
- [ ] respx contract test: method, exact path, exact query keys, exact JSON body
- [ ] Refusal test: gated tool with its tier off makes **zero** HTTP calls
- [ ] `test_mcp_integration.py` tier sets updated — that test partitions every registered tool and
      fails if an annotation disagrees with its declared set

---

## Standing constraints

Carried from DECISIONS.md; none of them are relaxed by this expansion.

- **`mcp` stays pinned to 1.28.x** (§1). Keep the tool layer thin so the 2.x migration stays cheap.
  Adding 60 tools makes this pin *more* load-bearing, not less.
- **Single-tenant, one token, no caller auth** (§2). This is why the tiers exist. Nothing here adds
  per-caller scoping, and the ADMIN tier should stay off on any shared deployment.
- **No new runtime dependencies** without updating `NOTICE` and the generated third-party license
  file (§3).
- **No generic `fossa_request` tool.** Grouped action tools are still explicit about their sections
  and actions; an arbitrary-endpoint proxy remains out of scope.
- **`POST`/`PATCH` are never retried** (`client.py`, `_IDEMPOTENT_METHODS`). A replayed create is a
  duplicate. Do not "fix" the retry loop by making it uniform.
