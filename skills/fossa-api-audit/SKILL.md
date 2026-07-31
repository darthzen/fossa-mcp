---
name: fossa-api-audit
description: Audit the FOSSA MCP server against its vendored OpenAPI spec and the live API - enumerate documented operations, map registered tools to them, live-verify every read endpoint, and prove the write gate refuses without a single HTTP call. Use when asked whether the endpoints are alive and accessible, whether the tool surface matches the documented API, for a coverage matrix or parity check, to look for spec drift, or after regenerating the spec or registering new tools.
---

# fossa-api-audit

Parse the vendored spec, derive the registered tool surface from the code as it
sits on disk, cross them into a coverage matrix, exercise every read endpoint
against the live API, run the refusal tests to prove the write gate holds, and
report the gaps.

**Why this workflow exists:** three surfaces drift independently. The vendored
spec (`spec/fossa-openapi.json`) is regenerated from FOSSA's published swagger
and grows on FOSSA's schedule; the registered tool list changes per branch —
this repo has had 9 tools on one branch and 13 on another *at the same time*,
with tool modules that exist but are not imported; and the live API answers for
what actually works today, for this org, with this token. An audit that
hardcodes any of the three answers a question nobody asked.

**The honest framing, stated up front and never dropped:** "live-verified"
means one successful call, from one org, at one moment. And the spec cannot
always be failed against: several GET operations declare a bodyless or
property-less 200 (6 of 157 at API 4.34.55, `GET /projects/{locator}` the
known worst case), so a live response full of fields the spec never mentions is
a **spec gap to report, not a server bug to flag**. Keep the two verdicts
separate everywhere they appear.

Run from the repo root. Results are branch-specific — name the branch
(`git branch --show-current`) in the report, first line.

## 1. Enumerate the documented surface

Confirm the spec exists before anything else. It lives at
`spec/fossa-openapi.json` on the branches where this skill is used
(`api-parity`, `security-policy-writes`) but not on every branch — if the file
is missing, read it out of git without switching branches:

```bash
git show api-parity:spec/fossa-openapi.json > "$TMPDIR/fossa-openapi.json"
```

Do **not** reach for `scripts/update_openapi.py` as the fallback: regeneration
fetches the *current* live spec, which may be a newer API version than the one
the code was written against, and that silently moves the goalposts of the
audit. Regenerate only if the user asks.

```bash
python3 - <<'EOF'
import json
spec = json.load(open("spec/fossa-openapi.json"))
ops = sorted((m.upper(), p) for p, item in spec["paths"].items()
             for m in item if m in ("get", "post", "put", "patch", "delete"))
gets = [o for o in ops if o[0] == "GET"]
print(f"API {spec['info']['version']}: {len(spec['paths'])} paths, "
      f"{len(ops)} operations ({len(gets)} GET, {len(ops)-len(gets)} write-method)")
for m, p in ops:
    print(m, p)
EOF
```

At 4.34.55 that prints 191 paths and 271 operations, 157 GET / 114
write-method. The method split is a first cut, not the truth: `POST
/v2/projects` is a documented **read** (the filter set moves into the body when
the query string gets long), and `fossa_list_projects` genuinely issues it.
Classify by what the operation does, not only by its verb.

## 2. Derive the registered tool surface

From `src/fossa_mcp/server.py`, at runtime, every time. Never reuse a tool
list from a previous audit, this file, or memory — it is wrong on at least one
branch of this repo right now.

```bash
grep -n 'mcp.tool(name=' src/fossa_mcp/server.py
grep -n 'from .tools import' src/fossa_mcp/server.py
ls src/fossa_mcp/tools/
```

The difference between the second and third commands matters: a module in
`tools/` that the server does not import is written-but-unregistered work
(`release_groups.py` has been in exactly that state), and it belongs in the
report's recommendations, not in the coverage count.

Then map each registered tool to the spec operations it exercises by reading
the requests out of the tool modules:

```bash
grep -n 'request_json\|request_text' src/fossa_mcp/tools/*.py
```

Normalize the f-strings — `f"/projects/{encoded_locator}"` is the spec's
`/projects/{locator}` — and expect one tool to map to **several** operations:
`fossa_get_project` can issue up to four GETs (project, labels,
release-groups, last-published) and `fossa_project_posture` is an aggregate by
design. Credit every operation a tool touches. Also read the tool body far
enough to catch conditionals: a "list" tool may have a POST fallback branch.

## 3. Build the coverage matrix

Three columns per operation: **documented in spec / registered as a tool /
verified live**. Lead the matrix with counts, then keep three explicit gap
lists:

- **Documented, no tool** — the backlog. Group by path prefix (domain) so the
  list reads as "Teams: 0 of 11" rather than 90 raw rows.
- **Tool requests it, spec doesn't document it** — the server depends on an
  undocumented endpoint. Rare and worth a loud flag; it will break without
  notice.
- **Registered, not verified live** — whatever step 4 could not confirm, with
  the reason (auth, missing data, timeout), never silently dropped.

## 4. Live-verify the read surface

The token is **`FOSSA_API_TOKEN`** — there is no `FOSSA_API_KEY` in this
codebase. `src/fossa_mcp/config.py` is the authority for every variable name
(`fossa_api_token`, `fossa_base_url` defaulting to
`https://app.fossa.com/api`, and the rest); it also loads `.env`, so an unset
shell variable does not mean the server has no token. Check config.py again
each audit rather than trusting this paragraph.

Get a real locator first — **never invent one**; a 404 on a fabricated
locator proves nothing about the endpoint:

```bash
curl -s -H "Authorization: Bearer $FOSSA_API_TOKEN" \
  "https://app.fossa.com/api/v2/projects?count=1" | python3 -m json.tool | head -30
```

URL-encode the locator before it enters a path — it contains `+`, `/`, and
`$`:

```bash
python3 -c 'from urllib.parse import quote; print(quote("git+github.com/org/repo", safe=""))'
```

Then hit every path a registered read tool requests, recording status and
latency:

```bash
curl -s -o /tmp/resp.json -w '%{http_code} %{time_total}s\n' \
  -H "Authorization: Bearer $FOSSA_API_TOKEN" \
  "https://app.fossa.com/api/projects/<encoded-locator>"
```

**Run the independent calls in parallel** — background the curls and `wait`,
or write a short httpx/asyncio script with the repo's own venv. The calls are
independent and round-trips dominate the runtime. Exercising the registered
MCP tools directly is equally valid *if* the connected server was built from
the branch under audit; a stale connected server audits last week's code, and
curl audits the checkout. Say which you used.

Read the statuses as diagnosis, not pass/fail:

| Status | Meaning |
|---|---|
| 200 | Alive. Proceed to field comparison. |
| 401 / 403 | Token or entitlement problem — the endpoint may be fine. Report as auth, not as a dead endpoint. |
| 404 on a known-good locator | Endpoint or data problem — worth a second locator before concluding. |
| 5xx | FOSSA-side. Retry once; report if it persists. |

For each 200, compare the response's top-level fields against the spec's
declared `properties` for that operation. Three outcomes: fields match;
**fields present live but absent from the spec** (spec gap — the
`/projects/{locator}` case, where the 200 schema is a bare `{"type":
"object"}` with an example but zero properties); fields declared but missing
live (only this one is a potential server/API bug). When the schema is empty,
the spec's `examples` block is the best available hint — use it, and label the
comparison as example-based.

## 5. Prove the write gate without mutating anything

Never verify a write endpoint by calling it. The repo already contains the
proof — refusal tests that call each gated tool with the tiers off and assert
both the typed refusal and **zero HTTP calls**
(`respx_mock.calls.call_count == 0`; respx intercepts the transport, so even a
gate bug could not reach FOSSA from inside the test). Run them with the tier
variables *removed*, not merely unset-looking:

```bash
env -u FOSSA_ALLOW_WRITES -u FOSSA_ALLOW_DESTRUCTIVE -u FOSSA_ALLOW_ADMIN \
  uv run pytest tests/test_policy_tools.py -q
```

`pyproject.toml` sets `addopts = "-m 'not live'"`, so this run touches no
network anywhere in the suite. If `src/fossa_mcp/writes.py` or the refusal
tests are absent on the audited branch, the branch has no write surface —
report that as a fact, not a failure. Report the write side as: N gated tools,
refusal tests green, zero requests sent.

## 6. Report

Verdict first, one block:

- **X of Y documented operations covered** by registered tools (and X of the
  GET subset — the number that matches the server's read-first posture).
- **X of Y registered read tools verified live**, with the failure list right
  there, each with its status and diagnosis.
- Write gate: held / not run / absent on this branch.

Then the matrix (counts, then the domain-grouped gap lists). Then **spec
drift**, its own section: fields returned live but undocumented (per
endpoint), operations with empty schemas, and the vendored spec version
against today's live one if known. Close with **recommended next
registrations**, in order: tool modules already written but not imported
(cheapest), then documented GET domains with no tool at all, sized by
operation count. If nothing is broken, the verdict is one line and the report
earns its length from the gaps, not from restating success.

## Traps

- **`FOSSA_API_KEY` does not exist.** The variable is `FOSSA_API_TOKEN`.
  Config strips surrounding whitespace from the token; curl does not — a
  token read from a file with `$(cat ...)` keeps its trailing newline and
  turns every request into a 401 that looks like a bad token.
- **A missing `spec/fossa-openapi.json` means the checkout is on a branch
  without the vendored spec, not that the spec is gone.** Read it from the
  branch that has it — `git show api-parity:spec/fossa-openapi.json` — rather
  than regenerating; `scripts/update_openapi.py` fetches today's live spec and
  changes the source of truth mid-audit.
- **The registered tool count is branch-dependent and changes weekly.** 9 on
  the current working branch, 13 on `api-parity` (9 read + 4 policy from
  `tools/policies.py`), with unimported modules sitting in `tools/`. This is
  exactly why steps 1–2 derive everything from `server.py` at runtime;
  hardcoding a tool list is how an audit reports last month.
- **A read tool can issue POST.** `fossa_list_projects` falls back to
  `POST /v2/projects` (documented) when the filter set outgrows the query
  string. A method-only read/write split miscounts both columns.
- **One tool is not one operation.** `fossa_get_project` touches up to four
  paths, `fossa_project_posture` aggregates several. Mapping tools 1:1 to
  operations undercounts coverage.
- **Empty response schemas are a spec property, not a finding against the
  server.** `GET /projects/{locator}` declares a property-less object; fields
  like `securityPolicyId` were confirmed from live calls, not the spec
  (API_PARITY_PLAN.md, "Two known traps"). Tolerate undocumented fields and
  report them as spec gaps.
- **An exported `FOSSA_ALLOW_WRITES=true` fails the refusal tests.**
  pydantic-settings reads the real environment, and the tests assert the tier
  is off. That failure means your shell is configured to write, not that the
  gate is broken — hence the `env -u` in step 5.
- **The connected MCP server can be older than the checkout.** Its tool list
  reflects whatever build is running, not `server.py` on disk. When they
  disagree, the checkout is what you are auditing; say the running server is
  stale rather than merging the two lists.
- **Locators break unencoded paths.** `quote(locator, safe="")` before
  interpolation — `+`, `/`, and `$` are all load-bearing.

## Scope

This skill reads FOSSA and runs the repo's own tests. It does **not** mutate
FOSSA state — write endpoints are verified exclusively through the refusal
path, never by sending a request with the tiers enabled. It does **not**
regenerate `spec/fossa-openapi.json` — if the spec is missing or stale, ask
before running `scripts/update_openapi.py`, because that changes the source of
truth mid-audit. And it does **not** register tools or edit code: when the gap
list says `release_groups.py` should be imported, that is a recommendation for
the user to act on, raised as its own task.
