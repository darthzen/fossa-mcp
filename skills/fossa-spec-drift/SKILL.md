---
name: fossa-spec-drift
description: Compare the vendored FOSSA OpenAPI spec against the live one and report which changes affect this repo's registered MCP tools. Use when asked what changed in the FOSSA API since the spec was vendored, whether the vendored spec is stale, whether an API change breaks or touches a registered tool, or before refreshing the counts in API_PARITY_PLAN.md.
---

# fossa-spec-drift

Snapshot the vendored spec, fetch the live one, diff them at the operation
level, and say which of the differences land on a tool this server actually
registers. The output is a report, not a commit: the working tree is put back
the way it was found unless the user says otherwise.

**Why the diff is operation-level:** the spec is 1.4 MB of pretty-printed JSON.
A text diff drowns in key-order and formatting churn and cannot tell a doc-string
tweak from a removed parameter. Comparing the parsed JSON path-by-path gives
three clean lists — added, removed, changed — and "changed" is defined as
parameters, request body, or responses differing. Nothing else counts as drift.

Everything below is procedure; the only question worth asking first is whether
the user wants the report only (default) or also wants the new spec kept.

## 1. Snapshot the baseline

All commands run from the repo root:
`/Users/rashford/Library/Mobile Documents/com~apple~CloudDocs/Developer/fossa-mcp`
— quote the path, it contains spaces.

First confirm the baseline exists. `spec/fossa-openapi.json` is
branch-dependent: it was added in commit `340518d` and lives on `api-parity`
and `security-policy-writes`; on `block-package-tools` (checked 2026-07-31)
`spec/` holds only a three-line README stub and there is no JSON at all. If the
file is missing, there is no drift to measure — say so, and note that running
the update script (step 2) establishes a baseline for next time.

```bash
cp spec/fossa-openapi.json "$SCRATCHPAD/spec-baseline.json"
python3 -c "
import json
s = json.load(open('spec/fossa-openapi.json'))
M = {'get','put','post','delete','patch','options','head','trace'}
print(s['info']['version'],
      sum(1 for item in s['paths'].values() for m in item if m in M), 'operations')
"
```

Record both numbers. For reference: API 4.34.55 has 191 paths and 271
operations. Count operations with the method set above — `len(paths)` is the
wrong number and the two are 80 apart.

## 2. Fetch the latest spec

```bash
.venv/bin/python scripts/update_openapi.py
```

Facts about the script, from reading it:

- It fetches `https://app.fossa.com/api/api-docs/swagger.json`, validates
  OpenAPI 3.x and title `FOSSA API`, and exits non-zero on failure.
- It writes with **relative paths** — run it from the repo root or it creates a
  stray `spec/` wherever you are.
- It overwrites **two** files: `spec/fossa-openapi.json` and `spec/README.md`
  (retrieval timestamp, version, SHA-256). Both need restoring in step 6.
- It needs `httpx`, which is a project dependency — use the project venv, not
  system python.

## 3. Diff old vs new at the operation level

Save this to `$SCRATCHPAD/spec_drift.py` and run
`python3 "$SCRATCHPAD/spec_drift.py" "$SCRATCHPAD/spec-baseline.json" spec/fossa-openapi.json`:

```python
"""Operation-level diff of two FOSSA OpenAPI specs."""
import json, sys

METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}

def ops(spec):
    return {
        f"{m.upper()} {path}": op
        for path, item in spec["paths"].items()
        for m, op in item.items()
        if m in METHODS
    }

old, new = (json.load(open(p)) for p in sys.argv[1:3])
o, n = ops(old), ops(new)
print(f"version    {old['info']['version']} -> {new['info']['version']}")
print(f"operations {len(o)} -> {len(n)}")

for title, keys in (("ADDED", sorted(n.keys() - o.keys())),
                    ("REMOVED", sorted(o.keys() - n.keys()))):
    print(f"\n{title} ({len(keys)})")
    for k in keys:
        print(f"  {k}")

changed = [
    (k, [p for p in ("parameters", "requestBody", "responses")
         if o[k].get(p) != n[k].get(p)])
    for k in sorted(o.keys() & n.keys())
]
changed = [(k, parts) for k, parts in changed if parts]
print(f"\nCHANGED ({len(changed)})")
for k, parts in changed:
    print(f"  {k}  [{', '.join(parts)}]")
```

This diff is complete for this spec: it contains **zero `$ref`s** — every
parameter and schema is inlined into its operation, so nothing changes out of
band in `components`. (The 48 schemas under `components/schemas` are referenced
by no operation; ignore them.)

For anything the script flags as CHANGED that a tool depends on, pull the two
operation objects and compare them by eye before calling it action-required — a
reworded description inside `responses` is drift by the definition above but
needs no code change; a removed query parameter does.

## 4. Cross-reference against registered tools

Build the tool → endpoint map from the source, not from memory:

```bash
grep -n 'mcp.tool(name=' src/fossa_mcp/server.py
grep -rnE '"(GET|PUT|POST|PATCH|DELETE) /' src/fossa_mcp/tools/
```

`server.py` maps each `fossa_*` name to a function in `src/fossa_mcp/tools/`;
each tool module carries its endpoint as a string literal (the `"endpoint"` key
of its response envelope, or `_ENDPOINT` in `reports.py`). The 9 current read
tools resolve to 8 spec paths — `fossa_project_posture` has no endpoint of its
own, it composes the issues and dependencies calls in `posture.py`, so any flag
on those endpoints applies to it too.

Classify every diff line:

- **Changed operation with a tool on it → action-required.** Name the tool, the
  operation, and which of parameters / requestBody / responses moved.
- **Removed operation with a tool on it → breakage.** Top of the report.
- **Added operation → coverage opportunity.** Cross-check against the domain
  inventory in `API_PARITY_PLAN.md` (branch-dependent, see Traps) so you can say
  whether it falls in a domain already planned.
- **Changed/removed operation with no tool → mention in counts, no detail.**

## 5. Report

In this order: version bump (old → new) and operation counts; **breakage**;
**action-required**; then opportunities; then the no-tool remainder as a count.
If the lists are empty, "no drift affecting registered tools between X and Y"
is the whole finding and is worth stating plainly.

Update the counts in `API_PARITY_PLAN.md` **only if the user asks** — the plan
itself says to regenerate its numbers after an update run, but editing it is
the user's call, and the file only exists on the parity branches.

## 6. Restore the working tree

The update script has now modified the working tree. If the user wanted the
drift report only — the default — put it back:

```bash
git status --short spec/
git checkout -- spec/fossa-openapi.json spec/README.md
```

Run the `status` first and believe it: on a branch where the JSON was never
tracked, `git checkout` cannot restore it — the fetched file simply stays
untracked, and the honest move is to tell the user it is there and let them
keep or delete it. `spec/README.md` is tracked on every branch and always needs
the checkout, because the script rewrote it.

Committing the new spec is a separate decision the user makes. Do not stage it,
do not commit it, and do not fold it into an unrelated commit.

## Traps

- **The baseline is branch-dependent.** `spec/fossa-openapi.json` and
  `API_PARITY_PLAN.md` exist on `api-parity` and `security-policy-writes` but
  not on `main` or `block-package-tools` (verified 2026-07-31). Check
  `git ls-files spec/` before promising a diff; on the wrong branch the "old
  spec" you are diffing against may be one you just fetched.
- **The script overwrites `spec/README.md` too.** Restoring only the JSON
  leaves a modified README with a new timestamp and SHA in the tree — a
  confusing half-restore that looks like someone re-vendored without the spec.
- **Relative paths in the script.** Run from the repo root, and quote the root
  path — the iCloud path contains spaces and unquoted `cd` fails.
- **Count operations, not paths.** 191 paths vs 271 operations on 4.34.55. Any
  count that skips the method-set filter also miscounts, because path items can
  carry non-method keys.
- **Absent from both specs is not the same as safe.** FOSSA has real endpoints
  the spec never documented — `docs/ENDPOINT_INFERENCE.md` reconstructs one for
  package blocking. A tool built on an inferred endpoint cannot be drift-checked
  here; list any such tool as "not covered by the spec" instead of silently
  skipping it.
- **"Changed" per the script is necessary, not sufficient, for action.** It
  flags any byte-level difference inside parameters/requestBody/responses,
  including reworded descriptions. Read the flagged operation before declaring
  action-required; never declare it without the script flagging first.

## Scope

This skill reads the repo, runs one fetch script, and produces a report. It
does **not** commit anything, does **not** edit tool code or models to chase
the new spec, and does **not** touch `API_PARITY_PLAN.md` unless the user asks
for the count refresh. If drift demands code changes, name them precisely and
hand them back as their own task.
