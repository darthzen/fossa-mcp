# Calibration — worked examples

Scored 2026-07-31 against a real 10-project FOSSA org. Use these as anchors so a
finding scored today lands where a comparable one landed before. All arithmetic
is shown; all FOSSA values are as returned by `fossa_project_posture`.

**Project names are anonymized** and replaced with the deployment shape that
actually decided each score — that shape is the reusable part, and the identity
of the org's projects is not. Every CVE, CVSS, EPSS percentile, and computed
score below is unaltered.

**Transports and import surfaces below were verified from source**, not assumed —
see "The assumption that was wrong" at the end for why that distinction cost 12
points on one project and 12 on another, in opposite directions.

**Re-verified against live FOSSA data.** Every CVSS, EPSS percentile and
`remediation` value quoted here was re-pulled and every arithmetic block
recomputed; all of them still reproduce exactly. Two things to know when
matching new work against these anchors:

- **Rounding is inconsistent in this file, by one point, twice.** Issue-level
  scores here round half **up** (54.5 → 55, 82.5 → 83) while the two project
  roll-ups round half **down** (56.5 → 56, 93.5 → 93). SKILL.md now fixes the
  rule at half-up; under it those roll-ups would read 57 and 94. The numbers
  are left as they were computed so the anchors match the report they came
  from. Neither ±1 crosses a band boundary — this is a rendering difference,
  not a scoring one.
- **The licensing anchors count raw issue rows.** Both were scored before the
  collapse rule in SKILL.md step 5. The LIS *values* (28 and 28) are unaffected
  — LIS scores a license and a linkage, not a row count — but the "15 flags"
  and "16 flags" figures are pre-collapse totals, and one of them is mostly
  packaging fan-out (see the note under the first licensing anchor).

## Result

| Project | Shape | L/S/Q | Worst CVSS | Peak EPSS %ile | CIRS | Band |
|---|---|---|---|---|---|---|
| `memory-service` | MCP server, streamable-HTTP, public ingress | 0/5/0 | 8.7 | 92.6 | 93 | Critical |
| `code-mcp` | MCP server, stdio, local | 0/6/0 | 8.7 | 92.6 | 81 | Critical |
| `metrics-exporter` | Go binary importing Prometheus as a library | 0/5/0 | 7.5 | 84.6 | 56 | Medium |
| `scanner-mcp` | MCP server, stdio; HTTP mode refuses to start without bearer auth | 15/1/2 | 6.8 | 3.9 | 34 | Low |
| `web-app` | Next.js SaaS, private repo | 16/1/19 | 6.1 | 10.7 | 31 | Low |

Five further projects had zero issues and were reported as clean.

The org has since grown a **duplicate project**: the same repo as `scanner-mcp`
at the same commit, uploaded separately under a `custom+` locator with its own
title. It returns the *same issue ids* as `scanner-mcp` and differs only in
which dev dependencies its scan included. It is not a sixth scored project and
must not become one — see the dedup rule in SKILL.md step 1.

The deployment facts behind these numbers were each read out of source or
deployment config, not inferred: the transport default in each server's entry
point, the Ingress in the Kubernetes manifests, the Go import surface, and a
lockfile grep establishing that the flagged npm package appears only in the
build chain.

## Anchor 1 — reachable, high EPSS, local service

**`code-mcp` / CVE-2025-53366 in `mcp 1.6.0`** (direct dep). Unhandled exception
on malformed requests. The parse path is shared across transports, so stdio does
not exempt it → Reachability 100. Local MCP server → Exposure 50. Fix is
1.6.0 → 1.28.1, a minor bump → FixFriction 0.

```
0.35×87.0 = 30.45      CVSS 8.7
0.25×92.6 = 23.15      EPSS 0.05981 → 92.563rd percentile
0.20×100  = 20.00      direct runtime dependency
0.15×50   =  7.50      local-only service
0.05×0    =  0.00      minor bump available
            ------
              81.1  →  81
```

This is the calibration point for "genuinely urgent." Note EPSS did the work:
the same CVSS at the 28th percentile scores 65.

## Anchor 2 — same package, transport-gated

**`code-mcp` / CVE-2025-53365** — same package, same CVSS 8.7, but the advisory
scopes it to the streamable-HTTP transport. Transport verified as stdio from the
server's config default → Reachability 20, Exposure 20.

```
0.35×87.0 = 30.45
0.25×28.0 =  7.00      EPSS 28.01st percentile
0.20×20   =  4.00      vulnerable transport not enabled
0.15×20   =  3.00
0.05×0    =  0.00
            ------
              44.45 →  44
```

Identical CVSS, 37 points apart. Siblings under verified stdio:
CVE-2025-66416 → 44, CVE-2026-52869 → 38, CVE-2026-59950 → 35.

## Anchor 2b — the same CVE, other side of the transport line

**`memory-service` / CVE-2025-53365** — byte-identical dependency (`mcp 1.6.0`),
but it defaults to streamable-HTTP and runs behind a public Kubernetes Ingress.
Reachability 100, Exposure 100.

```
0.35×87.0 = 30.45
0.25×28.0 =  7.00
0.20×100  = 20.00      transport in use
0.15×100  = 15.00      public ingress
0.05×0    =  0.00
            ------
              72.45 →  72
```

**28 points on the same CVE and the same package version, decided entirely by a
one-line default in the server's entry point.** Read the transport; never infer
it from the fact that something is "an MCP server."

Siblings: CVE-2025-53366 → 89, CVE-2026-52869 → 66 (session hijack against a
*memory store* — the highest-consequence finding in that portfolio),
CVE-2025-66416 → 66 at Reachability 70 (the Host-validation gap is present, but
the advisory's exploit scenario is localhost-specific), CVE-2026-59950 → 47
(WebSocket transport, not in use, even though the service is HTTP-exposed).

Project: 89 + 1.5×3 = 93.5 → 93.

## Anchor 3 — the CVSS disagreement

**`metrics-exporter` / CVE-2019-3826 in `prometheus v0.51.2`** (direct dep).
Stored XSS in the Prometheus **web UI**. The project imports Prometheus as a Go
library and builds an exporter binary — the web UI is not compiled in.

Naive scoring, treating a direct dep on a network-listening service as fully
reachable:

```
0.35×61.0 = 21.35
0.25×84.6 = 21.15      EPSS 84.627th percentile
0.20×100  = 20.00
0.15×100  = 15.00
0.05×100  =  5.00      NO_SAFE_VERSION
            ------
              82.5  →  83   ← ranks #1 in the portfolio
```

With reachability applied (component not in artifact → 20; not exposed → 20):

```
21.35 + 21.15 + 4.00 + 3.00 + 5.00 = 54.5 → 55
```

28 points, and the project drops from 1st to 3rd. Siblings: CVE-2026-42154
(remote-read endpoint, server-side) → 52, CVE-2026-42151 (azuread remote-write
config) → 40, CVE-2026-40179 → 30, CVE-2026-44903 (flag-gated legacy UI) → 27.

Project roll-up: 55 + 1.5×1 (CVE-2026-42154 at 52 is the only other ≥50) = 56.5 → 56.

## Anchor 4 — transitive, build-time only

**`web-app` / CVE-2026-41305 in `postcss 8.4.31`** at depth 2. XSS requires the
app to parse user-submitted CSS and re-stringify it into a `<style>` tag; no such
path exists → Reachability 20. `postcss` appears only in the Next.js build
chain's lockfile — it never runs in production → Exposure 20, not 100.

```
0.35×61.0 = 21.35
0.25×10.7 =  2.67      EPSS 10.685th percentile
0.20×20   =  4.00
0.15×20   =  3.00      build-time only
0.05×0    =  0.00
            ------
              31.02 →  31
```

"Internet-facing web app" describes the *project*; Exposure scores the
*dependency's* runtime. A build-chain package in a web app is build-time.
Scoring the project instead of the package cost 12 points here.

## Anchor 5 — dev-only dependency

**`scanner-mcp` / CVE-2025-71176 in `pytest 8.4.2`** (direct, test-only). Local
tmpdir permissions. Fix requires 8.4.2 → 9.0.3, a major bump.

```
0.35×68.0 = 23.80
0.25×3.9  =  0.97      EPSS 3.858th percentile
0.20×20   =  4.00      dev/test-only
0.15×20   =  3.00      build/test-time only
0.05×40   =  2.00      major bump
            ------
              33.77 →  34
```

CVSS 6.8 landing at 34 is correct and is the point of the rubric.

## Licensing anchors

**`web-app`** — 16 flags: LGPL-3.0-or-later on prebuilt native image-processing
addons (dynamically loaded, not statically linked), MPL-2.0 on the web
framework, one CC-BY-SA-4.0 policy conflict. Private repo, SaaS deployment.

Those 16 rows collapse to **three** findings: the 14 LGPL rows are 14
per-architecture variants of one image-processing dependency, and the other two
are one row each. This is the case SKILL.md step 5 collapses and step 6 refuses
to count as volume. It is also the case that exposed the truncation trap: at
`top_issue_count=15` the page returned all 14 LGPL duplicates plus the MPL row
and dropped the CC-BY-SA-4.0 `policy_conflict` — the only non-`policy_flag`
finding the project had, and the one that most needed reading.

```
Copyleft 60 (weak: LGPL/MPL) × (Linkage 50 / 100) × 0.8 = 24
Distribution 20 (SaaS, private) × 0.2                   =  4
                                                          --
                                                          28
```

**`scanner-mcp`** — 15 flags: GPL-2.0-only discovered in a direct dev-tool
dependency, GPL/LGPL/CPL in a transitive dev dependency. Public repo, but
neither package is bundled into anything distributed.

These 15 rows collapse to **three** findings, on three packages. The fan-out
here is the other axis from `web-app`'s: one multi-licensed package alone
raised 11 rows — GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only,
GPL-3.0-or-later, three LGPL-2.1/3.0 variants, two exception-qualified forms
and CPL-1.0 — which is one dependency and one linkage decision, not eleven.

```
Copyleft 100 (strong GPL) × (Linkage 10 / 100) × 0.8 = 8
Distribution 100 (public) × 0.2                      = 20
                                                       --
                                                       28
```

Both land at 28 by different routes — strong copyleft that ships nowhere, and
weak copyleft that ships dynamically. Neither project's score is set by
licensing: `web-app` takes 43 from postcss, `scanner-mcp` takes 34 from pytest.

An additive formula would have scored `scanner-mcp` at 64 and made a linter the
org's third-biggest problem. This is why Linkage multiplies.

## Remediation rollup

18 vulnerability findings across the portfolio, four bumps:

| Bump | Projects | Clears |
|---|---|---|
| `mcp` 1.6.0 → 1.28.1 | `memory-service`, `code-mcp` | 10 — both Critical scores |
| `prometheus` v0.51.2 → v0.311.3 | `metrics-exporter` | 3 of 5; two are `NO_SAFE_VERSION` and all five unreachable |
| `pytest` → 9.0.3 | `code-mcp`, `scanner-mcp` | 2 |
| `postcss` → 8.5.10 (npm override) | `web-app` | 1 |

Recommended first: `mcp`. One dependency, two projects, retires the 93 and the 81.

## The assumption that was wrong

The first pass at this portfolio (same day, before the repos were read) assumed
stdio for all MCP servers and scored the *project's* exposure rather than the
*dependency's*. Both assumptions were stated in the report with deltas, which is
the only reason they were cheap to correct. Net effect once verified:

| Project | Assumed | Verified | Why |
|---|---|---|---|
| `memory-service` | 81 | **93** | defaults to streamable-http behind a public Ingress, not stdio |
| `web-app` | 43 | **31** | postcss is build-chain, not runtime |
| `code-mcp` | 81 | 81 | stdio assumption happened to be right |
| `metrics-exporter` | 56 | 56 | import-surface reasoning confirmed by grep |

The ranking's top two swapped. **Read the transport and the import surface
before scoring whenever the repo is reachable** — it is a handful of greps and
it is the difference between a defensible number and a plausible one.
