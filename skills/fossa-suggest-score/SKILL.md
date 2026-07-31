---
name: fossa-suggest-score
description: Rank FOSSA projects by remediation urgency using a custom impact risk score that adds reachability and exposure to CVSS and EPSS. Use when asked which projects need remediation, how to prioritize FOSSA findings, to build or suggest a custom risk/impact score, to triage a FOSSA portfolio, or whenever FOSSA severity is being questioned as a prioritization signal.
---

# fossa-suggest-score

Read a FOSSA org's open issues, score every finding on a rubric that CVSS alone
cannot express, roll the findings up per project, and hand back a ranked
remediation list plus the version bumps that actually clear it.

**Why this workflow exists:** CVSS ranks the *vulnerability*. It does not know
whether the vulnerable code path is compiled into your binary, whether the
service listens on a network, or whether the package is a test-only dependency.
In a real portfolio those three facts move findings by 25–30 points and reorder
the list. The score below is CVSS and EPSS — both straight out of FOSSA — plus
three judgment terms that you must gather and must label as judgment.

**The honest framing, stated up front and never dropped:** the reachability and
exposure terms are *your assessment*, not FOSSA data. They carry 35% of the
weight between them. Every report states the assumption explicitly, and states
what the ranking becomes if the assumption is wrong. A score presented as if it
came out of FOSSA is worse than no score.

Ask which org or project set if it isn't obvious. Everything else is procedure.

## 1. Inventory

```
fossa_list_projects(count=50, sort="issues-total_desc")
```

That one call gives you titles, locators, `latestRevision.locator`, per-category
issue counts, and `public`. Projects with `issues.total == 0` need no
remediation — name them as clean and drop them; do not spend calls on them.

Never guess a locator from a repo name. If the user named projects informally,
resolve each with `fossa_list_projects(title=...)` first — but `title` is a
**substring match that can return several projects**, not a lookup. Read the
result before picking; if more than one comes back, disambiguate with the user
rather than taking the first row.

**Deduplicate the inventory before scoring it.** One repository can appear as
several FOSSA projects — a CLI/integration scan under `git+<host>/<org>/<repo>`
and a separately uploaded scan of the same tree under
`custom+<orgId>/<something>`, each with its own title. Observed live: two
projects at the **same commit SHA**, returning **the same issue ids**, with
issue counts that differ only because the two scans included different dev
dependencies. Scoring both puts one codebase in the ranking twice and
double-counts the portfolio's remediation work.

Detect it from step 1's own output — same `version` (the commit SHA) and the
same repo visible in `id`/`title`/`url` — then pick the project the user
actually operates against (usually the continuously-scanned `git+` one), score
that, and say in the report which duplicate you set aside and why. Do not merge
their issue lists: they are the same issues, not additional ones.

## 2. Pull posture for every project that has issues

```
fossa_project_posture(project_locator=..., revision_locator=..., top_issue_count=15)
```

**Issue these in parallel — one message, one call per project.** They are
independent and the round-trips dominate the runtime. Parallel does not mean
unbounded: at `top_issue_count=15` a single posture response measured 18–46 KB
(roughly 4.6k–11.5k tokens) per project on a small org, so batch about six at a
time and let each batch land before sending the next. Step 1 happily lists 50
projects; 50 postures in one message will not fit.

`project_posture` is the right tool here: one call returns the CVE detail, CVSS,
**EPSS score and percentile**, `remediation` distances, dependency depth, and the
direct-dependencies-with-issues rollup. Reaching for `fossa_list_issues` per
category instead costs 3× the calls for less data.

`top_issue_count=15` is enough for the vulnerability list in most projects.
**Truncation is silent, and the truncated issues are not a random sample.** The
issue payload inside posture carries only an `issues` array — there is no
`total` field — so the response cannot tell you it dropped anything. Reconcile
the returned count against the per-category counts from step 1 (and against
posture's own `issue_counts`) every time, and say in the report which
categories you saw in full.

When a category is truncated, **do not treat the retained rows as
representative of it.** Posture sorts licensing and quality by
`created_at_desc`, which sorts by nothing you care about. Observed live on a
16-licensing-issue project: the 15 returned rows were all `policy_flag`, 14 of
them the *identical* LGPL flag on 14 per-architecture variants of one npm
package, and the row that fell off the end was the project's only
`policy_conflict` — the single highest-signal licensing finding it had. Redundant
copies were kept and the outlier was dropped.

So when step 1 shows more licensing issues than `top_issue_count`, re-pull that
category in full rather than sampling it:

```
fossa_list_issues(category="licensing", scope_type="project",
                  project_locator=..., revision_locator=..., count=100)
```

It is one extra call and it is the difference between scoring a license family
and scoring a packaging artifact.

**Project scope on `fossa_list_issues` requires `revision_locator` as well as
`project_locator`**, or the call fails validation. Only reach for it when you
need issues `project_posture` truncated away.

## 3. Establish reachability and exposure

Do this **before** scoring. This is the step that earns the skill its keep, and
it is not answerable from the CVE text.

For each vulnerable package, answer three questions:

1. **Is the vulnerable code path in the shipped artifact?** A Go binary that
   imports `prometheus` as a metrics library does not compile in the Prometheus
   web UI, the `/api/v1/read` endpoint, or the remote-write config — so the
   CVEs in those components are unreachable no matter how high the CVSS. Read
   the advisory for *which component* is affected, then check whether this
   project uses it.
2. **Is it a runtime or a dev/test dependency?** `pytest`, `ruff`, linters,
   build tooling — these never reach production and never reach a customer.
   They score low and they should.
3. **What transport / deployment does this thing actually run in?** An MCP
   server over stdio is untouched by CVEs in SSE, WebSocket, and streamable-HTTP
   transports. An MCP server over HTTP is fully exposed to all of them. Same
   package, same version, ~25 points apart.

Where the answer is knowable, know it: read the repo's manifest, entry point, or
deployment config. Establishing whether it is knowable is its own step, and the
skill cannot do it for you — a FOSSA locator such as
`git+<host>/<org>/<repo>` names a remote, not a path. Check for a local
checkout of `<repo>` under the user's source root before concluding the answer
is unavailable, and ask where their checkouts live if you cannot find one.

When a checkout is there, **search the whole repository, not just `src/`, and
include the deployment manifests.** Layout is not uniform and the answer moves
between the two: one project observed live sets its transport default in
`src/<pkg>/config.py`, another sets it in `<subdir>/src/<pkg>/server.py` *and*
overrides it with an env var in a Kubernetes Deployment. A grep scoped to
`src/` returns nothing for the second and sends you to the default you were
told not to assume:

```bash
grep -rn -i 'transport' <repo> \
  --include='*.py' --include='*.go' --include='*.ts' --include='*.js' \
  --include='*.toml' --include='*.yaml' --include='*.yml' | grep -v '/\.venv/'
```

Where the deployment config and the code default disagree, **the deployment
config wins** — it is what actually runs.

Where it is not knowable — transport is the usual one — **pick the likelier
default, score with it, and surface it as the named assumption with the
delta.** Do not silently assume, and do not refuse to score.

Group findings by **package**, not by CVE, while you do this. Five CVEs in one
dependency is one version bump and one reachability judgment.

## 4. Score each vulnerability finding

```
CIRS = 0.35·Severity + 0.25·Exploit + 0.20·Reachability + 0.15·Exposure + 0.05·FixFriction
```

Every term is 0–100. The result is 0–100.

| Term | Source | Scale |
|---|---|---|
| **Severity** | FOSSA `cvss` × 10 | 0–100 |
| **Exploit** | FOSSA `epss.percentile` × 100 | 0–100 |
| **Reachability** | judgment, step 3 | 100 direct runtime dep · 70 transitive runtime · 20 dev/test-only **or** vulnerable component not in the shipped artifact |
| **Exposure** | judgment, step 3 | 100 network-listening service · 50 local-only service · 20 build/test-time only |
| **FixFriction** | FOSSA `remediation.partialFixDistance` | 0 `PATCH` or `MINOR` · 40 `MAJOR` · 100 `partialFix` is `NO_SAFE_VERSION` |

Use **`epss.percentile`, not `epss.score`.** Both are 0–1, so both need the
×100; the difference is what they mean. The raw score is a tiny probability
(0.00205) that contributes nothing on a 0–100 scale; the percentile is the
comparative signal you actually want, and the gap between them is large — 0.0598
raw is the 92.6th percentile.

**`remediation` is an object, not a string, and FixFriction reads exactly one
half of it.** The live shape is
`{partialFix, partialFixDistance, completeFix, completeFixDistance}`, where
`partialFix` is the version that clears **this** CVE and `completeFix` the
version that clears **every** CVE in that package. FixFriction scores the
finding, so it reads the `partial*` pair. Reading `completeFix` instead is a
silent wrong answer in both directions: it flattens every CVE in a package to
one friction value, and on a package whose worst CVE has no fix it scores 100
against findings that have a perfectly good minor bump — observed live on a
package where three of five CVEs had `partialFix` set and `completeFix` was
`NO_SAFE_VERSION` for all five.

Two shape traps that bite code more than prose: when a fix field is
`NO_SAFE_VERSION` the matching `*Distance` key is **absent from the object
entirely**, so read it with a default rather than by subscript; and the
distance vocabulary includes `PATCH`, which is not in the original three-value
rubric and scores 0 alongside `MINOR`.

**State scores as integers, rounded half-up, once, at the end.** Round the
final CIRS — not the individual weighted terms — and round the project roll-up
in step 6 the same way. Fixing the rule matters less than having one: bands are
15 points wide, so a ±1 rounding difference almost never moves a project, but
two readers reporting different integers for the same finding undermines the
whole exercise. The anchors in `references/calibration.md` predate this rule
and round two roll-ups down; see the note there.

FixFriction is deliberately the smallest weight. It does not make a finding more
dangerous; it makes the finding more likely to sit unfixed, which is a real but
second-order concern. Never let it dominate.

## 5. Score licensing on its own track

Licensing findings are not vulnerabilities and the vulnerability formula
mis-scores them: they carry no `cvss`, no `epss` and no `severity` at all, only
`type`, `license`, `details` and `source`. Run them separately:

```
LIS = Copyleft × (Linkage / 100) × 0.8 + Distribution × 0.2
```

| Term | Scale |
|---|---|
| **Copyleft** | 100 strong (GPL, AGPL) · 60 weak (LGPL, MPL) · 20 permissive-with-notice |
| **Linkage** | 100 distributed and statically linked · 50 distributed, dynamically linked or separate process · 10 dev/build-only, never distributed |
| **Distribution** | 100 publicly distributed software · 50 distributed to customers · 20 internal or SaaS-only |

Linkage **multiplies** rather than adds, on purpose. A GPL-2.0 discovered
license in a linter that ships to nobody is not a 100-point problem, and an
additive formula makes it one.

Note what does and does not trigger an obligation: LGPL and MPL do not reach a
SaaS deployment, and dynamically-loaded native addons are not static linking.
AGPL is the exception that does reach SaaS — flag it loudly if you see it.

**Collapse licensing findings before scoring them, the same way step 3 groups
vulnerabilities by package.** FOSSA emits one issue per (package, license), and
both halves of that key fan out:

- *One package, many licenses.* A multi-licensed package produces a flag per
  alternative — observed live, one package alone raised 11 flags spanning
  GPL-2.0-only, GPL-3.0-or-later, several LGPL variants, exception-qualified
  forms and CPL-1.0. That is one dependency and one decision, not eleven.
- *One license, many packages.* Platform-specific binary variants each raise
  their own flag — observed live, 14 identical LGPL-3.0-or-later flags across
  14 per-architecture builds of a single npm dependency. One upstream project,
  one linkage judgment, one remediation.

Score the collapsed finding once, and carry the fan-out count as context. It is
not evidence of 14 problems.

**Read the issue `type`, not just the `license`.** `policy_flag` is FOSSA
saying the policy flags this license; `policy_conflict` is FOSSA saying the
license's terms conflict with the policy, which stays open until someone
reconciles it in FOSSA and is the stronger signal of the two. Score a
`policy_conflict` at least one Copyleft tier above where the license name alone
would put it, and never let it be the finding you dropped to a truncated page
(step 2). For the obligation analysis behind a conflict, hand off to
[[fossa-license-review]] rather than deriving it here.

**Project score = max(highest vulnerability CIRS, highest licensing LIS).** Quality
findings (outdated deps, native-code risk) do not score; report them as context.

## 6. Roll up to the project

```
Project CIRS = highest issue score + min(10, 1.5 × count of other issues scoring ≥ 50)
```

The cap matters. Without it, a project with sixteen near-identical LGPL flags
outranks one with a 92nd-percentile RCE, and that is exactly the failure this
skill exists to prevent. Volume is a tiebreaker, never the driver.

**Count collapsed findings, not raw issue rows.** The cap alone does not save
you: the fan-out described in step 5 is real and large enough to max the bonus
out of a single dependency, so a project can take the full +10 for one
LGPL-flagged package that happened to ship 14 architecture variants. Deduplicate
first, then count. The same applies to vulnerabilities — five CVEs in one
package are five findings and score as five, but only because each is a
distinct advisory; two rows for the *same* advisory on two variant packages are
one.

| Band | Score |
|---|---|
| Critical | ≥ 75 |
| High | 60–74 |
| Medium | 40–59 |
| Low | 20–39 |
| Informational | < 20 |

Two projects that depend on the same package at the same version **should tie**.
Do not manufacture a difference to break it — say they tie and why, then break
it on deployment exposure if you actually know it differs.

## 7. Report

Lead with the ranked table: project, FOSSA issue counts as L/S/Q, worst raw
CVSS, peak EPSS percentile, and the CIRS with its band. Showing the raw inputs
next to the score is what lets the user check your judgment rather than take it.

Then, in order:

- **The formula and both rubric tables**, with each term marked FOSSA or
  judgment. The user asked for a *suggested* score; they cannot adopt or amend
  one they cannot see.
- **The assumptions**, called out as their own block, each with its delta:
  "scored as stdio; if any runs over HTTP these four CVEs go from ~40 to ~65 and
  the project moves to 91."
- **Per-project detail**, a short paragraph each, leading with whatever the score
  turned on.
- **The remediation table, grouped by package.** This is the payoff and it goes
  last because it is what the user acts on: bump, projects affected, issues
  cleared. Close by naming which single bump to do first and why.

**Say when the score disagrees with CVSS, and say it as a finding.** "Raw CVSS
ranks this first at 83; reachability drops it to 56 because four of five CVEs
are in components an exporter binary does not compile in" is the most valuable
sentence in the report. Burying it wastes the whole exercise.

## Traps

- **`customRiskScore` is `null` on every issue until someone configures it.**
  Check it — if FOSSA already has custom scores, the user wants those reconciled
  with your suggestion, not overwritten by it. If it is null everywhere, say so:
  it tells them nothing custom is configured today. Depending on the branch, the
  server may also register tools that *write* a custom risk score back to FOSSA;
  their existence does not change this skill's Scope. Offer the write as a
  separate, explicitly-requested step, never as the tail of a scoring run.
- **Nothing here is stable across a re-scan.** Every number in the report is a
  reading of one revision at one moment: issue counts move when a scan
  reclassifies dev dependencies, `remediation` moves when upstream publishes,
  and EPSS percentiles move daily. Date the report and name the revision
  locators it was computed from, so a reader who gets different numbers next
  week can tell whether the portfolio changed or the inputs did.
- **Do not present judgment terms as FOSSA output.** Reachability and exposure
  are 35% of the weight and neither exists in the API.
- **Exposure scores the dependency's runtime, not the project's.** A build-chain
  package inside an internet-facing web app is build-time (20), not
  network-listening (100). Getting this backwards inflated a finding by 12 points
  on 2026-07-31.
- **Read the transport before scoring it.** Two MCP servers on the identical
  package version scored 28 points apart on the same CVE, decided by a one-line
  default. When the repo is on disk this is a grep, not a judgment call.
- **Do not skip clean projects silently.** "Five of ten have issues; the other
  five are clean" is information.
- **Weight sums to 1.0.** If you tune the weights for a user's environment —
  reasonable, and they may ask — re-normalize, and restate the changed formula in
  the report rather than quietly scoring against a different rubric than the one
  you printed.

## Scope

This skill reads FOSSA and produces an assessment. It does **not** write to
FOSSA, and it does **not** change the target repositories. When the fix is a
version bump — it nearly always is — recommend it and let the user decide; raise
it as its own task rather than editing their code here.

When the bump cannot happen — no owner, no build, legacy code nobody will touch
— a compensating control is the remaining option, and [[fossa-protect]] turns
these same findings into WAF sensors. It is a different deliverable, not a
continuation of this one: do not start it without being asked.

Worked examples with full arithmetic, for calibrating new scores against past
ones: `references/calibration.md`.
