---
name: fossa-license-review
description: Run a customer-facing, obligation-oriented license audit of a FOSSA project — classify every license by what it actually obligates in this customer's distribution model and hand back an action list. Use when asked for a license audit, to review licensing issues, "can we ship this", any GPL/AGPL/copyleft question, license compliance for a release, or an M&A / due diligence licensing review.
---

# fossa-license-review

Read a project's licensing findings and full dependency list out of FOSSA,
establish how the customer actually distributes their software, classify every
license by the obligations it creates rather than by its name, and report which
findings require action for this customer and which are noise.

**Why this workflow exists:** FOSSA tools return license *names*. "GPL-3.0" is
not a verdict; it is an input to one. The same license is a shipping blocker in
a publicly distributed binary and a non-event in a SaaS backend, and a linter
with a copyleft license usually obligates nobody. The judgment that converts
names into obligations lives here, not in the API.

**The honest framing, stated up front and never dropped:** the obligation
classes below are settled, mainstream readings of these licenses, but the
distribution model and linkage facts they key off are *your assessment of the
customer's situation*, gathered in step 1. State that basis in the report. A
finding classified against a guessed distribution model is worse than an
unclassified one.

For a ranked score across a portfolio instead of a per-project obligations
audit, use [[fossa-suggest-score]] — same copyleft tiers, quantitative track.
This skill is the qualitative audit. Ask which project if it isn't named.
Everything else below is procedure.

## 1. Establish the distribution model first

Everything downstream depends on this, so ask — or infer from the repo,
deployment config, or what the user has already said — before pulling a single
finding. Four models, in descending order of how much they obligate:

1. **Publicly distributed** — binary, app store package, installer, npm/PyPI
   package, embedded firmware. Every distribution-triggered obligation is live.
2. **Distributed to customers** — on-prem installs, appliances, SDKs shipped
   under contract. Same obligations as public distribution; the audience is
   smaller but the trigger is identical.
3. **SaaS-only** — the code runs on the customer's servers and only its
   *output* reaches users. GPL, LGPL, and MPL obligations do **not** reach this
   deployment, because they trigger on distribution of the software itself.
   **AGPL is the exception that does reach SaaS — flag it loudly.** Its
   network-interaction clause is exactly the case the license was written for.
4. **Internal-only** — tooling, services, and scripts that never leave the
   organization. Almost nothing fires; attribution obligations technically
   attach to copies but there is no external audience.

Also establish, where knowable, **how copyleft dependencies are linked**:
static linking, dynamic linking, or a separate process. It decides LGPL
outcomes — statically linked LGPL in a distributed binary obligates you to
enable relinking (ship object files or use dynamic linking); dynamically linked
or process-separated LGPL asks only for attribution and the LGPL'd source.
When the repo is on disk, this is often a manifest or build-config read, not a
judgment call. When it is not knowable, pick the likelier default, say so, and
state what changes if it is wrong.

## 2. Pull the findings

Resolve the project first — never guess a locator:

```
fossa_list_projects(title=...)
```

Take the project locator and `latestRevision.locator` from the result (or a
specific revision from `fossa_list_project_revisions` if the user named one).
Then, in parallel:

```
fossa_project_posture(project_locator=..., revision_locator=..., top_issue_count=15)
fossa_list_dependencies(revision_locator=..., count=100)
```

Posture gives the per-category counts and the top licensing issues in one call.
If the licensing count exceeds what posture returned, page the full set:

```
fossa_list_issues(category="licensing", status="active", scope_type="project",
                  project_locator=..., revision_locator=...)
```

**Project scope requires `revision_locator` as well as `project_locator`**, or
the call fails validation. Note the categories are `licensing`,
`vulnerability`, `quality` — there is no `security` category.

The dependency list is not optional. Licensing *issues* only exist where a
FOSSA policy flagged something; the audit covers every license in the
revision, including the ones the policy waved through. `fossa_list_dependencies`
takes the **full revision locator** (it has no project_locator parameter) and
returns each dependency with its licenses. Useful filters while working:
`depths=["direct"]` / `["transitive"]`, `has_issues=["hasLicensingIssues"]`,
`licenses=[...]` to pull all packages under one license, and
`include_copyright=true` when attribution text will be needed. Page until the
list is exhausted — an audit of page one is not an audit.

For any single package that needs a closer look — license text, resolution
notes, copyright — use the exact locator the list returned:

```
fossa_get_dependency(revision_locator=..., dependency_revision_locator=...)
```

A `state: "analysis_in_progress"` response (HTTP 202 underneath) means the scan
is still running; say so and do not audit a partial dependency list.

## 3. Classify every license by obligation class

Group by obligation class, not by name. The classes, aligned with the copyleft
tiers in [[fossa-suggest-score]]:

| Class | Licenses | What it obligates |
|---|---|---|
| **Strong copyleft** | GPL-2.0, GPL-3.0, AGPL-3.0 | Distributing the work (or, for AGPL, serving it over a network) obligates releasing the combined work's source under the same license. GPL-2.0 and GPL-3.0 are mutually incompatible — note which one. |
| **Weak copyleft** | LGPL, MPL, EPL, CDDL | File- or library-scoped: modifications to the covered code must be released, but the rest of the work stays yours. LGPL adds the relinking requirement for static linking. |
| **Permissive with attribution** | MIT, BSD-2/3-Clause, Apache-2.0, ISC | Ship the license text and copyright notices. Apache-2.0 additionally requires preserving the NOTICE file if upstream has one, and carries an explicit patent grant with a retaliation clause — relevant in M&A review. |
| **Public-domain-equivalent** | CC0, Unlicense, 0BSD | Nothing. Exclude from the action list entirely. |
| **Unknown / custom / unlicensed** | no license found, custom text, "SEE LICENSE IN ..." | **The dangerous bucket.** No license means no grant — treat as all-rights-reserved until resolved. A custom license means someone has to read it. Never classify this bucket as permissive because the package "looks like" MIT-adjacent. |

Two situations that cut across the classes:

- **Dual-licensed packages** (e.g. GPL-2.0 OR MIT, or commercial-or-copyleft
  offerings). The customer must *elect* one and document the election. FOSSA
  may list both licenses on the dependency; the finding is "no documented
  election", and the usual remediation is electing the permissive option in
  writing.
- **License change on upgrade.** A version bump can cross a relicensing
  boundary — BUSL, SSPL, and Elastic-2.0 conversions are the common ones.
  When a remediation elsewhere in the report recommends upgrading a package,
  check the target version's license before recommending it, and flag any
  dependency currently pinned just below a relicensing boundary.

## 4. Cross obligation class with distribution model and role

This is the step that produces the audit. For each finding, three facts decide
whether it fires:

1. **Distribution model** (step 1). Strong and weak copyleft obligations
   trigger on distribution — so under SaaS-only or internal-only, GPL, LGPL,
   MPL, EPL, and CDDL findings are noise *unless the license is AGPL*, which
   fires under SaaS. Attribution obligations follow distribution too: no
   distribution, no NOTICE file to ship.
2. **Dependency role.** Runtime vs dev/build-only (`depths` and the manifest
   tell you; a GPL linter or test framework never enters the shipped artifact
   and is noise in every model). Direct vs transitive changes who can fix it,
   not whether it fires — a transitive GPL in a shipped binary fires exactly
   as hard, but the remediation is an exclusion or an upstream issue rather
   than a swap.
3. **Linkage** (step 1), for weak copyleft in a distributed artifact: static
   LGPL → relinking obligation (action); dynamic or separate-process LGPL/MPL →
   attribution plus source availability for the covered library only (usually
   a small action, sometimes already satisfied).

Everything that survives this cross gets a remediation from the standard menu:
**relicense** (elect the permissive half of a dual license, or buy the
commercial license), **replace** (swap the package for a
permissive-equivalent), **isolate** (move the copyleft component behind a
process boundary — a separate service or CLI invocation — so the combined-work
question never arises), or **add attribution** (license texts, copyright lines,
Apache NOTICE contents — the cheap and common case). The unknown bucket gets
**resolve**: identify the actual license from the package's repository, contact
the author, or remove the package; it cannot be closed from FOSSA data alone.

## 5. Report

Lead with the verdict in one sentence: N licensing findings, M require action
for **this** distribution model, stated by name ("SaaS-only, so M of N").

Then, in order:

- **The action table** — package, license, obligation class, the specific
  obligation, why it fires *here* (which distribution/role/linkage fact
  triggered it), and the remediation options from step 4 with a recommended
  one. Order by severity of consequence, strong copyleft first.
- **The noise, explained in one paragraph.** Not a table — one paragraph
  saying why the remaining findings do not fire for this customer ("the four
  LGPL and two MPL findings do not reach a SaaS deployment; the GPL-2.0 flag
  is on a build-only linter"). This paragraph is what stops the customer
  re-litigating the same findings next quarter, so write it to be quoted.
- **Unknowns as their own block**, never mixed into either list above, each
  with concrete resolution steps and the statement that until resolved it is
  treated as all-rights-reserved.
- **The stated basis**: the distribution model used, whether it was told or
  inferred, the linkage assumptions, and what flips if any of them is wrong.

Where the action list includes attribution obligations, hand off to
[[fossa-attribution]] to generate the NOTICE file — it drives
`fossa_get_attribution_report` and is the follow-on for exactly the
attribution rows this review surfaces. Do not inline a half-built NOTICE file
into this report.

## Traps

- **`fossa_list_issues` with project scope fails without `revision_locator`.**
  Both locators, every time; take the revision from `latestRevision.locator`.
- **Discovered vs declared license mismatches.** FOSSA can surface a license
  discovered in the package's files that differs from what the manifest
  declares. When a dependency shows a surprising license, pull
  `fossa_get_dependency` with `include_license_text=true` and check the
  resolution notes before classifying — the audit classifies what is actually
  in the code, and a mismatch is itself a finding worth reporting.
- **"Unlicensed" is not "permissive".** The absence of a flagged issue on an
  unlicensed package means the FOSSA policy didn't flag it, not that anyone
  granted rights. No license, no grant.
- **SaaS is not a blanket "safe".** The SaaS carve-out is real for GPL, LGPL,
  and MPL and void for AGPL. A report that says "we're SaaS, so copyleft
  doesn't apply" with an AGPL dependency in the list is wrong in the way that
  gets noticed later.
- **Linters and build tools with copyleft licenses are usually noise.** They
  never enter the shipped artifact. Classify them, put them in the noise
  paragraph, and do not let them pad the action count — sixteen GPL flags on
  dev tooling is one sentence, not sixteen rows.
- **Issue depth and dependency depth use different vocabularies.** Issues
  filter on `depths=["direct","deep"]`; dependencies on
  `depths=["direct","transitive"]`. Mixing them fails validation.
- **The dependency list pages.** Default `count` is 20. An obligations audit
  that read one page has audited 20 packages, not the project.

## Scope

This skill assesses and recommends. It is not legal advice: it applies the
mainstream reading of each license to the facts you gathered, and decisions
with real legal exposure — an AGPL finding in a shipped product, an M&A
representation — should go to counsel with this report as the input, not
instead of it. That is said here once and not repeated per finding.

It reads FOSSA and does **not** write to it — ignoring issues, concluding
licenses, and policy changes happen in FOSSA by the user. It does **not**
modify the customer's code; when the remediation is a replacement or an
isolation, recommend it and let the user decide, raising it as its own task
rather than editing their code here.
