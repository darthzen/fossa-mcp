---
name: fossa-vuln-export
description: Export a FOSSA project's vulnerability findings as a normalized OSV or CycloneDX 1.6 VDR document, and diff them against another scanner's output. Use when asked to export vulnerabilities, produce a VEX/VDR/OSV/CycloneDX payload, compare FOSSA with Snyk/Trivy/Grype or another scanner, run a vendor comparison, or turn FOSSA findings into a standard machine-readable format.
---

# fossa-vuln-export

Read a project's vulnerability findings out of FOSSA, join each one to the
dependency it lives in, and emit a document in a standard format — OSV by
default, CycloneDX 1.6 VDR on request — so the findings can be compared
mechanically against another scanner's output. Given another vendor's export,
normalize both sides to the same keys and report where they agree, where they
differ, and where they disagree about severity.

**Why this workflow exists:** every scanner invents its own JSON, so "how does
FOSSA compare to Snyk" usually degenerates into two people reading two files
and arguing about counts. Normalizing both sides to (package identity,
vulnerability identity) keys turns that argument into a join. The join is only
honest if the normalization is: aliases resolved, versions treated
consistently, scope differences named. This skill does the normalization and
names the residual judgment calls instead of burying them.

**The honest framing, stated up front and never dropped:** a diff of two
scanner outputs measures *detection differences*, not *correctness*. A
"FOSSA-only" finding is not automatically a win and a "vendor-only" finding is
not automatically a miss — either can be a true positive the other scanner
scoped out, a version-range disagreement, or an alias the normalization failed
to resolve. Spot-check before you characterize, and present counts with their
caveats attached.

This skill exports and compares facts. When the user wants the findings
*ranked* — which project or package to fix first — that is [[fossa-suggest-score]],
which layers reachability and exposure judgment on top of the same data. Do
not blend the two: an export contains only what FOSSA returned.

Ask which project (and, for mode 2, for the vendor file) if it isn't obvious.
Everything else is procedure.

## 1. Resolve the project

```
fossa_list_projects(title=...)
```

Never guess a locator from a repo name. The listing gives you the exact
`locator` (e.g. `git+github.com/acme/widget`) and `latestRevision.locator`
(e.g. `git+github.com/acme/widget$abc123`), and you need both downstream. If
the user wants a specific revision rather than the latest, resolve it with
`fossa_list_project_revisions(project_locator=...)`.

When the target is a criterion rather than a name — "the project with the
most vulnerability findings" — sort the listing instead of sampling:
`fossa_list_projects(sort="issues-security_desc")`. Mind the naming mismatch:
project listings call this category `security` (the `issues.security` count,
sort key `issues-security_desc`) while the issue endpoints call the same
category `vulnerability`.

Keep the **full** revision locator (`project$revision`). The dependency
endpoints take it verbatim as a path parameter; the issue endpoints accept
either form. Passing a bare revision id to `fossa_list_dependencies` is a 404.

For a set of projects, resolve them all first, then run the per-project steps
below — the FOSSA calls for different projects are independent, so issue them
in parallel, one message.

## 2. Pull the vulnerability findings

```
fossa_project_posture(project_locator=..., revision_locator=..., top_issue_count=25)
```

One call returns the per-category `issue_counts`, the top vulnerability issues
sorted by severity with CVE detail, CVSS, **EPSS score and percentile**,
`remediation` distances and dependency depth, plus the
direct-dependencies-with-issues rollup. Prefer it over assembling the same
picture from N `fossa_list_issues` calls.

**`top_issue_count` is capped at 25.** The cap is enforced by input
validation, so "set it high" means exactly 25, and a project with more than 25
vulnerabilities *will* be truncated. Detect it mechanically: compare
`issue_counts.vulnerability` against the length of
`top_vulnerability_issues`. If the count is larger, page the rest:

```
fossa_list_issues(category="vulnerability", scope_type="project",
                  project_locator=..., revision_locator=...,
                  sort="severity_desc", count=100, page=1)
```

Increment `page` until you hold `issue_counts.vulnerability` issues. Both
`project_locator` **and** `revision_locator` are required for project scope —
omit either and the call fails validation before it ever reaches FOSSA.

**The category is `"vulnerability"`, not `"security"`.** The enum is
`licensing | vulnerability | quality`; `"security"` is rejected. Licensing and
quality issues are not vulnerabilities and do not belong in this export —
if the user wants them too, that is a separate document, not extra rows.

If either call reports `analysis_state: "in_progress"` (or `state:
"analysis_in_progress"`), the revision is still being analyzed and any export
would be partial. Say so and ask whether to wait or export the partial state
with a prominent caveat — never export partial data silently.

## 3. Join each finding to its dependency

Each vulnerability issue names the affected package as a FOSSA dependency
locator (`fetcher+package$version`, e.g. `npm+lodash$4.17.20`) — where it
lives depends on the payload. In posture's `top_vulnerability_issues` (and
`fossa_list_issues` records) it is the issue's `source.id`; the `revisionId`
visible there sits under `projects[]` and is the **project's** revision, not
the dependency's — joining on it silently mismatches every finding. The field
is named `revisionId` only in the nested issues of
`direct_dependencies_with_issues` / `fossa_list_dependencies` records. Verify
against the first live response rather than trusting this note, then join on
the locator string.

Pull the dependency records for the revision:

```
fossa_list_dependencies(revision_locator="git+github.com/acme/widget$abc123",
                        has_issues=["hasIssues"], count=100)
```

- `revision_locator` must be the **full** `project$revision` form.
- `has_issues=["hasIssues"]` restricts the page to dependencies that carry
  issues, which is exactly the join set. Page if more than 100 qualify.
- The record gives you the dependency's exact locator, title, and depth —
  enough for purl construction and the `affects` entries.

Use `fossa_get_dependency(revision_locator=..., dependency_revision_locator=...)`
— with the exact locator string from the listing — only when a specific
dependency needs its richer detail record; the listing covers the common case.

If an issue's locator matches nothing in the dependency listing, do not drop
the finding: emit it with the package identity parsed from the locator itself
and note the failed join in the report.

## 4. Construct purls from FOSSA locators

FOSSA locators are `fetcher+package$revision`. The purl is mechanical for
registry-backed fetchers and judgment-laden for the rest:

| FOSSA fetcher | purl type | rule | example |
|---|---|---|---|
| `npm` | `npm` | name as-is; scoped packages put the percent-encoded scope in the namespace slot | `npm+lodash$4.17.20` → `pkg:npm/lodash@4.17.20`; `npm+@babel/core$7.20.0` → `pkg:npm/%40babel/core@7.20.0` |
| `pip` | `pypi` | lowercase, collapse runs of `-_.` to `-` (PEP 503) | `pip+PyYAML$6.0.1` → `pkg:pypi/pyyaml@6.0.1` |
| `go` | `golang` | last path segment is the name, the rest is the namespace; keep the `v` prefix on the version | `go+github.com/gin-gonic/gin$v1.9.1` → `pkg:golang/github.com/gin-gonic/gin@v1.9.1` |
| `mvn` | `maven` | `group:artifact` → `namespace/name` | `mvn+com.fasterxml.jackson.core:jackson-databind$2.13.4` → `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4` |
| `cargo` | `cargo` | as-is | `cargo+serde$1.0.188` → `pkg:cargo/serde@1.0.188` |
| `gem` | `gem` | as-is | `gem+rails$7.0.4` → `pkg:gem/rails@7.0.4` |
| `nuget` | `nuget` | keep original casing; compare case-insensitively | `nuget+Newtonsoft.Json$13.0.1` → `pkg:nuget/Newtonsoft.Json@13.0.1` |
| `comp` | `composer` | `vendor/package` → `namespace/name`, lowercase | `comp+symfony/http-kernel$5.4.20` → `pkg:composer/symfony/http-kernel@5.4.20` |
| `hex` | `hex` | lowercase | `hex+phoenix$1.7.0` → `pkg:hex/phoenix@1.7.0` |
| `pod` | `cocoapods` | as-is | `pod+AFNetworking$4.0.1` → `pkg:cocoapods/AFNetworking@4.0.1` |
| `git` | `github` when the host is github.com, else `generic` | `git+github.com/org/repo$rev` → `pkg:github/org/repo@rev` (lowercase org/repo); other hosts → `pkg:generic/<repo>@<rev>?vcs_url=...` | `git+github.com/expressjs/express$4.18.2` → `pkg:github/expressjs/express@4.18.2` |
| `apk` / `deb` / `rpm` (container scans) | same | distro/vendor as namespace; keep epochs and release suffixes verbatim | `apk+alpine/musl$1.2.4-r2` → `pkg:apk/alpine/musl@1.2.4-r2` |
| `archive`, `user`, custom | `generic` | no registry exists; carry the original locator in a qualifier | `pkg:generic/widget-vendored@1.0?fossa_locator=archive%2B...` |

Do not invent mappings for fetchers not in this table — check what the
revision actually contains (the dependency records name their fetchers), map
what you can, send the remainder to `pkg:generic` with the `fossa_locator`
qualifier, and list them in the report. A purl you constructed by analogy and
never flagged is a silent join failure in mode 2.

## 5. Emit the document

**Primary format — OSV.** One entry per vulnerability id, affected packages
as purls. The file is a JSON array of OSV entries. Skeleton:

```json
{
  "schema_version": "1.6.0",
  "id": "CVE-2021-23337",
  "modified": "2026-07-31T17:00:00Z",
  "aliases": ["GHSA-35jh-r3h4-6jhm"],
  "summary": "Command injection in lodash",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash@4.17.20"},
      "versions": ["4.17.20"],
      "database_specific": {"fossa": {"depth": "direct", "issue_id": 9412}}
    }
  ],
  "database_specific": {
    "fossa": {"cvss": 7.2, "severity": "high",
              "epss_score": 0.00205, "epss_percentile": 0.62,
              "remediation": {"partialFix": "4.17.21", "partialFixDistance": "PATCH",
                              "completeFix": "4.17.21", "completeFixDistance": "PATCH"},
              "modified_is": "export-timestamp"}
  }
}
```

- The same CVE in two packages is **one** entry with two `affected` items,
  not two entries.
- **OSV requires `modified`.** FOSSA has no per-advisory modified date, so
  set it to the export timestamp (or the revision's `analyzedAt` if you
  prefer scan time) and label which one it is
  (`database_specific.fossa.modified_is`) — an entry without `modified` fails
  schema validation.
- OSV's `severity` field requires a CVSS **vector string**. FOSSA returns a
  numeric base score; do not fabricate a vector from it. Omit `severity` and
  carry the numeric score in `database_specific.fossa.cvss` unless the issue
  carries a `cvssVector` — it usually does, and then the `type` must be
  derived from the vector prefix (`CVSS:4.0` → `CVSS_V4`, `CVSS:3.x` →
  `CVSS_V3`), never hardcoded: FOSSA emits CVSS:4.0 vectors routinely, and
  typing them `CVSS_V3` is schema-invalid.
- Everything FOSSA-specific (EPSS, depth, remediation distance, issue id)
  goes under `database_specific.fossa` so the entry stays valid OSV and
  nothing FOSSA said is lost.

**Secondary format — CycloneDX 1.6 VDR**, when asked for CycloneDX, VDR, or
VEX: `specVersion: "1.6"`, affected dependencies as `components[]` with
purl-valued `bom-ref`s, and one `vulnerabilities[]` entry per id with
`ratings[]` (CVSS score + severity band, and EPSS as a second rating from
source EPSS), `analysis` (`state: "exploitable"` for active findings — FOSSA
only exports active issues here), and `affects[]` referencing the bom-refs.

Every exported field must be traceable to the FOSSA field it came from. The
full three-way mapping table (FOSSA field → OSV field → CycloneDX field),
plus the per-vendor key-extraction paths for mode 2, is in
`references/field-mapping.md` — follow it rather than improvising, and extend
it if you meet a field it lacks.

Write the document to a local file the user can diff and ship:
`<project-slug>.osv.json` / `<project-slug>.cdx.json`, in the working
directory unless the user names another. For multi-project exports, one file
per project; a merged file hides which project a finding came from.

The JSON **array** of OSV entries is a local convention chosen because one
file diffs — it is not standard OSV interchange. The OSV ecosystem is one
entry per file, and osv-scanner will not ingest an array. If the export is
destined for OSV tooling rather than this skill's diff, offer one
`<id>.json` file per entry instead.

Validate before reporting: the file parses, every entry has an `id` **and a
`modified` timestamp**, every `severity[]` type matches its vector's prefix,
every `ranges[]` entry has an `introduced` event, every affected package has
a purl, and the entry count reconciles with `issue_counts.vulnerability`
(state the arithmetic — N issues → M entries after grouping by CVE — so the
user can check it).

## 6. Vendor diff — normalize both sides

Given another vendor's export, identify the format and extract one record per
(package, vulnerability) from each side. Recognized inputs and where their
keys live are tabulated in `references/field-mapping.md`: Snyk JSON, Trivy
JSON, Grype JSON, CycloneDX (BOM or VDR), SARIF, and OSV.

Normalize every record — FOSSA's and the vendor's — to the key:

```
(purl stripped of version and qualifiers, canonical vulnerability id)
```

- **Package half:** `pkg:type/namespace/name` only. Dropping the version is
  deliberate: scanners disagree about version *formatting* (v-prefixes,
  epochs, rebuild suffixes) far more often than about which package is
  affected, and a version-sensitive key converts formatting noise into fake
  detection differences. Lowercase the parts that are case-insensitive in the
  purl spec (type, and name/namespace for npm, pypi, composer, golang).
  Version disagreements are still reported — as their own category, not as
  missing findings.
- **Vulnerability half:** resolve aliases *before* comparing. Prefer the CVE
  id; map GHSA and vendor ids (SNYK-*, GO-*, RUSTSEC-*, …) to their CVE using
  the alias lists both formats carry (`aliases` in OSV, `identifiers` in
  Snyk, `references`/`ids` in CycloneDX, `dataSource`/`relatedVulnerabilities`
  in Grype). A finding is "unique to one side" only after alias resolution
  fails; if you could not resolve an id, put it in an "unresolved identity"
  bucket rather than claiming it as a difference.

Then compute four sets: **both agree** (key present on both sides),
**FOSSA-only**, **vendor-only**, and **severity disagreements** — same key on
both sides but a different severity band or a CVSS base-score gap ≥ 1.0.
Check the CVSS *version* before calling it a disagreement: a v2 score against
a v3.1 score is a methodology difference, not a dispute about the
vulnerability — and the case you will actually hit today is v4-vs-v3.x, since
FOSSA routinely carries CVSS:4.0 vectors while most vendors still report
v3.1.

## 7. Vendor diff — report

Lead with the overlap arithmetic, then the disagreement tables, in this
order:

1. **Counts**: total keys per side, agreed, FOSSA-only, vendor-only,
   unresolved-identity — with the scope caveats (below) attached to the
   counts, not footnoted three pages later.
2. **Severity disagreements**: key, FOSSA score/band, vendor score/band,
   CVSS versions, delta.
3. **FOSSA-only**, each row spot-checked: read the advisory (or at minimum
   the CVE's affected-version range) — the **upstream** advisory, not FOSSA's
   own `affectedVersionRanges`, which is FOSSA's claim restated and makes the
   check circular — and mark the row *confirmed* (the
   installed version is in the affected range), *version-range disagreement*
   (vendor saw the package but considers the version unaffected), or
   *unverified*. **Never present an unverified FOSSA-only row to a customer
   as a win.** The three honest explanations for a one-sided finding are: the
   other scanner scoped it out, the scanners disagree about affected version
   ranges, or the alias resolution failed — and "our scanner is better" is
   the claim you may make only after eliminating all three.
4. **Vendor-only**, with the same discipline in reverse — the most common
   cause is scope, not a FOSSA miss: dev/test dependencies (scanners differ
   on whether these are in scope by default), OS/container packages FOSSA
   was not pointed at, or a lockfile-vs-artifact difference. Name the
   likeliest cause per row or say you cannot tell.
5. **What was compared**: which FOSSA revision, which vendor file, its
   generation date if the format records one, and whether both sides scanned
   the same commit/artifact. Two scans of different revisions produce an
   impressive-looking diff that means nothing.

If the user then asks which of the agreed or FOSSA-only findings to fix
first, that is prioritization — hand off to [[fossa-suggest-score]] rather
than improvising a ranking here.

## Traps

- **Project scope on `fossa_list_issues` requires `revision_locator` as well
  as `project_locator`** — the input model rejects the call otherwise. Take
  it from `latestRevision.locator`.
- **`fossa_list_dependencies` wants the full `project$revision` locator.** It
  is a path parameter passed verbatim; a bare revision id 404s. The issue
  endpoints normalize either form — the dependency endpoints do not.
- **`top_issue_count` maxes out at 25** and validation rejects more. Always
  reconcile against `issue_counts.vulnerability` and page
  `fossa_list_issues` for the remainder; an export that silently contains
  only the top 25 is wrong in exactly the way nobody notices.
- **`epss.score` and `epss.percentile` are different numbers and the gap is
  large** — 0.0598 raw is the 92.6th percentile. Export both, labeled. A
  diff that compares FOSSA's percentile against another tool's raw
  probability manufactures a disagreement out of nothing.
- **The category is `"vulnerability"`.** Filters follow it: `severity`,
  `severity_source`, and `cwes` are only accepted for the vulnerability
  category, and `issue_types` is rejected there.
- **Git dependencies have no registry purl.** `pkg:github/...` only when the
  host really is github.com; everything else is `pkg:generic` with a
  `vcs_url` or `fossa_locator` qualifier — and vendors' purls for the same
  repo will differ, so expect these to land in the unresolved bucket and say
  so rather than counting them as differences.
- **Purl edge cases cluster in four ecosystems**: npm scopes must be
  percent-encoded (`%40babel`), pypi names must be PEP 503-normalized before
  comparing, maven's `group:artifact` colon becomes a slash, and Go versions
  keep their `v` prefix (most vendors emit it; stripping it breaks nothing
  in mode 1 and breaks joins in mode 2 if done on only one side).
- **Do not fabricate CVSS vectors.** OSV's `severity` wants a vector string;
  use FOSSA's `cvssVector` when present (typed by its prefix, per step 5) and
  omit `severity` when it is not. A back-constructed vector looks
  authoritative and is fiction.
- **`analysis_state: "in_progress"` means the numbers are not final.** Both
  posture and the issues list can return it (HTTP 202 upstream). Never diff
  or export an in-progress revision without saying so.
- **Ignored issues are excluded by default** (`status="active"`). That is
  correct for an export of open findings, but say it in the report — the
  vendor tool has no notion of FOSSA's ignores, and an issue someone ignored
  in FOSSA will otherwise surface as a fake "vendor-only" finding.

## Scope

This skill reads FOSSA and writes local files. It does **not** write to
FOSSA, does not change the target repository, and does not upload the export
or the comparison anywhere — publishing or sending the document is the
user's call, made after they have read it. It also does not rank findings or
recommend remediation order; that is [[fossa-suggest-score]].

Field-by-field mapping (FOSSA → OSV → CycloneDX) and per-vendor key
extraction paths: `references/field-mapping.md`.
