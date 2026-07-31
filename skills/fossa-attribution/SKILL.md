---
name: fossa-attribution
description: Produce a shippable third-party attribution document (NOTICE / THIRD_PARTY_LICENSES) for a FOSSA project from its attribution report. Use when asked for a NOTICE file, third-party licenses, an attribution report, open source notices, license texts for a release, or a list of a project's dependencies with their licenses and copyright holders.
---

# fossa-attribution

Pin a FOSSA project revision, pull its attribution report, agree the inclusion
scope with the user, and write the attribution file(s) — a NOTICE-style summary
and/or a full THIRD_PARTY_LICENSES with complete license texts — with every
unresolvable entry flagged rather than dropped.

**Why this workflow exists:** most licenses that permit redistribution require
notice in return — the license text, the copyright line, or both, preserved in
the shipped artifact. The failure mode is not producing an ugly file; it is
producing a *plausible-looking* file with silent gaps. A dependency missing
from the notices is a compliance hole nobody will spot by reading the file,
which is why steps 5 and 6 (flag the gaps, reconcile the counts) are the
non-negotiable part of this skill.

This skill produces the artifact. Whether attribution is required at all for a
given distribution, and which obligations attach, is the sibling skill
[[fossa-license-review]] — run that first when the question is "do we owe
notices" rather than "write the notices".

Ask which project if it isn't named. Everything else below is procedure.

## 1. Resolve the project and pin the revision

Never guess a locator, and never generate against "latest" without recording
what latest resolved to — an attribution document that cannot say which build
it covers is not evidence of anything.

- `fossa_list_projects(title=...)` → the project locator and
  `latestRevision.locator`.
- If the user wants a specific release rather than the newest scan:
  `fossa_list_project_revisions(project_locator=..., refs_type="tag")` for
  tagged releases, or `locator_contains=<sha-prefix>` to find a commit.
  `resolved_only=True` (the default) is what you want — an unresolved revision
  has no dependency analysis to report on.

Whichever way you got it, **write the full revision locator down, including the
`$<revision>` suffix**, and put it in the header of the generated file:
project, revision, and the date the report was pulled. That triple is the
document's provenance.

## 2. Pull the attribution report

```
fossa_get_attribution_report(
    revision_locator="...",          # the full locator from step 1
    format="MD",                     # MD | TXT | SPDX_JSON | CYCLONEDX_JSON
    include_copyright_list=True,     # default is False — see below
)
```

What the parameters actually control (defaults in parentheses):

- `format` (`MD`): `MD`/`TXT` return the report as one text blob in `content`;
  `SPDX_JSON`/`CYCLONEDX_JSON` return a parsed SBOM object. Text formats are
  the right input for a NOTICE file; the JSON formats are for when the user
  wants a machine-readable SBOM alongside.
- `include_license_list` (True) — the full text of every license in use. This
  is where THIRD_PARTY_LICENSES content comes from; leave it on.
- `include_dependency_summary` (True) — the package/version/license table.
  This is where the NOTICE summary comes from; leave it on.
- `include_copyright_list` (**False**) — copyright holders per package. A
  NOTICE file wants these, so **set it to True explicitly**; the default
  silently gives you a report with no copyright holders in it.
- `include_direct_dependencies` / `include_deep_dependencies` (both True) —
  scope knobs for step 3.
- Off by default and usually correct to leave off for an attribution file:
  `include_license_scan`, `include_file_matches`, `include_license_headers`,
  `include_open_vulnerabilities`, `include_closed_vulnerabilities`,
  `include_package_labels`. `include_hash_and_version_data` is worth turning
  on when the user wants verifiable package identity in the document.

The response is not the standard envelope: report content sits at the top
level as `content`, with `format`, `content_type`, and a `truncated` flag
beside it. **Check `truncated` before using the content** — see Traps.

## 3. Agree the inclusion scope with the user

Two decisions, and they are the user's, not yours — ask before generating:

- **Runtime vs everything.** Shipped notices cover what is *distributed*.
  Dev and build tooling (test frameworks, linters, compilers) is normally
  excluded because it never reaches the customer. Container images are the
  usual exception: everything installed in the image ships, including things
  a source-only distribution would call build tooling.
- **Direct vs transitive.** Legally the notices need everything distributed,
  which almost always means *all runtime transitives* — a transitive MIT
  dependency's license text ships with your binary just as surely as a direct
  one's. Direct-only is a valid choice only for documents that are explicitly
  an overview, not the shipped notice file.

The default, absent instruction: all runtime dependencies, direct and
transitive. Record the chosen scope in the generated file's header so a reader
knows what the document claims to cover.

FOSSA's report does not itself distinguish runtime from dev in every
ecosystem. Where the report includes packages the user excluded (or the scan
was configured to include dev dependencies), filter against
`fossa_list_dependencies` data and the project's own manifests, and say in the
report what you filtered and why.

## 4. Generate the output file(s)

Two shapes, matching this repo's own artifacts. Generate the one(s) the user
asked for; when unspecified, offer both.

**NOTICE-style summary** — one entry per package: name, version, license,
copyright holder. Match the layout of the repo's own `NOTICE`: product name
and copyright at the top, then delimited sections; the third-party section
names the license families in use and calls out anything non-permissive
individually (the repo's `NOTICE` does exactly this for certifi's MPL-2.0).

**Full THIRD_PARTY_LICENSES** — the worked example is
`scripts/generate_third_party_licenses.py`, which produces the format to
match: a two-line preamble stating what the file covers and how it was
generated, then per package, sorted case-insensitively by name:

```
================================================================================
<name> <version> — <license>
================================================================================
<full license text>
```

That script's fallback line — `(no bundled license file; see declared license
above)` — is the in-file marker for a missing text. Use the same pattern, but
*also* list every such package in the gaps section (step 5); an inline marker
alone is too easy to miss in a 10,000-line file.

Write the files locally (in the directory the user names, or the current
project root). Do not commit them into the customer repo unless asked.

## 5. Flag the failure cases — their own required section, never dropped

The generated document gets a section titled something like "Attribution gaps
requiring review", present even when empty ("none"), listing:

- **License text unresolved** — the package is in the dependency list but no
  license text came back. Try `fossa_get_dependency(revision_locator=...,
  dependency_revision_locator=..., include_license_text=True)` before
  declaring it unresolved; the per-dependency endpoint sometimes has text the
  aggregate report lacks.
- **Unknown / unlicensed packages** — declared license missing or "UNKNOWN".
  These are the highest-risk entries in the file; name them first.
- **Multiple / ambiguous licenses** — dual-licensed packages. Record *which
  license was elected* for this distribution and on whose decision (the
  user's, or FOSSA's configured policy). "MIT OR GPL-2.0" with no election
  recorded is an unfinished entry.
- **Missing copyright holders** — entries where `include_copyright_list`
  returned nothing for the package. The license section still ships; the
  gap is noted so someone can chase the holder line if the license requires
  it verbatim.

An attribution file with silent gaps is worse than none: it tells its reader
the diligence was done when it wasn't. Every one of these cases appears either
resolved in the body or named in the gaps section — there is no third state.

## 6. Reconcile before handing over

Pull the authoritative dependency list and count it against the document:

```
fossa_list_dependencies(revision_locator="...", depths=["direct", "transitive"], count=100)
```

Paginate (`page=2, 3, ...`) until a page comes back short — `count` is capped
at 100 per page. Filter to the agreed scope from step 3, then verify: **every
dependency in the list appears either in the document body or in the flagged
gaps section.** Do the arithmetic and state it in your closing report, e.g.
"87 runtime dependencies in FOSSA; 84 attributed in full, 3 in the gaps
section; 0 unaccounted for." A nonzero unaccounted count means the document is
not done — go find them, or move them to the gaps section with a reason.

Close with: the file paths written, the project/revision/date provenance
triple, the scope statement, the reconciliation count, and the gaps list with
what resolving each would take.

## Traps

- **The report is truncated at 200,000 characters by default** (the server's
  `FOSSA_REPORT_MAX_CHARS`, raisable to 1,000,000). The response says so via
  `truncated: true` plus `original_char_count` — check it every time. A
  full-license-texts report for a large project blows through the cap easily.
  When it does: raise the env var if you control the server, or assemble the
  license texts per-package via `fossa_list_dependencies(...,
  include_license_text=True)` page by page instead of from the one big report.
- **Truncation applies to the JSON formats too**, and a truncated
  `SPDX_JSON`/`CYCLONEDX_JSON` body is broken JSON — the tool then returns the
  raw string with `json_parse_error: true` instead of a parsed object. Do not
  try to repair it; reduce the report options or switch strategy as above.
- **`include_copyright_list` defaults to False.** The single most common way
  to produce a NOTICE file with no copyright holders in it. Set it True.
- **Revision locators must be passed whole**, `$` suffix and all (e.g.
  `custom+1234/my-project$20260731000000`). The tool URL-encodes internally;
  pass the raw locator exactly as a listing tool returned it.
- **`fossa_list_dependencies` license fields are off by default** —
  `include_license_text` and `include_copyright` are both False. The cheap
  reconciliation pass (step 6) leaves them off; only turn them on when using
  the list as the license-text *source* after a truncated report.
- **The report can be slow on large projects.** It is a single synchronous
  download — FOSSA renders the whole report before the first byte. There is
  no polling to do; just do not conclude the tool is broken because one call
  took much longer than the listing calls.
- **"Latest" moves.** If any time passes between pulling the report and the
  reconciliation pass, both must use the pinned revision locator from step 1,
  not a re-resolved latest — otherwise the counts can legitimately disagree
  and the discrepancy is your own procedure, not a gap.

## Scope

This skill reads FOSSA and writes local files only. It does not modify FOSSA,
and it does not commit into the customer's repository unless the user asks.
The output is an attribution document, not legal advice: license election for
dual-licensed packages and the final compliance sign-off belong to the user
and their counsel.
