# Field mapping — FOSSA → OSV → CycloneDX 1.6 VDR

Every exported field must trace back to a FOSSA field through this table.
FOSSA field names below are as returned by the MCP tools (`fossa_project_posture`
top-issue entries and `fossa_list_issues` / `fossa_get_issue` records; dependency
fields from `fossa_list_dependencies`). Verify against the first live response —
if a name differs, fix this table rather than guessing per-field.

## Vulnerability identity and description

| FOSSA field | OSV field | CycloneDX 1.6 field |
|---|---|---|
| `cve` (e.g. `CVE-2021-23337`) | `id` | `vulnerabilities[].id` + `source: {name: "NVD"}` |
| — (no structured alias field exists) | `modified` — **required by the OSV schema**; FOSSA has no per-advisory modified date, so use the export timestamp (or the revision's `analyzedAt`) and label which one it is (`database_specific.fossa.modified_is`) | not required; `vulnerabilities[].updated` if wanted |
| GHSA id, extracted from `references[]` URLs — match `…/security/advisories/GHSA-…` and take the `GHSA-…` segment. There is **no** structured alias field in the issue payload; this URL parse is the only source | `aliases[]` | `vulnerabilities[].references[].id` |
| issue `id` (FOSSA's integer issue id) | `affected[].database_specific.fossa.issue_id` — per-package, because one OSV entry can merge several FOSSA issues (same CVE, different packages) | `properties[]` name `fossa:issueId` |
| `title` | `summary` | `vulnerabilities[].description` |
| details / description text | `details` | `vulnerabilities[].detail` |
| `cwes` | `database_specific.fossa.cwes` | `vulnerabilities[].cwes[]` (numeric CWE ids, `CWE-79` → `79`) |
| `createdAt` (when FOSSA first found it — **not** the advisory publish date) | `database_specific.fossa.first_found` | `properties[]` name `fossa:firstFound` |
| `published` (the advisory's publication date — this one **is** it) | `published` | `vulnerabilities[].published` |
| `references[]` (array of URL strings) | `references[]`, typed by URL: advisory pages (nvd.nist.gov, `/security/advisories/`, osv.dev) → `ADVISORY`, commit/patch URLs → `FIX`, everything else → `WEB` | advisory URLs → `vulnerabilities[].advisories[].url`; the rest as `properties[]` name `fossa:reference` |
| `affectedVersionRanges[]` (free-text range strings, e.g. `<4.17.11`) | `database_specific.fossa.affected_version_ranges` — no clean OSV home: OSV ranges want structured events, and these strings are not that | `properties[]` name `fossa:affectedVersionRanges` |
| `status` (`active`; export excludes `ignored`) | not exported — active-only, stated in the report | `analysis.state: "exploitable"` (VDR reading of an open finding; do not use VEX not-affected states unless the user supplies a justification) |

Do not map FOSSA's `createdAt` to OSV `published` or CycloneDX `published` —
those mean the advisory's publication date, which FOSSA's found-date is not;
the advisory date is FOSSA's `published`, mapped above.

Skipping the GHSA extraction from `references[]` does not fail loudly — it
silently degrades mode 2: a finding both scanners see, one under a CVE and one
under its GHSA, stops joining and shows up as a fake difference on **both**
sides.

## Severity and exploitability

| FOSSA field | OSV field | CycloneDX 1.6 field |
|---|---|---|
| `cvss` (numeric base score) | `database_specific.fossa.cvss` — OSV `severity[]` requires a vector string; omit it unless a vector is actually present | `ratings[]` entry: `score`, `method` derived from the `cvssVector` prefix (see next row); no vector → `method: "other"` with a property naming the source |
| `severity` band (`critical`/`high`/`medium`/`low`/`unknown`) | `database_specific.fossa.severity` | same `ratings[]` entry: `severity` |
| `cvssVector` (vector string, usually present) | `severity[]`: `{type: <derived>, score: "<vector>"}` — derive `type` from the prefix: `CVSS:4.0` → `CVSS_V4`, `CVSS:3.x` → `CVSS_V3`, `CVSS:2` → `CVSS_V2`. Never hardcode `CVSS_V3`: FOSSA emits CVSS:4.0 vectors routinely, and typing those `CVSS_V3` fails schema validation | same `ratings[]` entry: `vector`, with `method` from the same prefix: `CVSSv4` / `CVSSv31` / `CVSSv3` |
| `epss.score` (raw probability, 0–1) | `database_specific.fossa.epss_score` | second `ratings[]` entry: `source: {name: "EPSS"}`, `score`, `method: "other"` |
| `epss.percentile` (0–1) | `database_specific.fossa.epss_percentile` | `properties[]` name `fossa:epssPercentile` |
| `customRiskScore` (null unless the org configured one) | `database_specific.fossa.custom_risk_score`, only when non-null | `properties[]` name `fossa:customRiskScore`, only when non-null |

Keep score and percentile separate and labeled everywhere. They differ by
orders of magnitude (raw 0.0598 ≈ 92.6th percentile) and conflating them is
the single easiest way to fake a severity disagreement in mode 2.

## Affected package (joined from the dependency record)

| FOSSA field | OSV field | CycloneDX 1.6 field |
|---|---|---|
| dependency locator (`fetcher+package$version`, from the issue's `source.id` — SKILL.md step 3 says which payloads use `source.id` vs `revisionId` — joined to `fossa_list_dependencies`) | `affected[].package.purl` (via the fetcher table in SKILL.md) | `components[].purl` = `components[].bom-ref`; referenced from `vulnerabilities[].affects[].ref` |
| fetcher prefix | `affected[].package.ecosystem` (OSV names: npm→`npm`, pip→`PyPI`, go→`Go`, mvn→`Maven`, cargo→`crates.io`, gem→`RubyGems`, nuget→`NuGet`, comp→`Packagist`, hex→`Hex`) | purl type (inside the purl) |
| package name (from the locator; `title` as display name) | `affected[].package.name` | `components[].name` |
| version (locator revision segment) | `affected[].versions` = `["<installed>"]` — the installed version, not an advisory range; do not invent `ranges` FOSSA did not state | `components[].version` |
| `depths` (`direct`/`transitive`) | `affected[].database_specific.fossa.depth` | `properties[]` name `fossa:depth` on the component |
| `remediation` — an **object** `{partialFix, partialFixDistance, completeFix, completeFixDistance}`, not a string. `partialFix` is the fix for **this** CVE; `completeFix` is the version clearing **all** CVEs in the package | carry the object verbatim as `database_specific.fossa.remediation`; additionally, when `partialFix` names an exact version, emit `affected[].ranges[]` as the full shape `{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "<partialFix>"}]}` — a `fixed` event without an `introduced` event is schema-invalid, and `partialFix` (not `completeFix`) is the per-CVE fixed version | `vulnerabilities[].recommendation` rendered from the object ("upgrade <pkg> to <partialFix>; <completeFix> clears all findings"); `NO_SAFE_VERSION` → say so in `recommendation`, never omit |
| scanned project + revision (`project_locator`, full `revision_locator`) | `database_specific.fossa.project`, `.revision` on every entry | `metadata.component` (the project, purl-formed when the locator is `git+github.com/...`) + `properties[]` name `fossa:revision` |

## Mode 2 — where each vendor format keeps the key

Extract `(purl-without-version-and-qualifiers, vulnerability id + aliases)`
from these paths. Formats are recognizable by the marker column.

| Format | Marker | Package identity | Vulnerability id | Aliases |
|---|---|---|---|---|
| Grype JSON | top-level `matches[]` | `matches[].artifact.purl` (already a purl) | `matches[].vulnerability.id` | `matches[].relatedVulnerabilities[].id`; a GHSA id may also be embedded in the `matches[].vulnerability.dataSource` URL |
| Trivy JSON | top-level `Results[]` | `Results[].Vulnerabilities[].PkgIdentifier.PURL`; fall back to `PkgName`+`PkgType` | `Results[].Vulnerabilities[].VulnerabilityID` | none inline — Trivy emits CVE ids where one exists; GHSA-only rows need external resolution |
| Snyk JSON | top-level `vulnerabilities[]` with `packageManager` | `packageName` + `packageManager` (build the purl yourself — Snyk does not emit one) + `version` | `identifiers.CVE[0]`; else the `SNYK-*` `id` | `identifiers.CVE[]`, `identifiers.GHSA[]` |
| CycloneDX (BOM or VDR) | `bomFormat: "CycloneDX"` | resolve `vulnerabilities[].affects[].ref` → the component's `purl` | `vulnerabilities[].id` | `vulnerabilities[].references[].id` |
| SARIF | `$schema` …`sarif`… / `runs[]` | weakest of the set: parse purl or package@version out of `ruleId` / `result.message` / `properties` per producing tool; say which convention you assumed | usually embedded in `ruleId` (`CVE-…` substring) | rarely present |
| OSV | entries with `schema_version` + `affected[]` | `affected[].package.purl` | `id` | `aliases[]` |

Normalization applied to **both** sides after extraction:

- strip `@version` and all `?qualifiers` / `#subpath` from the purl
- lowercase purl type always; lowercase name/namespace for npm (not the
  `%40` escape), pypi (plus PEP 503 collapsing), composer, golang, github
- keep nuget/maven name case but compare case-insensitively
- vulnerability id: uppercase; prefer CVE over GHSA over vendor id when the
  alias set links them; an id you could not link goes to the
  unresolved-identity bucket, not to a one-sided count
