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
| GHSA / other advisory id, when present in the issue detail | `aliases[]` | `vulnerabilities[].references[].id` |
| issue `id` (FOSSA's integer issue id) | `database_specific.fossa.issue_id` | `properties[]` name `fossa:issueId` |
| `title` | `summary` | `vulnerabilities[].description` |
| details / description text | `details` | `vulnerabilities[].detail` |
| `cwes` | `database_specific.fossa.cwes` | `vulnerabilities[].cwes[]` (numeric CWE ids, `CWE-79` → `79`) |
| `createdAt` (when FOSSA first found it — **not** the advisory publish date) | `database_specific.fossa.first_found` | `properties[]` name `fossa:firstFound` |
| `status` (`active`; export excludes `ignored`) | not exported — active-only, stated in the report | `analysis.state: "exploitable"` (VDR reading of an open finding; do not use VEX not-affected states unless the user supplies a justification) |

Do not map FOSSA's `createdAt` to OSV `published` or CycloneDX `published` —
those mean the advisory's publication date, which FOSSA's found-date is not.

## Severity and exploitability

| FOSSA field | OSV field | CycloneDX 1.6 field |
|---|---|---|
| `cvss` (numeric base score) | `database_specific.fossa.cvss` — OSV `severity[]` requires a vector string; omit it unless a vector is actually present | `ratings[]` entry: `score`, `method: "CVSSv31"` (only if the CVSS version is actually known — otherwise `method: "other"` with a property naming the source) |
| `severity` band (`critical`/`high`/`medium`/`low`/`unknown`) | `database_specific.fossa.severity` | same `ratings[]` entry: `severity` |
| CVSS vector string, if the issue detail carries one | `severity[]`: `{type: "CVSS_V3", score: "<vector>"}` | same `ratings[]` entry: `vector` |
| `epss.score` (raw probability, 0–1) | `database_specific.fossa.epss_score` | second `ratings[]` entry: `source: {name: "EPSS"}`, `score`, `method: "other"` |
| `epss.percentile` (0–1) | `database_specific.fossa.epss_percentile` | `properties[]` name `fossa:epssPercentile` |
| `customRiskScore` (null unless the org configured one) | `database_specific.fossa.custom_risk_score`, only when non-null | `properties[]` name `fossa:customRiskScore`, only when non-null |

Keep score and percentile separate and labeled everywhere. They differ by
orders of magnitude (raw 0.0598 ≈ 92.6th percentile) and conflating them is
the single easiest way to fake a severity disagreement in mode 2.

## Affected package (joined from the dependency record)

| FOSSA field | OSV field | CycloneDX 1.6 field |
|---|---|---|
| dependency locator (`fetcher+package$version`, from the issue's `revisionId` joined to `fossa_list_dependencies`) | `affected[].package.purl` (via the fetcher table in SKILL.md) | `components[].purl` = `components[].bom-ref`; referenced from `vulnerabilities[].affects[].ref` |
| fetcher prefix | `affected[].package.ecosystem` (OSV names: npm→`npm`, pip→`PyPI`, go→`Go`, mvn→`Maven`, cargo→`crates.io`, gem→`RubyGems`, nuget→`NuGet`, comp→`Packagist`, hex→`Hex`) | purl type (inside the purl) |
| package name (from the locator; `title` as display name) | `affected[].package.name` | `components[].name` |
| version (locator revision segment) | `affected[].versions` = `["<installed>"]` — the installed version, not an advisory range; do not invent `ranges` FOSSA did not state | `components[].version` |
| `depths` (`direct`/`transitive`) | `affected[].database_specific.fossa.depth` | `properties[]` name `fossa:depth` on the component |
| `remediation` (fix distance / safe version) | `database_specific.fossa.remediation`; additionally `affected[].ranges[].events[].fixed` **only** when FOSSA names an exact fixed version | `vulnerabilities[].recommendation` ("upgrade <pkg> to <version>"); `NO_SAFE_VERSION` → say so in `recommendation`, never omit |
| scanned project + revision (`project_locator`, full `revision_locator`) | `database_specific.fossa.project`, `.revision` on every entry | `metadata.component` (the project, purl-formed when the locator is `git+github.com/...`) + `properties[]` name `fossa:revision` |

## Mode 2 — where each vendor format keeps the key

Extract `(purl-without-version-and-qualifiers, vulnerability id + aliases)`
from these paths. Formats are recognizable by the marker column.

| Format | Marker | Package identity | Vulnerability id | Aliases |
|---|---|---|---|---|
| Grype JSON | top-level `matches[]` | `matches[].artifact.purl` (already a purl) | `matches[].vulnerability.id` | `matches[].relatedVulnerabilities[].id` |
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
