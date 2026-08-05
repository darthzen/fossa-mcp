---
name: fossa-protect
description: Turn a project's FOSSA findings into NeuVector runtime controls and push them to the cluster. Two tracks — vulnerability findings become WAF sensors (regex-matched request inspection); license-conflict findings become a workload quarantine (network isolation / deploy hold). Use when asked to mitigate, compensate for, or "protect against" CVEs found by FOSSA, to write WAF sensors/rules for a project's dependencies, to quarantine or "wall off" a workload with an unresolved license conflict, or whenever FOSSA findings and NeuVector need to be connected. Also use when asked which projects are available to protect or how critical each one is, and when asked to review or roll back sensors or quarantines created this way.
---

# fossa-protect

Read a project's vulnerabilities out of FOSSA, decide which are actually
mitigable by a regex WAF, write sensors for those, and bind them to the right
NeuVector groups in an alert-only mode.

**Why this workflow exists:** so the security team can mitigate **immediately
and unilaterally**, without waiting on the dev team. In practice — especially
with legacy code — the upgrade can take years or never happen at all:
maintainers leave, nobody knows where the source lives or what server it runs
on. The sensor is a real mitigation in its own right, not a placeholder for a
fix that is presumed imminent. Plan for it to be the operative control
**indefinitely**: write comments that survive team turnover, validate rather
than assume, and treat the Protect-mode warning as more important the longer a
binding will live, not less.

**The honest framing, stated up front and never dropped:** a NeuVector WAF
sensor is *regex matched against request context* — nothing more. Only
upgrading the vulnerable dependency closes the CVE, so every report this skill
produces names the version bump that actually fixes the finding — as the
parallel dev-side track, not as a reason to withhold or undersell the
mitigation. Honesty cuts both ways: never inflate what a rule catches
(step 3's classification), and never dismiss a validated sensor as "just a
stopgap".

Ask which project if it isn't named. Everything else below is procedure.

**Two enforcement tracks, by finding type.** Sections 1–8 are the **vulnerability
→ WAF sensor** track (regex inspection of request context). A **license conflict**
is a different problem with a different control — there is no attack request to
regex, the finding is a legal blocker on shipping at all — and it routes to the
**licensing → quarantine** track at the end of this file. Pick the track from the
finding category; the two share the step-2 deployment-correlation discipline but
nothing else.

## 1. Pull the findings

Resolve the project first — never guess a locator:

- `fossa_list_projects(title=...)` → the locator (e.g. `git+github.com/org/repo`).
  If the project was not named, run the picker in **1a** rather than dumping the
  inventory.
  **`title` is a substring match and one repo can be several FOSSA projects.**
  Observed live: a title search returned both a continuously scanned
  `git+<host>/<org>/<repo>` project and a separately uploaded `custom+<orgId>/…`
  project for the *same commit*, where the second reported **zero** security
  issues. Taking the first row without reading it is how you conclude a project
  has nothing to protect when it has findings. Match on the commit SHA
  (`version`) and pick the scan the user actually operates against.
- `fossa_list_issues(category="vulnerability", scope_type="project",
  project_locator=..., revision_locator=...)` — **project scope requires
  `revision_locator` as well**, or the call fails validation. Take it from the
  project's `latestRevision.locator`.
- `fossa_get_issue(...)` for anything whose CVE detail you actually need

Group findings by **package**, not by CVE. Five CVEs in one dependency is one
version bump, and that reframing is usually the most useful thing you can tell
the user.

### 1a. The picker — what is available to protect, and how bad it is

Run this only when the user did not name a project. The job is to let them pick
in one glance: which projects have something a runtime control can act on, which
control that would be, and how urgent each one looks **on FOSSA data alone**.

**Before the calls, read `references/remediation.md` if the target is a demo
project it covers.** It pre-stages the stable half of the answer — locator, the
CVE↔package map, the track, and the version bump that actually fixes each finding
— so the fix is in hand without re-derivation. It deliberately omits EPSS and the
revision SHA, which move; those still come from the live calls below. Never speak
a percentile or a revision off that file.

**Two calls, two tiers.** Tier 1 is one cheap call and covers every project.
Tier 2 enriches only the candidates.

**Tier 1 — inventory.** One call, and note the sort:

```
fossa_list_projects(count=50, sort="issues-total_desc")
```

Sort on `issues-total_desc`, **not `issues-security_desc`.** Security-desc sorts
a licensing-only project to the bottom of the list, and a licensing-only project
is a first-class target for this skill — it is the entire quarantine track. A
sort that buries it hides half of what the skill does.

From each row, tier 1 gives you `title`, `id` (the project locator),
`latestRevision.locator`, `version` (the commit SHA), `public`, `scanned`, and
`issues:{total,licensing,security,quality}`. That is enough to assign a **track**
and to drop the clean projects. It is not enough to assign a band — there is no
CVSS, no EPSS and no license name anywhere in this response.

**Tier 2 — enrich the candidates.** For every project with `issues.security > 0`
or `issues.licensing > 0`, in one message, in parallel:

```
fossa_project_posture(project_locator=..., revision_locator=..., top_issue_count=5)
```

`top_issue_count=5` on purpose: the picker needs the worst finding, not the full
list, and posture responses run tens of KB each at 15. Cap the fan-out at the top
**five** candidates by `issues.total` and say in the output how many you did not
enrich — a picker that silently sampled the portfolio is worse than one that
admits its cut. Step 1 proper re-pulls the chosen project in full anyway.

Read these fields, all of them verified live on 2026-08-04:

| Signal | Where | Read |
|---|---|---|
| Worst CVSS | `top_vulnerability_issues[].cvss` | 0–10 float; `severity` carries the same thing as a word |
| Peak EPSS %ile | `top_vulnerability_issues[].epss.percentile` | 0–1 — **percentile, not `score`**; ×100 to show |
| Exploit maturity | `top_vulnerability_issues[].exploitability` | `MATURE` is the loud one. `UNKNOWN` is the common one. Treat any other value as not-MATURE rather than guessing its rank |
| Direct or transitive | `top_vulnerability_issues[].depths` | `{direct, deep}` are **occurrence counts, not depth levels**. `direct ≥ 1` means the package is a direct dependency; `deep ≥ 1` means it is pulled in transitively. A cheap stand-in for reachability, and *only* that |
| License and type | `top_licensing_issues[].license` / `.type` | `policy_conflict` outranks `policy_flag` |
| Fix distance | `remediation.partialFixDistance` | `PATCH` here means the real fix is cheap — say so in the picker, it often ends the conversation |

### The colour bands

Colour comes from **FOSSA fields only**, by this rule:

| | Band | Trigger — any one of these |
|---|---|---|
| 🔴 | Critical | worst CVSS ≥ 9.0 · any `exploitability: MATURE` · any licensing `policy_conflict` |
| 🟠 | High | worst CVSS 7.0–8.9 · peak EPSS percentile ≥ 0.90 |
| 🟡 | Medium | worst CVSS 4.0–6.9 · copyleft `policy_flag` (GPL / AGPL / LGPL / MPL) |
| 🟢 | Low | worst CVSS < 4.0 · permissive-notice flags · quality findings only |
| ⚪ | Clean | `issues.total == 0` — name it as clean and do not offer it |

And the track, from the finding categories:

| | Track | When |
|---|---|---|
| 🛡️ | WAF sensor | `issues.security > 0` — sections 1–8 |
| ⚖️ | Quarantine | `issues.licensing > 0` with a copyleft or denied license — the licensing track |
| 🔧 | Neither | quality findings only. There is no runtime control for an outdated dependency; say so and do not offer a sensor |

A project can carry both markers. Show both.

### The output

```
| | Project | Sec / Lic / Qual | Worst CVSS | CVE | EPSS %ile | Track |
|---|---|---|---|---|---|---|
| 🔴 | react2shell-app | 7 / 0 / 11 | 10.0 | CVE-2025-55182 | 99.9 | 🛡️ |
| 🟠 | ollama-exporter | 5 / 0 / 0 | 7.5 | CVE-2026-42154 | 53.5 | 🛡️ |
| | ↳ peak EPSS | | 6.1 | CVE-2019-3826 | 84.7 | |
| 🟡 | license-conflict-demo | 0 / 14 / 4 | — | — | — | ⚖️ |
| | ollama-code-mcp | 6 / 0 / 0 | — | — | — | 🛡️ not enriched |
| ⚪ | fossa-mcp | 0 / 0 / 0 | — | — | — | clean |
```

**Name the CVE the worst CVSS belongs to.** A bare score is not actionable and
does not survive being read aloud. On a CVSS tie, pick the tied CVE with the
higher EPSS percentile.

**When the peak EPSS belongs to a different CVE, expand the project downward
into a second row.** Each row then carries one CVE and *its own* CVSS and
percentile, so neither number is attributed to a finding it does not belong to.
Continuation rows leave the band, counts and track cells empty and mark the
project column `↳ peak EPSS`. The example above is live: `ollama-exporter`'s
worst CVSS is CVE-2026-42154 at 7.5 / 53.5, while the portfolio-high 84.7
percentile sits on CVE-2019-3826 at CVSS 6.1 — a 2019 XSS that raw severity
ranking buries.

Adjacent columns are read as one finding, so a single row here states something
false. Do not solve it with a footnote; expand the row. When the two coincide —
`react2shell-app` and `ollama-code-mcp` both peak on their own worst CVE, checked
live — one row is correct and a second would be noise.

Getting this right costs one extra call on a project posture truncated: posture
returns its top slice, not an EPSS ranking, so confirm the peak with
`fossa_list_issues(category="vulnerability", scope_type="project", sort="epss_desc")`
whenever the project has more findings than `top_issue_count`. Checked live on
`ollama-code-mcp` — 6 findings, top 5 returned; the omitted one was the lowest
EPSS in the set, but nothing in the posture response says so.

Exploit maturity and fix distance stay out of the table — they drive the **band**
and belong in the per-row line underneath, where there is room to say what they
mean.

Those four rows are real — read off this org on 2026-08-04, with
`ollama-code-mcp` left deliberately unenriched to show the empty-band rule. The
numbers are calibration, not a cache: re-pull them, because EPSS percentiles move
daily and a push moves the revision.

Under the table, one line per coloured row saying what the colour turned on —
"MATURE exploit on a direct dependency", "14 LGPL flags, all one package" —
then ask which to protect. Lead with the 🔴 rows; offer the rest without
narrating them.

### What the colour is not

**The band is pre-reachability and it is not the impact risk score.** It is
computed before step 2 has looked at the cluster, so it knows nothing about
whether the vulnerable path is reachable, whether the service listens, or
whether the workload is even running. Say this in one line every time you print
the table. The [[fossa-suggest-score]] band is a different number arrived at a
different way, and quoting a picker colour as a CIRS band is the same error as
presenting a judgment term as FOSSA output.

The gap is real and worth showing rather than hiding. Worked, on the two demo
projects: `license-conflict-demo` bands **🟡 Medium** here on 14 copyleft
`policy_flag` rows, and scores **34 (Low)** under [[fossa-list]] once linkage
(dynamically-loaded native addon) and distribution (customers, not public) are
applied — and once the 14 rows collapse to the one dependency they actually are.
The picker over-ranks it because it has not made those judgments yet. That is the
picker working correctly: it is a triage aid that decides what to look at, never
the verdict on what was found.

Two failure modes to refuse outright:

- **Do not colour a project you did not enrich.** A tier-1-only row has counts
  and nothing else; print its counts and leave the band cell empty rather than
  inferring a colour from issue volume. Volume is not severity — that is the
  whole point of the exercise these skills exist to demonstrate.
- **Do not let the colour promise a mitigation.** 🔴 means the findings look
  urgent, not that a WAF can touch them. Step 3 decides what is mitigable, and it
  routinely concludes "none". A red row that triages to zero good rules is a
  normal, honest outcome.

## 2. Establish what is actually deployed

Do this **before** triage, not after. Triage is not answerable in the abstract:
whether a CVE is reachable at all depends on how this deployment is configured,
and getting that backwards means writing a sensor for something that cannot fire.

**First check that the NeuVector tools exist at all — this is a precondition,
not a formality.** Everything from here to step 8 runs through `nv_*` tools, and
they are present only when a NeuVector MCP server is connected to this session.
That server is a separate deployment from the FOSSA one and is routinely absent:
observed live, a session with full FOSSA access and a working kubeconfig had **no
`nv_*` tools whatsoever**. Confirm with a cheap read before promising a plan that
depends on them — but make it a read that actually hits the controller.
`nv_list_workloads` or `nv_list_groups` do. `nv_whoami` may **not**: observed
live 2026-08-04, with `NV_ALLOW_UNDOCUMENTED` false it returned the identity
cached at startup (`role:""`, `global_permissions:["unknown (api key)"]`) without
calling the controller at all — a "successful" `nv_whoami` is therefore not proof
the controller is reachable. Use a list call for the liveness check.

If the tools are missing, or present but unable to reach a controller, **say so
immediately and deliver the part of this skill that does not need them.** Steps 1
and 3 are independently valuable and are not a consolation prize: the findings,
the deployment facts you *can* read, the good/partial/none/n-a triage table, and
the dependency upgrades that actually fix the CVEs. Then state plainly which
steps did not run and what would be needed to run them. Do not draft sensor
definitions as though they had been created, do not describe a binding that does
not exist, and do not substitute `kubectl` for the WAF surface — `kubectl` can
show you pods, and cannot create, bind, or validate a sensor.

With the tools available, confirm the workloads are running and serving traffic:

- `nv_list_workloads` / `kubectl get pods -n <ns>`
- `nv_list_groups(name_prefix="nv.<service>")` — plain listing truncates and is
  alphabetical, so the group you want may simply not be on the page. It pages
  with `start`/`limit` and defaults to `limit=50`; page it rather than
  concluding a group is absent.
- `nv_list_waf_groups(bound_only=true)` for what already has sensors

Then read the deployment's actual configuration — Deployment, Service, Ingress,
ConfigMap. You are looking for the facts that decide reachability and that the
rules will be written against:

- **Which transport / protocol is really enabled.** A CVE in a transport this
  deployment does not use is not mitigable, it is *not applicable*, and saying so
  is worth more than a rule.
- **Whether auth is configured**, and what the vulnerable default actually is.
- **Every legitimate ingress path** — ingress hostnames, LoadBalancer and cluster
  IPs, all service DNS forms, pod CIDR, health-probe style. Step 4's allowlist is
  built from exactly this list, and anything omitted becomes a false positive on
  real traffic.

**The fastest reachability answer is often the import graph, when a checkout is
on disk.** Many "component not in the artifact" cases close in one grep, before
any cluster call. A dependency can be pulled in for one narrow package while the
vulnerable component sits in a different part of the same module and never
compiles in. Read what the code actually imports and which endpoints it actually
serves:

```bash
grep -rhn 'github.com/<mod>/' <repo> --include='*.go' | grep -o '"github.com/<mod>/[^"]*"' | sort -u
grep -rn 'HandleFunc\|http.Handle\|ListenAndServe\|"/<path>"' <repo> --include='*.go' | grep -v _test.go
```

Worked live 2026-08-04 on `ollama-exporter`: 5 CVEs, all in
`github.com/prometheus/prometheus@v0.51.2`, all rated high on CVSS. The binary
imports exactly **one** package from that module — `prompb` — and serves only
`/metrics` and `/healthz`. The vulnerable components (the `/api/v1/read` server
handler, the `/-/config` endpoint, the entire web UI) are not compiled in, so all
5 are **n/a — component not in the artifact**, decided from the checkout without a
single `nv_*` call. Note the direction trap: `prompb` is used here as an
*outbound remote-write client*, so even the CVE in the remote-*read* server
handler that shares the module is unreachable — same package, opposite direction.
This is the same "which component is affected" reasoning [[fossa-suggest-score]]
step 3 uses; when the checkout is present it is a grep, not a judgment call.

**Correlate the scanned revision with the running artifact.** FOSSA scans a git
revision; the cluster runs an image. A floating tag such as `:latest` with
`imagePullPolicy: IfNotPresent` can be arbitrarily far from the commit FOSSA
analyzed — **in either direction**. The definitive check, when exec is
available, is to read the installed version out of the running container:

```
kubectl exec -n <ns> deploy/<name> -- sh -c \
  'python3 -c "import importlib.metadata as m; print(m.version(\"<pkg>\"))"'
```

(`python` may not be on PATH; try `python3` and known venv paths.) Fall back to
NeuVector's scan of the running image (`nv_list_image_scan_summaries` to find
it, then `nv_get_scan_report`, which needs both a `target` and a `target_id`
— it will not take a bare image name) when exec is not possible. If they cannot
be reconciled, say so — the findings describe the source tree, not necessarily
the process you are about to put a sensor in front of.

**The image scan answers nothing when the code is not in the image.** Check how
the application actually gets into the container before trusting a scan of it.
Observed live: a Deployment running a stock upstream language base image with
the entire application mounted in from a ConfigMap — a pattern that also shows
up with PVC mounts, initContainers that fetch source, and sidecar-populated
volumes. Scanning that image reports the base image's packages and says nothing
whatsoever about the dependency the CVE is in, while looking like a clean
correlation. In this shape the only real answers are exec-ing the installed
version out of the running process, or reading the mounted source itself; if
you can do neither, the correlation is **unestablished**, and that is what the
report should say.

**The running artifact can be *newer* than the findings.** Hit live 2026-07-31:
the repo manifest pinned a vulnerable version, but the image had been built with
the patched one — every finding was already closed as-deployed, and the honest
triage was "0 of N mitigable, nothing to mitigate". When this happens, say it
as the headline, reframe any sensors as defense-in-depth/canary (never CVE
mitigation), and make the manifest bump the recommended fix so the scanner
matches reality.

**A sensor bound to a dead or idle workload produces zero events and validates
nothing.** If the pods are down, say so before writing sensors — the user needs
to decide whether to fix the workload, probe the mechanism against a different
live group, or just stage the sensors unbound. Do not present a plan whose
validation step cannot run.

## 3. Triage — which CVEs a WAF can actually touch

Two questions per CVE, in order. The first is the gate:

1. *Is the vulnerable code path reachable in this deployment at all?* — answered
   from step 2, not from the CVE text. If not, mark it **n/a** and move on.
2. *Is there a regex over the URL, headers, body, or raw packet that
   distinguishes an attack request from a legitimate one?*

Classify each as **good / partial / none / n-a** and say why:

- **good** — the attack is a recognizable request shape. Missing or foreign
  `Origin`/`Host`, an unexpected `Upgrade: websocket`, a known exploit string.
- **partial** — the WAF narrows the attack surface but misses the real case. A
  malformed-session-id rule catches guessing and fuzzing but not a *stolen valid*
  session id.
- **none** — nothing in the request distinguishes it. Connection-lifecycle bugs,
  resource-exhaustion-by-valid-traffic, anything triggered by a well-formed
  request.
- **n/a** — the vulnerable transport, feature or code path is not enabled here.

A CVE that is **n/a** may still be worth a cheap one-pattern **canary** — an
`Upgrade: websocket` on a service that speaks only streamable HTTP is anomalous
by definition. Label it as a canary, never as mitigation of that CVE.

**When a finding is n/a because the vulnerable *component is not in the artifact*
— not merely because a transport is toggled off — a pre-position canary is a
recommended action, not just an option.** The realistic failure mode is not
today's build; it is a later build that adds the vulnerable surface while nobody
re-runs this skill, leaving it exposed with no control. A canary on the request
signature that *would* appear if the component were re-introduced closes that gap
for free. The decision belongs to the user, but recommend it: there is no harm in
it sitting inert and real cost if it is needed and absent.

It is safe **only** when the signature is one legitimate traffic never produces —
a path the binary does not serve (`/api/v1/read`, `/-/config` on an exporter that
serves only `/metrics`), a header it never sets. That makes it a **positive
match with no allowlist** (step 4), which cannot false-positive by construction.
Bind it in Discover/Monitor with `action: deny`: inert today, and it becomes a
real block the moment the group is moved to Protect — which for a
never-legitimate path is the behaviour you want. Worked live 2026-08-04 on
`ollama-exporter`: two `url` rules for `/api/v1/read` and `/-/config`, bound to
`nv.ollama-exporter.ai` in Discover, validated by the paired probe (both fired
server-side, `/metrics` stayed silent). Say plainly it covers the paths it
covers: the same run left the three Prometheus web-UI XSS CVEs uncovered because
stored XSS via injected metrics has no inbound request signature a WAF can match.

Order the table by consequence, not by CVSS. Reachability and exposure decide
which of these findings matters here, and raw CVSS routinely disagrees with that
ordering — [[fossa-suggest-score]] is the worked rubric for it, and its
reachability and exposure terms are the same judgments step 2 just made. Reuse
them rather than re-deriving an ad-hoc ranking.

Put this in a table with the CVSS and the real fix. **Do not inflate the count
of mitigable CVEs** — it is tempting to describe "partial" as covered, or to
count an n/a finding because you wrote a rule near it. State coverage
conservatively as an explicit tally ("of N findings: 1 good, 1 partial, 4 none")
and correct yourself immediately if you overclaimed.

## 4. Design the sensors

Semantics that drive the whole design:

- **Patterns within a rule are ANDed. Rules within a sensor are ORed.**
- `op: "regex"` fires on match. `op: "!regex"` fires when it does **not** match —
  this is how allowlists are written and it is very easy to get backwards.
- `context`: `url` | `header` | `body` | `packet`. **Set it on every pattern,
  explicitly.** The tool defaults `context` to `packet` when you omit it — and
  `packet` is the one mode whose matching behaviour the reference still marks
  UNVERIFIED, so an omitted `context` quietly opts you into the mode you were
  told not to rely on. It is also not what you meant: a header rule written
  without `context` matches raw bytes, not header lines. `header` (v5.6.0) and
  `url` (2026-08-04) are both verified live; `body` and `packet` are not — see
  step 7 and the reference.

**The `!regex` trap.** An over-narrow `!regex` fires on every legitimate request.
Never use a bare `!regex` where the field may be absent — "header missing"
and "header present but wrong" both fire, and the first is usually normal
traffic. Use the two-pattern shape instead, which needs no lookahead:

```
rule.origin-not-allowed:
  regex   header  (?i)origin:\s*http                              <- present
  !regex  header  (?i)origin:\s*https?://([a-z0-9-]+\.)*corp\.com <- and not allowed
```

Both must match, so a client that sends no `Origin` at all is untouched.

**Build the allowlist from the enumeration in step 2, not from memory.** The
allowlist half of a `!regex` is the highest-risk artifact in this whole skill:
every legitimate ingress path you forget becomes a false positive on production
traffic. Write them out and check them off — ingress hostname, LoadBalancer IP,
cluster IP, every service DNS form (`svc`, `svc.ns`, `svc.ns.svc`,
`svc.ns.svc.cluster.local`), pod CIDR, `localhost`/`127.0.0.1` — then confirm the
health probes: HTTP probes generate constant traffic and must be allowlisted,
while `tcpSocket` probes never reach the WAF at all.

Terminate an allowlist alternation with `(\s|$)` rather than a bare `$`. It
denies the `Host: allowed.example.com.evil.com` suffix bypass, and unlike `$` it
behaves the same whether the enforcer matches per-line or against the whole
header block — which is unverified either way (see step 7).

**The cheap shape: a positive match on a signature legitimate traffic never
produces — no allowlist at all.** The `!regex` allowlist above is the expensive,
error-prone half of this skill because it must enumerate every legitimate path.
When the attack signature is something *no* real request carries — a path the
service does not serve, a header it never sets — a single positive `regex` fires
on exactly the anomaly and nothing else, needs no enumeration, and cannot
false-positive by construction. This is the pre-position canary shape from step 3.
Reach for it first when the finding fits; it is faster to write and safer to run
than any allowlist. Live 2026-08-04, the whole sensor was two rules:

```
rule.remote-read-endpoint:  regex  url  (?i)/api/v1/read
rule.config-endpoint:       regex  url  (?i)/-/config
```

No allowlist, because `ollama-exporter` serves only `/metrics` and `/healthz` —
neither substring can appear in legitimate traffic. Do **not** anchor these with
`^/`: the `url` context may carry the method or scheme ahead of the path, so a
leading-slash anchor can silently never match. A cheap substring is both safer
and enough here.

Keep expressions cheap and anchored — the enforcer runs them on live traffic.
Avoid lookahead entirely; assume an RE2-like engine.

Naming: prefix sensors `sensor.` and rules `rule.`, matching NeuVector's own
convention so threat events stay readable.

**Constraint that bites: `comment` is capped at 256 characters.** The controller
rejects longer ones with HTTP 400 `code=6`, and that happens *after* you have
spent a confirm handshake — the plan step does NOT pre-validate length. "Count
before you send" means literally: run the comment through `len()` (or draft to
~230 characters) before the *first* handshake call. This trap was hit again
2026-07-31 despite this warning; eyeballing does not work.

## 5. Write them

Every mutating NeuVector tool is a **two-step handshake**: call without
`confirm` to get a plan plus a token, then call again with identical arguments
plus `confirm=<token>`. A plan is not a change — nothing reaches the controller.
Changing any argument invalidates the token; re-plan.

- `nv_create_waf_sensor(sensor_name, rules, comment)` — `comment` is optional
  and defaults to empty. Nothing forces you to write one and nothing validates
  its length until the controller rejects it, which is why step 4 says to count
  the characters yourself. Write one anyway: it is the only thing that explains
  this sensor to whoever inherits it.
- `nv_update_waf_sensor(sensor_name, rules)` — **replaces the rule list
  wholesale.** Always `nv_get_waf_sensor` first and send back existing rules plus
  your changes, or you silently delete detections.

**Tool arguments are not the wire body.** The reference documents the controller's
JSON, in which every pattern carries `"key": "pattern"`. The MCP tools reject
`key` as an extra field and add it themselves — pass only `op`, `value`,
`context`. Read the reference for controller behaviour, not for tool call shape.

Then **read every sensor back with `nv_get_waf_sensor`** and verify the regex
bodies, `op`, and `context` round-tripped exactly. Read-back returns rules
alphabetically rather than in creation order; that is harmless since rules are
ORed. A freshly created sensor has `groups: []` and inspects nothing.

## 6. Bind — never Protect first

`nv_set_waf_group(group_name, sensors=[{name, action}], status=true)`

- **This REPLACES the group's binding list.** `nv_get_waf_group` first. An empty
  list unbinds everything.
- `action: "deny"` does **not** block by itself. Blocking requires the group's
  policy mode to be Protect, set separately via `nv_set_group_policy_mode`.
- **Bind in Discover or Monitor. Never go straight to Protect.** Confirm the
  group's current mode before binding; if it is already Protect, stop and tell the
  user, because binding there takes effect on live traffic immediately and can
  break the app.

**Discover is fine to bind in, and is what you will usually find.** Learned
groups start there and most clusters never move them. Discover and Monitor behave
identically for WAF purposes — a match raises a threat event and the request
proceeds. Do not change a group's policy mode just to satisfy the word "Monitor";
policy modes stay untouched unless the user asks.

**There is no alert-only action.** The enum is `deny` | `allow` only. A `deny`
binding left on a Discover group is inert *today* and becomes live blocking the
moment anyone moves that group to Protect — possibly months later, by someone who
has no idea these sensors exist. Say this in the report, and say it again if the
rules have not been validated against live traffic yet.

Bind the narrowest set of groups that actually run the vulnerable code. Ask
before binding more.

## 7. Validate

Watch `nv_query_security_events(kind="threat", side="server")`, filtered to the
namespace, and compare against expected traffic.

**`side="server"` is mandatory.** The tool defaults to filtering the *client*
side of each event, and inbound attack traffic arrives as client
`Workload:ingress` with an **empty** client namespace — so a namespace-filtered
query on the default side returns zero events *while the rules are firing*,
which looks exactly like a dead rule. Hit live 2026-07-31: identical probes,
`side="client"` → 0 events, `side="server"` → all 4. Take a baseline query
before probing so events attribute by rule name rather than by guesswork.

**Verify that rules fire at all before trusting silence.** Silence means either
"no attacks" or "the rule never matches" and those look identical.
`context: "header"` matching raw `name: value` lines is **verified** (enforcer
v5.6.0), and `context: "url"` matching the request path is **verified**
(2026-08-04) — see the reference. The paired probe is still required per sensor:
it validates the allowlist enumeration and the regex, which matching semantics
cannot.

**The WAF inspects the request before the app answers — so a canary for an
endpoint that does not exist yet is still probeable.** The enforcer matches the
inbound request in the data path regardless of what the app returns. Live
2026-08-04: `GET /api/v1/read` and `GET /-/config` against `ollama-exporter`
both **404'd at the app** and both **fired their `url` canary** server-side, while
a clean `GET /metrics` (200) raised nothing. This is what makes the step-3
pre-position canary verifiable: you do not need the vulnerable surface to exist
to prove the rule catches the request that would reach it.

**Probe in pairs.** One attack request is not enough: it can tell you a rule
fired, but not that legitimate traffic is clean, and the two header-matching
failure modes are opposite. Send both, from a vantage point whose traffic
actually traverses the enforcer on its way to the pod — another pod in the
cluster, or the LoadBalancer IP from the LAN. A request to `localhost` inside the
target container proves nothing.

For a two-pattern header allowlist:

| Probe | Expected | If wrong |
|---|---|---|
| Clean — allowlisted `Host`, no `Origin` | **zero** events | rules match per-line, or the allowlist is incomplete → alerting on all traffic |
| Attack — foreign `Host` *and* `Origin` | rule fires | header matching is value-only → header-name rules never fire, and silence is meaningless |

For a positive-signature `url` canary the pair is simpler — a request to the
never-served path, and a request to a real one:

| Probe | Expected | If wrong |
|---|---|---|
| Attack — the anomalous path (`/api/v1/read`) | rule fires server-side | `url` matching not working, or the pattern over-anchored (`^/` trap) → canary is dead |
| Clean — a legitimately served path (`/metrics`) | **zero** events | the pattern is too broad and catches real traffic |

Only the pair distinguishes working / never-fires / fires-on-everything. Report
which of the three you actually established, and treat any rule you could not
probe as unvalidated rather than working.

Expect and pre-announce known false positives. A `!regex` on `body` will fire on
every bodyless request, including GETs that open an SSE stream — reason enough on
its own to stay out of Protect.

## 8. Report and leave a rollback

Close with: sensors created, groups bound, policy modes (unchanged unless asked),
known false positives, what remains unvalidated, and **the dependency upgrade
that actually fixes the CVEs.**

**If a step is refused or blocked, stop there and hand the decision back.** The
procedure has a safe resting state at every boundary: a created-but-unbound
sensor inspects nothing, and an unconfirmed plan has not reached the controller.
Say plainly which step was blocked, quote the exact call so the user can approve
it, and report the partial state as partial. Do not reach for another route to
the same mutation.

Rollback, in order:

1. `nv_set_waf_group(group_name=..., sensors=[])` — unbind; stops all inspection
2. `nv_delete_waf_sensor(sensor_name=...)` — check `groups` is empty first;
   deleting a bound sensor removes inspection silently and nothing reports the gap

The parameter is `sensor_name`, not `name`; every WAF tool takes `sensor_name` /
`group_name`, and both of these are mutating, so both need the plan-then-confirm
handshake from step 5. Rollback is the worst place to discover an argument-name
error, so pass them by keyword.

To find what a previous run left behind — the "review sensors created this way"
case — start from `nv_list_waf_sensors(name_prefix="sensor.")` for the sensors
and `nv_list_waf_groups(bound_only=true)` for the bindings, then
`nv_get_waf_sensor` for the regex bodies. A sensor that no group binds is inert
but still present, and it will not show up in a bindings-only listing.

**Watch for the opposite leftover: a binding to a sensor that no longer exists.**
`nv_list_waf_groups(bound_only=true)` marks each bound sensor with `exist`, and a
`deny` binding whose sensor was deleted reads back `exist: false`. It is inert —
there is nothing to inspect — but it is misleading noise, and if a sensor is later
created with that same name the stale binding silently adopts it. Observed live
2026-08-04: `nv.ollama-code-mcp.ai` carried two such bindings
(`sensor.ollama-code-mcp-canary`, `sensor.ollama-code-mcp-rebind`), both
`exist: false`. Clear them the same way as any binding — re-`nv_set_waf_group`
with the surviving (real) bindings only, which drops the dangling ones.

## Licensing track — quarantine, not WAF

Sections 1–8 turn a **vulnerability** into a **WAF sensor**. A second class of
FOSSA finding needs a different control: a **license conflict** that legally
blocks deployment — a copyleft (GPL / AGPL / LGPL) obligation or a denied license
inside a proprietary product, surfaced as a `licensing` issue (`policy_flag` /
`policy_conflict`). A WAF regex is meaningless here; there is no attack request to
match. The correct runtime action is to **stop the workload from being reached at
all** until the conflict is resolved — a compliance hold enforced in the data
path.

**Enforcement primitive: NeuVector workload quarantine** — not a WAF sensor, not
a policy-mode flip.

- `PATCH /v1/workload/{id}` with
  `{"config":{"quarantine":true,"quarantine_reason":"…"}}` severs all traffic to
  and from the container, **independent of the group's policy mode**.
  `cap_quarantine:true` on the workload confirms it is available; a GET reads back
  `quarantine_reason:"user-configured"`. Lift with `{"config":{"quarantine":false}}`.
- **Do NOT reach for network `policy_mode=Protect` to isolate.** Protect enforces
  the group's *learned* baseline, so a group that saw legitimate traffic in
  Discover keeps allowing it after the flip — observed live 2026-08-03, the pod
  stayed reachable under Protect. Quarantine is the override that actually walls
  it off.

Procedure:

1. **Pull licensing findings.** `fossa_list_issues(category="licensing",
   scope_type="project", project_locator=…, revision_locator=…)` — project scope
   still requires `revision_locator`. Group by `license` and `type`.
   `policy_conflict` and copyleft `policy_flag` (GPL / AGPL / LGPL) are the
   block-before-deploy set; a permissive-notice flag usually is not — say which is
   which, and do not quarantine over a notice obligation.
2. **Map the finding to a running workload.** The FOSSA project is a repo; the
   cluster runs a pod. Confirm which deployment actually ships the offending code
   and that it is the artifact the license issue is in — the same correlation
   discipline as step 2 of the WAF track. Quarantining the wrong pod is an outage
   for nothing.
3. **Confirm the target and blast radius before cutting.** Quarantine stops the
   service completely — an intended outage, appropriate for something that legally
   must not ship, but state it plainly and get the go-ahead. Name the pod, the
   license, and what resolves it. This is the irreversible-*enough* boundary that
   warrants a confirmation even in this lab.
4. **Quarantine.** Via an `nv_*` quarantine tool if one is connected (two-step
   confirm handshake, like every mutating nv tool); otherwise the raw controller
   API above (find the id with `nv_list_workloads` / `GET /v1/workload`). Record
   the `quarantine_reason` with CVE-equivalent detail: the license, its SPDX id,
   and the FOSSA issue URL, so whoever finds the walled-off pod knows why.
5. **Verify the wall.** Probe the service from a **neighbour pod** (its traffic
   traverses the enforcer), never from inside the target. Before: reachable.
   After: connection refused / no route to host. A quarantine you did not probe is
   unverified — the same rule as validating a sensor.
6. **Report + rollback.** State the workload quarantined, the license that drove
   it, the reachability proof, and the one-line lift (`quarantine:false`) plus the
   real fix — swap the copyleft dependency, obtain a commercial license, or get a
   documented policy exception. The safe resting state is un-quarantined; leave it
   reachable unless the user asked for the hold to stay on.

**Honesty for the talk track:** a quarantine is a blunt, total cut — the right
tool when the answer is "this must not run," the wrong tool when the service has
to keep serving. It buys time to resolve a legal blocker without shipping the
violation; it is not a fix, and it ends the moment someone lifts it. Say both.

## Scope

This skill reads FOSSA and writes NeuVector. It does **not** change the target
repository. If the fix is a version bump — it usually is — recommend it and let
the user decide; raise it as its own task rather than editing their code here.

Wire-level details, verified controller behaviour, and gotchas that are not in
the API docs: `references/waf-wire-contract.md`.

Pre-staged fix instructions for the demo projects (react2shell-app and
license-conflict-demo), so the remediation line is in context ahead of a live
run: `references/remediation.md`. Stable fields only — EPSS and revision stay
live.
