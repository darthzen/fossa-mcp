---
name: fossa-protect
description: Turn a project's FOSSA vulnerability findings into NeuVector WAF sensors and push them to the cluster. Use when asked to mitigate, compensate for, or "protect against" CVEs found by FOSSA, to write WAF sensors/rules for a project's dependencies, or whenever FOSSA findings and NeuVector need to be connected. Also use when asked to review or roll back sensors created this way.
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

## 1. Pull the findings

Resolve the project first — never guess a locator:

- `fossa_list_projects(title=...)` → the locator (e.g. `git+github.com/org/repo`).
  If the project was not named, `sort="issues-security_desc"` puts the candidates
  worth asking about at the top; offer those rather than the whole inventory.
- `fossa_list_issues(category="vulnerability", scope_type="project",
  project_locator=..., revision_locator=...)` — **project scope requires
  `revision_locator` as well**, or the call fails validation. Take it from the
  project's `latestRevision.locator`.
- `fossa_get_issue(...)` for anything whose CVE detail you actually need

Group findings by **package**, not by CVE. Five CVEs in one dependency is one
version bump, and that reframing is usually the most useful thing you can tell
the user.

## 2. Establish what is actually deployed

Do this **before** triage, not after. Triage is not answerable in the abstract:
whether a CVE is reachable at all depends on how this deployment is configured,
and getting that backwards means writing a sensor for something that cannot fire.

Confirm the workloads are running and serving traffic:

- `nv_list_workloads` / `kubectl get pods -n <ns>`
- `nv_list_groups(name_prefix="nv.<service>")` — plain listing truncates and is
  alphabetical, so the group you want may simply not be on the page
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
NeuVector's scan of the running image (`nv_get_scan_report`,
`nv_list_image_scan_summaries`) when exec is not possible. If they cannot be
reconciled, say so — the findings describe the source tree, not necessarily the
process you are about to put a sensor in front of.

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
- `context`: `url` | `header` | `body` | `packet`.

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

- `nv_create_waf_sensor(sensor_name, comment, rules)`
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
`context: "header"` matching raw `name: value` lines is now **verified**
(enforcer v5.6.0, see the reference) — header-name anchoring works. The paired
probe is still required per sensor: it validates the allowlist enumeration and
the regex, which matching semantics cannot.

**Probe in pairs.** One attack request is not enough: it can tell you a rule
fired, but not that legitimate traffic is clean, and the two header-matching
failure modes are opposite. Send both, from a vantage point whose traffic
actually traverses the enforcer on its way to the pod — another pod in the
cluster, or the LoadBalancer IP from the LAN. A request to `localhost` inside the
target container proves nothing.

| Probe | Expected | If wrong |
|---|---|---|
| Clean — allowlisted `Host`, no `Origin` | **zero** events | rules match per-line, or the allowlist is incomplete → alerting on all traffic |
| Attack — foreign `Host` *and* `Origin` | rule fires | header matching is value-only → header-name rules never fire, and silence is meaningless |

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

1. `nv_set_waf_group(group, sensors=[])` — unbind; stops all inspection
2. `nv_delete_waf_sensor(name)` — check `groups` is empty first; deleting a bound
   sensor removes inspection silently and nothing reports the gap

## Scope

This skill reads FOSSA and writes NeuVector. It does **not** change the target
repository. If the fix is a version bump — it usually is — recommend it and let
the user decide; raise it as its own task rather than editing their code here.

Wire-level details, verified controller behaviour, and gotchas that are not in
the API docs: `references/waf-wire-contract.md`.
