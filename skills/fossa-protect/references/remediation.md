# Remediation reference — demo projects

Pre-staged so the picker (§1a) and the report (§8 / licensing step 6) do not
re-derive the fix on stage. This file holds the **stable** half of the answer:
locators, the CVE↔package map, the track, and the version bump that actually
closes each finding. It does **not** hold the volatile half — **EPSS percentile
and revision SHA move (EPSS daily, the SHA on every push), so re-pull those
live every run.** Reading a percentile or a "score" off this file and speaking
it as current is the one thing this file must never be used for.

Scope is exactly two projects — the beat-5 encore. Log4Shell and the Struts app
are out of scope here; the Struts sensor lives in `neuvector-demo/`, not FOSSA.

Calibration date: **2026-08-04**, verified against the revisions named below.
The bumps are stable across a re-scan in a way the percentiles are not, but they
still move when upstream publishes — confirm the headline bump on the day.

---

## react2shell-app — 🛡️ WAF track

- Locator: `git+github.com/darthzen/react2shell-app`
- Revision on 2026-08-04: `$4f6d616c` — **re-pull `latestRevision.locator`.**
- Shape: **7 vulnerabilities, all one package** — `react-server-dom-webpack@19.0.0`,
  a direct (depth-1) runtime dependency. One version bump, not seven fixes.

### The fix — say this line

**Bump `react-server-dom-webpack` to `19.0.8`.** That is the package `completeFix`
and it clears all seven CVEs at once. If you only name one number, name `19.0.1`:
it is a **patch** bump that closes the CVSS 10.0 unauthenticated RCE
(CVE-2025-55182), the single finding that carries the beat.

### Per-CVE, for the drill-down (re-verify distances on the day)

| CVE | CVSS | partialFix | distance |
|---|---|---|---|
| CVE-2025-55182 | 10.0 | 19.0.1 | PATCH |
| CVE-2025-55184 | 7.5 | 19.0.2 | PATCH |
| CVE-2025-55183 | 5.3 | 19.0.2 | PATCH |
| CVE-2026-23864 | 7.5 | 19.0.4 | PATCH |
| CVE-2026-23869 | 7.5 | 19.0.5 | PATCH |
| CVE-2026-23870 | 7.5 | 19.0.6 | PATCH |
| CVE-2026-44907 | 7.5 | 19.0.8 | PATCH |

Every fix is a patch bump — there is no major-version wall here, which is worth
saying out loud: the dev-side fix is cheap, and the WAF sensor buys the window
until it merges, not forever.

### The runtime control

CVE-2025-55182 is the WAF-shaped one: the RCE arrives as a recognizable request
shape on the Server Function endpoint, so a sensor over request context can drop
it. The DoS CVEs (resource exhaustion by well-formed request) are largely **none**
on the triage rubric — do not let the 🔴 band promise sensors for all seven. Step 3
decides that live against the deployment; this file does not pre-judge it.

---

## license-conflict-demo — ⚖️ quarantine track

- Locator: `git+github.com/darthzen/license-conflict-demo`
- Revision on 2026-08-04: `$11943ea4` — **re-pull `latestRevision.locator`.**
- Shape: **14 `policy_flag` rows that collapse to one dependency.** All 14 are
  LGPL-3.0-or-later on `@img/sharp-*` — per-architecture builds of `sharp`
  (libvips), all transitive (depth 2). **No `policy_conflict` in the set.** One
  linkage judgment, one remediation. Carry the 14 as fan-out context, never as
  14 problems.

### The fix — say this line

There is **no version bump**; this is a policy decision, not a CVE. The real
fixes, in order of how often they apply:

1. **Confirm the obligation is not triggered.** LGPL's copyleft reaches only
   *static* linking. `sharp` loads `libvips` as a dynamically-loaded native addon —
   dynamic linkage, obligation not triggered. If that holds, the finding is a
   flag to document, not a blocker, and the honest answer is "no quarantine needed."
2. **If it must be treated as a blocker** — swap `sharp` for a permissively
   licensed image library, obtain a commercial `libvips` license, or record a
   documented policy exception in FOSSA.

### The runtime control

Quarantine is the blunt instrument for "this legally must not ship" — a total
cut of the workload, independent of policy mode. It buys time to resolve the
legal blocker without shipping the violation. Given the dynamic-linkage read
above, the honest talk track is that the quarantine is the *demonstration of the
control*, not a claim that this specific dependency legally requires isolation —
say which you mean.

---

## What stays live — do not pre-stage these

- **EPSS percentile** — moves daily. Re-pull; expand the row if the peak lands on
  a CVE other than the worst-CVSS one (§1a).
- **Revision SHA** — moves on push. Take `latestRevision.locator` from the live
  `fossa_list_projects`, never from this file.
- **The running artifact** — the image may already be patched past these findings
  (step 2). If it is, the headline flips to "already fixed as-deployed" and the
  sensor becomes defense-in-depth. This file describes the source tree, not the
  pod.
- **Creating or arming any sensor.** The demo opens insecure and is armed live.
  Nothing here is a pre-arm.
