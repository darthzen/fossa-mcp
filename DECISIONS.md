# Decisions

Durable decisions for this project, with the reasoning. Each exists because the
"obvious" alternative looks correct and would be wrong. Read before changing any
of them.

---

## 1. Pin `mcp` to 1.28.x. Do not upgrade to 2.x yet.

**Decided 2026-07-29.**

`mcp[cli]>=1.28.1,<1.29`

MCP Python SDK **2.0.0 exists** (released 2026-07-28) and `FOSSA_MCP_IMPLEMENTATION_SCOPE.md`
§4.2/§5 instruct using it. We are deliberately not, because this server is published to Docker Hub
for external businesses to depend on, and 2.0.0 has no patch releases yet.

1.28.1 (released 2026-06-26) is the last 1.x with meaningful soak time. Note 1.29.0 shipped the
same day as 2.0.0 — also too new.

**Consequences:** `mcp.server.fastmcp.FastMCP` is the correct API for this build, not `MCPServer`.
Scanners will flag the pin as behind 2.x. That is expected — do not auto-bump, and do not let a
dependency bot do it.

**Revisit when** 2.0.x has patch releases and real-world use. The migration is mechanical but not
trivial: 2.0.0 renames `fastmcp` → `mcpserver` and `FastMCP` → `MCPServer`, moves model fields to
snake_case (`read_only_hint`, `input_schema`), and relocates `Context` to
`mcp.server.mcpserver.context`. Keep the tool layer thin so the swap stays cheap.

---

## 2. Single-tenant only. Do not add multi-tenant auth.

**Decided 2026-07-29.**

Each operator runs their own container with their own `FOSSA_API_TOKEN`. One token per process,
supplied via environment at run time.

This is a **product constraint, not a technical limitation.** Multi-tenant FOSSA hosting is FOSSA,
Inc.'s own business and we are deliberately not building toward competing with it.

**Consequences:**

- `FOSSA_API_TOKEN` from the environment is the correct and complete auth model. Do not add
  `token_verifier`, OAuth, or per-request credential plumbing.
- `stdio` is the default transport and the intended deployment shape.
- `streamable-http` remains available but binds `127.0.0.1` by default. Keep that default.
  **Kubernetes is the one sanctioned exception:** a pod must bind `0.0.0.0` or the Service can never
  reach it, so `lab-fleet/09-mcp/fossa-mcp.yaml` sets `FOSSA_HTTP_HOST=0.0.0.0`.
- **The sdf1 deployment is reachable at `https://fossa-mcp.ash4d.com/mcp`** (Traefik Ingress,
  cert-manager `letsencrypt-dns`). This is a LAN-scoped exposure, not a public one: the Cloudflare
  record is public but points at the private Traefik address `192.168.7.150`, so it resolves
  everywhere and connects only from inside the network. Only `/mcp` is routed; `/healthz` stays
  cluster-internal.

  The boundary that makes this acceptable is the private target address, nothing else — the server
  still authenticates no callers, so anyone who reaches that host gets the token's full read access.
  A Cloudflare Tunnel, a public A record, or a LoadBalancer on a routable address all cross that
  boundary and require an authenticating middleware in front first.
- `FossaClient` is a single lifespan-scoped instance with one connection pool. Correct *because* of
  this decision; it would be wrong under multi-tenancy.
- **The server executes every request with the single token it was started with.** Exposing the HTTP
  transport to multiple users grants them all of that token's access. This must stay documented in
  the README.

---

## 3. Apache-2.0, not MIT.

**Decided 2026-07-29.**

The full runtime dependency tree (36 packages at `mcp` 1.28.1) is permissive — MIT, BSD-2/3-Clause,
Apache-2.0, ISC, MIT-0, PSF-2.0 — with no GPL, LGPL, or AGPL. Every inbound license is compatible
with any permissive outbound license, so compatibility did not constrain the choice; it was made on
merit for distribution to businesses:

- **Explicit patent grant (§3)**, which MIT lacks. Enterprise legal review routinely flags that gap.
- **Explicit trademark disclaimer (§6)**, which matters here — see below.
- **NOTICE mechanism (§4)** carries the unofficial-tool disclaimer through redistribution.

**Obligations to keep meeting:**

- `certifi` is **MPL-2.0** — weak, file-level copyleft. It constrains nothing in our code (we do not
  modify it), but container images redistribute its binary, so its license text must ship in the
  image. Ship a consolidated third-party license file at a documented path.
- SUSE BCI base images carry SUSE's own terms, independent of our Apache-2.0 grant. Do not conflate
  them in documentation.

---

## 4. This is an unofficial tool. Keep saying so.

**Decided 2026-07-29.**

"FOSSA" is a trademark of FOSSA, Inc., used here nominatively to identify the API this software
talks to. The project is not affiliated with, endorsed by, or supported by FOSSA, Inc.

The disclaimer must appear in `NOTICE`, the README, the OCI image description, and the Docker Hub
overview. Do not adopt FOSSA branding, and do not attribute authorship to FOSSA — an earlier draft
of `pyproject.toml` listed `support@fossa.com` as the package author, which was incorrect and is
exactly the failure mode to avoid.

---

## 5. The server is no longer wholly read-only. Policy and package-block writes are permitted.

**Decided 2026-07-31. This reverses part of decision-adjacent scope set on 2026-07-29.**
**Amended 2026-07-31** — see "Correction" at the end of this entry. Two claims made here about
what the FOSSA API does not support were inferred from the vendored spec and are false of the live
API. They are struck through below rather than deleted, because the entry is also a record of how
the mistake was made.

`FOSSA_MCP_IMPLEMENTATION_SCOPE.md` §3.3 lists "policy modification" as out of scope, and the README
promised "this version is read-only and does not modify FOSSA state." Both were accurate and both
are now partly obsolete: the server can assign a FOSSA security policy to a project and turn on the
enforcement that blocks packages violating it.

This was an explicit, informed product call — the read-only guarantee was named as the cost and
accepted. The scope document is a frozen requirements artifact and is deliberately **not** edited to
match; this entry is the record that the two now disagree, and this entry wins.

**What is writable, and nothing else:**

| Tool | Tier | Endpoint | Effect |
|------|------|----------|--------|
| `fossa_enable_security_policy` | write | `PUT /projects/{locator}` | Sets `securityPolicyId`, `securityIssueScanningEnabled`, `securityStatusCheckEnabled` |
| `fossa_assign_security_policy_to_projects` | write | `PUT /v2/projects/policy` | Assigns one policy id to explicitly named projects |
| `fossa_block_package` | write | `POST /packages/{locator}/rules` | Adds a `blacklisted_dependency` rule for one package to named quality policies |
| `fossa_unblock_package` | destructive | `PUT /policies/{id}/rules` | Replaces a quality policy's whole rule set with the rules surviving that package's removal |

Everything else in §3.3 stays out of scope. Issue ignoring, project deletion, label modification,
license conclusions, and disputes remain unimplemented.

**Consequences:**

- **`FOSSA_ALLOW_WRITES` defaults to false and must stay that way.** Every write tool refuses before
  issuing any request when it is off. A server that is merely *capable* of writing is not the same
  risk as one that will; under decision 2 every caller shares one token, so the default must be the
  safe one. `tests/test_mcp_integration.py` asserts a default-configured server refuses every write.
- The bulk endpoint's "apply to all projects matching these filters" mode is deliberately not
  exposed. `locators` is always an explicit list. A model that misreads a filter should not be able
  to re-policy an entire organization in one call.
- `FossaClient` retries the `PUT` writes. That is safe because each assigns or replaces whole state
  rather than accumulating, so a replay converges. `POST /packages/{locator}/rules` is a `POST` and
  is therefore never replayed (`_IDEMPOTENT_METHODS`), even though FOSSA happens to treat it
  idempotently — the retry loop stays verb-driven, not endpoint-driven.
- `readOnlyHint` is now per-tool rather than blanket. The integration test partitions the tool list
  into declared read and write sets and fails if a tool's annotation disagrees with its set. It
  checks `destructiveHint` against the destructive set the same way.
- **`fossa_unblock_package` is `DESTRUCTIVE`, not `WRITE`.** FOSSA has no delete for one rule; the
  only removal mechanism replaces the policy's entire rule set, with no ETag, `If-Match`, or version
  precondition on offer. Its blast radius is every rule on the policy rather than the one named, and
  two concurrent unblocks silently clobber each other. That is the tier boundary from decision 7 —
  tier follows blast radius, not verb.

~~**Why there is no "block this package" tool:** FOSSA has no per-package block primitive. A package
is blocked by an assigned security policy raising a vulnerability issue against it and the CI status
check then failing the build. `fossa_enable_security_policy` turns that combination on; that *is* the
block. Nor is there a create-policy or list-policies endpoint in the vendored spec, so policies are
authored in the FOSSA web app and addressed here by the numeric id in their URL.~~

**Correction — 2026-07-31.** Both claims in the struck paragraph are wrong about the live API. They
were true of the *documented* surface and were generalized to the product, which is the error worth
remembering: the vendored spec is a description of what FOSSA documents, not of what FOSSA does.

1. **FOSSA does have a per-package block primitive.** It is a `blacklisted_dependency` rule on a
   **QUALITY** policy, created by `POST /api/packages/{locator}/rules`. Chelsea Boling (Principal CS
   Engineer, FOSSA) corrected this directly; it was then confirmed empirically — the block dialog's
   policy selector offers only quality policies, and a security policy cannot receive a block rule at
   all. The security policy tools do real work but **are not the blocking mechanism**.
2. **`GET /api/policies` exists** and lists every policy with its full rule set, type, and
   `latestVersion`. Policies still have to be authored in the web app, but they no longer have to be
   addressed by reading an id out of a URL. No tool wraps this endpoint yet.

Neither endpoint appears anywhere in the vendored OpenAPI spec, and FOSSA owes no stability on
either. Both were captured from the FOSSA web app's own traffic and then verified against the live
API; the verified request schemas live in `src/fossa_mcp/tools/packages.py` and are pinned by
`tests/test_package_tools.py`. The capture notes themselves are kept outside this repository —
mapping a vendor's undocumented API surface is not something this project publishes.

---

## 6. The local policy overlay may only tighten, never loosen.

**Decided 2026-07-31.**

`FOSSA_POLICY_FILE` points at a JSON document of local security rules — CVSS ceilings, denied CVEs,
denied packages — evaluated by `fossa_evaluate_security_policy` on top of FOSSA's own findings.

**An active FOSSA vulnerability finding always blocks, and no local rule can clear it.** Exceptions
in the overlay suppress blocks the *overlay itself* introduced and nothing more. The asymmetry is
the design: a file on the MCP server's disk must not be able to wave through a live finding from the
system of record, because the resulting verdict would look authoritative while being weaker than
what FOSSA says. `tests/test_policy.py` pins this.

**Consequences:**

- Exceptions require a `reason` and should carry an `expires` date. An expired exception stops
  applying and is reported on the verdict, so a package does not silently revert to blocked with no
  explanation.
- A configured-but-broken policy file raises rather than degrading to "no policy." A typo in a path
  must not quietly weaken the security posture.
- The file is JSON, not YAML. YAML reads better, but every runtime dependency is enumerated in
  `NOTICE` and the generated third-party license file per decision 3, and policy file ergonomics do
  not justify adding PyYAML to that tree.
- `projectDefaultStatusCheckFilterVulnerability` (FOSSA's status-check severity threshold) is
  reported verbatim and never interpreted. Its integer scale is undocumented in the vendored
  OpenAPI spec — do not invent a mapping for it.

---

## 7. Full API parity is the goal. Coverage is tiered, not ungated.

**Decided 2026-07-31.** Requested directly; the driver was a FOSSA engineer asking for complete
write coverage during an interview.

The target is all 271 documented operations — 157 `GET`, 114 write. `FOSSA_MCP_IMPLEMENTATION_SCOPE.md`
§3.3 forbids most of this. That document is a frozen requirements artifact and stays unedited; this
entry supersedes it, and `API_PARITY_PLAN.md` holds the domain inventory and running status.

**Consequences:**

- **Tool shape is a tiered hybrid, not 1:1.** Individual tools for domains an operator drives by
  hand; grouped `section`/`action` tools for configuration long tails. Organization Settings is 57
  operations of near-identical `get/patch/put` triples and becomes ~3 tools, not 57. Target is ~60
  tools for 271 operations — 271 tools would exceed what MCP clients handle, and selection accuracy
  degrades well before that limit.
- **Grouped tools still validate `section` against a `Literal`.** An unknown section must fail at
  the client as a schema error, not reach FOSSA as a 404. This is what keeps a grouped tool from
  degenerating into the generic `fossa_request` proxy that §3.3 rules out — that exclusion stands.
- **Three write tiers, none implying another** (`src/fossa_mcp/writes.py`): `WRITE`, `DESTRUCTIVE`
  (deletes, wholesale replacements, and unbounded bulk targets), `ADMIN` (SAML, OIDC, roles,
  service accounts, team membership). Higher tiers require `FOSSA_ALLOW_WRITES` alongside their own
  flag, so a half-configured deployment fails closed.
- **Tier follows blast radius, not HTTP verb.** `PUT /v2/projects/policy` with `locators=all`
  re-policies an entire organization from one call, so it is `DESTRUCTIVE` despite being a `PUT`.
  A `PUT` that overwrites a whole record or settings section rather than merging into it is
  `DESTRUCTIVE` for the same reason: a caller who omits a key erases it, and FOSSA has no undo.
  This is why `fossa_update_org_settings` requires `DESTRUCTIVE` for `action="replace"` and not
  only for `action="propagate"` — the tool advertises `destructiveHint=True` on both grounds, and
  the gate has to say what the hint says.
- **`POST` and `PATCH` are never retried** (`client.py`, `_IDEMPOTENT_METHODS`). A replayed create
  is a duplicate team or a duplicate service account. Do not make the retry loop uniform.
- **The ADMIN tier should stay off on the sdf1 deployment.** Under decision 2 the server
  authenticates no callers and shares one token; `https://fossa-mcp.ash4d.com/mcp` is reachable
  from anywhere on the LAN. Identity and access-control writes behind an unauthenticated endpoint
  are a materially different exposure from reading dependency lists, and the private target address
  is the only boundary in place.
