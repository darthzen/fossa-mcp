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
- `streamable-http` remains available but binds `127.0.0.1` by default. Keep it that way.
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
