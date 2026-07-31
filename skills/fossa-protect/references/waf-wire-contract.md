# NeuVector WAF wire contract

Behaviour verified against a live NeuVector 5.4 controller, not read from docs.
The NeuVector API reference (Appendix B) documents **no WAF schema at all**, so
none of this is inferable — it was established by writing to a controller and
reading the result back.

Treat anything marked UNVERIFIED as a live risk, not a detail.

## Endpoints and envelopes

| Operation | Call | Response key |
|---|---|---|
| List sensors | `GET /v1/waf/sensor` | `sensors` |
| Get sensor | `GET /v1/waf/sensor/{name}` | `sensor` |
| Create sensor | `POST /v1/waf/sensor` | — |
| Update sensor | `PATCH /v1/waf/sensor/{name}` | — |
| Delete sensor | `DELETE /v1/waf/sensor/{name}` | — |
| List WAF groups | `GET /v1/waf/group` | `waf_groups` |
| Get WAF group | `GET /v1/waf/group/{name}` | `waf_group` |
| Bind sensors | `PATCH /v1/waf/group/{name}` | — |
| Rule catalogue | `GET /v1/waf/rule` | `rules` |

Both sensor writes wrap the body in `{"config": {...}}`.

## Sensor body

```json
{"config": {
  "name": "sensor.example",
  "comment": "<= 256 characters",
  "cfg_type": "user_created",
  "rules": [
    {"name": "rule.example",
     "patterns": [
       {"key": "pattern", "op": "regex", "value": "<regex>", "context": "header"}
     ]}
  ]
}}
```

- `key` is always the literal string `"pattern"` **on the wire**. The MCP tool
  layer rejects `key` as an extra field and supplies it itself — pass only `op`,
  `value` and `context` to `nv_create_waf_sensor` / `nv_update_waf_sensor`. This
  document describes the controller's JSON, not the tool signature.
- `op` is `regex` or `!regex`. **`!regex` is supported and round-trips.**
- `context` is `url` | `header` | `body` | `packet`.
- `rules` **REPLACES** the sensor's entire rule list on PATCH. Omitted rules are
  deleted silently.

## Group binding body

```json
{"config": {
  "name": "nv.app.namespace",
  "status": true,
  "replace": [{"name": "sensor.example", "action": "deny"}]
}}
```

- `replace` **REPLACES** the whole binding list; an empty list unbinds everything.
- There is a sibling `delete` key that takes **bare name strings, not objects**.
  Passing objects returns `code 6 "Request in wrong format"`. Prefer `replace`
  only — it expresses every state `delete` can.
- `status` toggles inspection for the group without touching bindings.

## Field-name traps

- The sensor field is **`predefine`**, not `predefined`. Reading `predefined`
  yields `False` for every shipped sensor, which misreports them as user-editable.
  Read `predefine` with `predefined` as fallback only.
- `GET /v1/waf/rule` returns **`sensor: ""`** for every entry — the controller does
  not populate it. The owning sensor is recoverable from the rule name, which the
  controller formats as `<sensor>_nVwAfCtR.<rule>`.
- `log4shell` and `spring4shell` ship with NeuVector but report
  `predefine: false` / `cfg_type: user_created`. They genuinely are editable and
  deletable — this is not a field-name bug.

## Validation the controller enforces

- `comment` > 256 characters → HTTP 400, `code=6`,
  `"Request in wrong format / Comment exceed max 256 characters!"`.
  Rejected **after** the confirm handshake is spent.
- Duplicate sensor name → rejected.
- Predefined sensors cannot be updated or deleted.

## Regex engine

Assumed RE2-like. **UNVERIFIED.** Inline flags such as `(?i)` are accepted on
write and round-trip intact, but acceptance on write does not prove the enforcer
evaluates them the same way. Avoid lookahead and backreferences entirely — express
"present AND not allowlisted" as two ANDed patterns instead. Assume no
catastrophic-backtracking protection and keep expressions anchored and cheap; they
run on live traffic.

**Terminate allowlist alternations with `(\s|$)`, not a bare `$`.** A bare `$`
means different things depending on whether the enforcer matches per-line or
against the whole header block — which is unresolved (below) — while `(\s|$)`
behaves correctly under either. Omitting the boundary entirely is worse than
both: `Host: allowed.example.com.evil.com` satisfies an unbounded allowlist and
walks straight past the rule.

## The header-context question — VERIFIED 2026-07-31 (enforcer v5.6.0)

**`context: "header"` matches raw `name: value` lines. Header-name anchoring
works.** Established with a live paired probe against an HTTP service on a
non-standard port (8765), enforcer v5.6.0:

- Attack probes with foreign `Host:`/`Origin:`, an `Upgrade: websocket`, and a
  malformed `Mcp-Session-Id:` each fired exactly the rule written against that
  header name — patterns of the form `(?i)host:` and
  `(?i)origin:\s*http` match against the `name: value` text.
- A clean request (allowlisted `Host`, no `Origin`) produced **zero** events
  across four bound rules including two two-pattern `!regex` allowlists — so the
  two-pattern shape does not false-positive on other header lines.
- One request matching two rules raises **two separate threat events**, one per
  rule.

Per-line vs whole-block matching is still not fully distinguished — both are
consistent with the observations above — but both behave correctly for the
two-pattern `present AND not-allowlisted` shape, which is the only shape this
skill emits. A bare single-pattern `!regex` on a header name remains untested
and should still be avoided.

The paired probe remains the required validation for every *new* sensor: it
verifies the allowlist enumeration and the regex itself, not just the matching
semantics. Probe from a vantage point that traverses the enforcer (another pod,
or the LoadBalancer IP from the LAN); a request to `localhost` inside the target
container proves nothing. `context: "packet"` as a fallback is still UNVERIFIED.

## Operational notes

- Creating a sensor changes nothing. It inspects only once bound to a group, and
  blocks only when that group is in **Protect** mode. Discover and Monitor raise a
  threat event and let the request proceed.
- Matches surface via `nv_query_security_events(kind="threat")` — **but the
  tool's `side` parameter defaults to `"client"`, and for inbound attacks the
  victim workload is the SERVER side.** Traffic entering via a LoadBalancer or
  ingress is attributed to client `Workload:ingress` with an **empty** client
  namespace, so a namespace-filtered query with the default side returns zero
  events even while rules are firing — indistinguishable from "rule never
  matches". Always pass `side="server"` when validating WAF sensors.
- Threat events carry `name` = `WAF.<sensor>.<rule>`, `threat_id` = the rule id
  (40000+), `action` = `alert` in Discover/Monitor, and the target as
  `server_name`/`server_namespace`.
- A cluster typically has hundreds of WAF groups with almost none bound — use
  `nv_list_waf_groups(bound_only=true)`.
- Read-back orders rules alphabetically, not by creation or id. Harmless: rules
  are ORed.
- Rule ids are assigned by the controller in creation order starting at 40000.
