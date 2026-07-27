# The inspection pipeline

Every JSON-RPC message crossing the gateway — client→server (C2S) and
server→client (S2C) — flows through an ordered chain of checks. The first
non-Allow verdict wins; checks may also mutate the message in place and
still allow it.

## Verdicts

| Verdict | Effect |
|---|---|
| `Allow` | forward the (possibly mutated) message |
| `Deny` | replace a request with a JSON-RPC error; the session survives |
| `Hold` | park the call until a human approves (or timeout rejects) |
| `Kill` | tear down the whole session |

Gateway error codes: `-32010` policy denied, `-32011` approval rejected,
`-32012` budget exceeded.

## Canonical order (`checks.Assemble`)

```
budget → policy → approval → s2c-gate → rug-pull → overrides → guardrails → redact → audit-tap
```

The order is load-bearing:

- **budget before policy** — an exhausted session refuses even allowed
  tools; the counter is the admission ticket.
- **rug-pull before overrides** — fingerprints must cover what the server
  actually sent; an operator's description rewrite must not trip detection.
- **every pre-override check un-aliases first** — checks resolve the real
  (pre-rename) tool name via the session's rename map, so an override alias
  cannot launder a denied or approval-gated call.
- **audit-tap last, always Allow** — it observes the post-mutation message,
  i.e. what the client/backend will actually see.

## What each check does

| Check | C2S | S2C |
|---|---|---|
| `budget` | max calls/session, per-tool sliding-window rate limits | truncates oversized results (text leaves only, UTF-8 safe, `[truncated by gateway]` marker) |
| `policy` | deny/allow globs; refuses tools never advertised in a received `tools/list` | filters denied/non-allowlisted tools OUT of the catalog |
| `approval` | Hold on `approval_tools` match (Deny if no store wired — fail closed) | — |
| `s2c-gate` | — | denies `sampling/createMessage` and `elicitation/create` unless explicitly allowed; the error answers the SERVER's request id |
| `rug-pull` | invalidates on `notifications/tools/list_changed` | fingerprints every tool (name + description + input schema, SHA-256); a change on a known tool → Kill (default) or audit alert |
| `overrides` | rewrites aliased `tools/call` names back to real names | renames tools / replaces descriptions in the catalog |
| `guardrails` | `Hooks.GuardInput` over `tools/call` arguments → Deny | over tool descriptions → Kill (poisoned catalog) |
| `redact` | — | `Hooks.Redact` over `result.content[].text` and `resources/read` contents |
| `audit-tap` | `mcp.tool_call` (args as SHA-256 digest, never verbatim) | `mcp.tools_listed` |

## Session state (`session.State`)

Checks are stateless; the session carries the memory:

- **pending map** — JSON-RPC id → {method, tool, backend}. Responses carry
  no method, so correlation is the only way to know a response answers
  `tools/call` vs `tools/list`.
- **tool catalog + fingerprints** — populated by the rug-pull check from
  `tools/list` responses; consulted by policy's unadvertised-tool refusal.
- **counters** — budget's call counts.
- **Meta** — typed scratch space per check (rename maps, rate windows,
  catalog-listed flag).

## Approvals flow

```
client tools/call ──▶ approval check: Hold
                        │  gateway parks the request, emits mcp.approval_pending
                        ▼
        GET  /approvals/            reviewer lists pending calls
        POST /approvals/{id}/approve  → call proceeds to the backend
        POST /approvals/{id}/reject   → client gets -32011, session lives
        (timeout → auto-reject)
```

The client's POST simply blocks while held — MCP clients already tolerate
slow tools, so no protocol extension is needed.

## Audit events

Stable vocabulary (see `audit/audit.go`): `mcp.session_start/end/killed`,
`mcp.initialize`, `mcp.tools_listed`, `mcp.tool_call`, `mcp.tool_result`,
`mcp.tool_denied`, `mcp.tools_changed`, `mcp.server_request[_denied]`,
`mcp.approval_pending/resolved`, `mcp.budget_exceeded`, `mcp.redacted`,
`mcp.guardrail_block`, `mcp.error`. Every event carries session, user,
backend, tool, rule, reason. Sinks fan out (log + WAL by default);
arguments are recorded as digests, never raw.
