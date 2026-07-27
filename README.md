# mcpproxy

A security gateway for MCP (Model Context Protocol) servers. It terminates
streamable-HTTP MCP on the front, inspects every JSON-RPC message in both
directions, and bridges to one or more backends — local stdio subprocesses or
remote MCP endpoints.

```
MCP client ──HTTP──▶ mcpproxyd ──▶ stdio child (npx some-mcp-server)
             auth      │ inspect       └─▶ remote MCP (https://…/mcp)
                       │ policy
                       │ audit
```

## Why

MCP servers are arbitrary third-party code that your AI agent calls with real
credentials. mcpproxy puts a control point between them:

- **Policy** — allow/deny tools by glob; tools removed from the catalog are
  invisible to the model, not just blocked.
- **Approvals** — hold flagged tool calls until a human approves via REST API.
- **Rug-pull detection** — fingerprint every tool (name, description, input
  schema); a mid-session change kills the session or raises an alert.
- **Server-request gating** — `sampling/createMessage` and
  `elicitation/create` from the server are denied by default.
- **Budgets** — max calls per session, per-tool rate limits, result-size
  truncation.
- **Audit** — structured events (`mcp.tool_call`, `mcp.tool_denied`,
  `mcp.tools_changed`, …) to logs and per-session JSONL replay files.
- **Auth, all three planes** — inbound (who may talk to the gateway: OIDC,
  GitHub, AWS STS, static token), outbound (how the gateway auths to MCP
  servers: static headers, passthrough, full OAuth with discovery + DCR +
  PKCE + refresh, RFC 8693 token exchange), and an embedded OAuth
  authorization server so MCP clients can OAuth against the gateway itself.
- **Aggregation** — several backends behind one endpoint; tools are prefixed
  `<backend>_<tool>` and routed automatically.
- **Telemetry** — Prometheus metrics and OTLP traces per message.

## Quick start

```sh
go build -o bin/mcpproxyd ./cmd/mcpproxyd
go build -o bin/mcpsmoke  ./cmd/mcpsmoke

bin/mcpproxyd -config examples/01-minimal-stdio.yaml

# in another terminal: initialize → tools/list → tools/call echo
bin/mcpsmoke -url http://127.0.0.1:8000/mcp \
  -tool echo -args '{"message":"hello"}'
```

Point any MCP client (Claude Code, Cursor, MCP Inspector) at
`http://127.0.0.1:8000/mcp` as a streamable-HTTP server.

## Configuration

One YAML file. `${ENV_VAR}` references are expanded. Full schema in
[`config/config.go`](config/config.go); every option is demonstrated in
[`examples/`](examples/):

| Example | Shows |
|---|---|
| [01-minimal-stdio](examples/01-minimal-stdio.yaml) | smallest useful config: one stdio backend |
| [02-remote-static-auth](examples/02-remote-static-auth.yaml) | remote MCP with an API-key/bearer header |
| [03-policy](examples/03-policy.yaml) | allow/deny globs, budgets, rug-pull mode, catalog overrides |
| [04-approvals](examples/04-approvals.yaml) | human review of flagged tool calls + curl walkthrough |
| [05-aggregation](examples/05-aggregation.yaml) | many backends, one endpoint, per-backend policy |
| [06-inbound-oidc](examples/06-inbound-oidc.yaml) | callers authenticate with IdP-issued JWTs |
| [07-inbound-github-awssts](examples/07-inbound-github-awssts.yaml) | GitHub-token and AWS-STS inbound modes |
| [08-outbound-oauth](examples/08-outbound-oauth.yaml) | OAuth to a remote MCP: discovery, DCR, PKCE, refresh |
| [09-outbound-passthrough](examples/09-outbound-passthrough.yaml) | per-user upstream credential supplied by the client |
| [10-auth-server](examples/10-auth-server.yaml) | embedded OAuth AS + upstream IdP federation + token swap |
| [11-token-exchange](examples/11-token-exchange.yaml) | RFC 8693: exchange the caller's token for an upstream one |
| [12-observability](examples/12-observability.yaml) | Prometheus, OTLP traces, session WAL, optimizer |
| [13-kitchen-sink](examples/13-kitchen-sink.yaml) | everything at once, commented |

## HTTP surface

| Endpoint | Purpose |
|---|---|
| `POST /mcp` | one JSON-RPC message (initialize starts a session; `Mcp-Session-Id` header carries it on) |
| `GET /mcp` | SSE stream of server-initiated messages for the session |
| `DELETE /mcp` | end the session |
| `GET /approvals/` | pending held tool calls (bearer: `approvals.api_token`) |
| `POST /approvals/{id}/approve` \| `/reject` | resolve a held call |
| `GET /healthz` | liveness |
| `GET /metrics` | Prometheus (when `telemetry.prometheus_path` set) |
| `/.well-known/*`, `/authorize`, `/token`, `/register`, `/callback` | embedded auth server (when `auth_server` set) |

## Session recording

With `wal_dir` set, every session writes an append-only JSONL file of audit
events — one line per protocol event, replayable for review:

```sh
cat sessions/<sid>.jsonl | jq -r '[.time,.event,.tool // "",.reason // ""] | @tsv'
```

## State

OAuth tokens and DCR client registrations persist under
`$MCPPROXY_STATE_DIR` (default `~/.mcpproxy`), AES-256-GCM encrypted with a
generated keyfile. The embedded auth server's sessions are memory-only.

## Embedding

The daemon is thin wiring over library packages; hosts (e.g. hoop) embed the
gateway and supply their own seams:

- `inspect.Hooks` — guardrails, data masking, AI analysis callbacks
- `audit.Sink` — event stream consumer
- `gateway.HeldStore` — approval workflow backend
- `gateway.IdentityResolver` — inbound identity (skip `auth/inbound` if the
  host already authenticated the caller)
- `gateway.Observer` — telemetry
