# mcpproxy

A security gateway for MCP (Model Context Protocol) servers. It terminates
streamable-HTTP MCP on the front, inspects every JSON-RPC message in both
directions, and bridges to one or more backends: local stdio subprocesses
or remote MCP endpoints.

```
MCP client ──HTTP──▶ mcpproxyd ──▶ stdio child (npx some-mcp-server)
             auth      │ inspect       └─▶ remote MCP (https://…/mcp)
                       │ policy
                       │ audit
```

## Why

Your agent calls MCP servers with real credentials, and those servers are
third-party code you did not write. Put mcpproxy on that path and you get:

- **Policy:** allow/deny tools by glob. mcpproxy strips denied tools from
  `tools/list`, so the model never sees them.
- **Approvals:** hold flagged tool calls until a human approves them over
  the REST API.
- **Rug-pull detection:** fingerprint every tool (name, description, input
  schema). If a fingerprint changes mid-session, mcpproxy kills the session
  or raises an alert.
- **Server-request gating:** the gateway denies `sampling/createMessage`
  and `elicitation/create` from the server by default, whether the server
  asks directly or embeds the ask in a `2026-07-28` `input_required` result.
- **Budgets:** max calls per session, per-tool rate limits, result-size
  truncation.
- **Audit:** structured events (`mcp.tool_call`, `mcp.tool_denied`,
  `mcp.tools_changed`, …) to logs and per-session JSONL replay files.
- **Auth, all three planes:** inbound (who may talk to the gateway: OIDC,
  GitHub, AWS STS, static token), outbound (how the gateway auths to MCP
  servers: static headers, passthrough, full OAuth with discovery + DCR +
  PKCE + refresh, RFC 8693 token exchange), and an embedded OAuth
  authorization server so MCP clients can OAuth against the gateway itself.
- **Aggregation:** several backends behind one endpoint. mcpproxy prefixes
  tools `<backend>_<tool>` and routes each call to its backend.
- **Telemetry:** Prometheus metrics and OTLP traces per message.

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

One YAML file. mcpproxy expands `${ENV_VAR}` references at load. Full
schema in [`config/config.go`](config/config.go); [`examples/`](examples/)
covers every option:

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

Public remote MCP servers (Linear, Notion, GitHub, Stripe, Sentry, …) with
ready-to-run configs: [`examples/remote/`](examples/remote/).

Architecture, auth planes, pipeline internals, operations, and embedding
guide: [`docs/architectural/`](docs/architectural/).

## Deployment

Running it outside hoop, on GCP or AWS: [`docs/deployment/`](docs/deployment/).
Start with [the constraints page](docs/deployment/README.md) — the daemon
keeps sessions, approvals, and auth-server state in memory, so it is
single-replica by construction and a round-robin load balancer in front of
two instances answers `404 unknown session`. That page also covers the
container image, TLS termination, state volumes, and the exposure
checklist; 

## HTTP surface

| Endpoint | Purpose |
|---|---|
| `POST /mcp` | one JSON-RPC message (initialize starts a session; later messages carry the `Mcp-Session-Id` header) |
| `GET /mcp` | SSE stream of server-initiated messages for the session. The gateway queues 64 of them; when the stream drains slower than the server sends, or is not open, the oldest is dropped, a dropped server request gets an error reply, and the backend pump never waits |
| `DELETE /mcp` | end the session |
| `GET /approvals/` | pending held tool calls (bearer: `approvals.api_token`) |
| `POST /approvals/{id}/approve` \| `/reject` | resolve a held call |
| `GET /healthz` | liveness |
| `GET /metrics` | Prometheus (when `telemetry.prometheus_path` set) |
| `/.well-known/*`, `/authorize`, `/token`, `/register`, `/callback` | embedded auth server (when `auth_server` set) |

## Protocol revisions

mcpproxy serves the session-based MCP revisions through `2025-11-25`.

It recognizes `2026-07-28` (the stateless revision) and refuses it with a
conformant `-32022` naming `2025-11-25`, so a dual-era client retries on the
session path instead of failing. A request whose mirrored `Mcp-Method` /
`Mcp-Name` / `MCP-Protocol-Version` headers disagree with its body is
rejected with `-32020`: an intermediary routing on the header and the gateway
executing the body would otherwise act on different requests.

The refusal is deliberate. Several controls — rug-pull detection, per-session
call budgets, and override un-renaming — decide by comparing across requests
in a session. Serving them statelessly today would not weaken them, it would
silently disable them, because each no-ops when its state is empty. The list
lives in `Gateway.statelessBlockers`; when it empties, the stateless path can
be served.

## Session recording

With `wal_dir` set, mcpproxy writes one append-only JSONL file per session,
one line per audit event, replayable for review:

```sh
cat sessions/<sid>.jsonl | jq -r '[.time,.event,.tool // "",.reason // ""] | @tsv'
```

## State

mcpproxy stores outbound OAuth tokens under `$MCPPROXY_STATE_DIR` (default
`~/.mcpproxy`), encrypted with AES-256-GCM under a generated keyfile. DCR
client registrations are not persisted, so a restart re-registers. The
embedded auth server keeps its sessions in memory.

## Embedding

The daemon is thin wiring over the library packages. Hosts such as hoop
embed the gateway and supply their own implementations of:

- `inspect.Hooks`: guardrails, data masking, AI analysis callbacks
- `audit.Sink`: event stream consumer
- `gateway.HeldStore`: approval workflow backend
- `gateway.IdentityResolver`: inbound identity (skip `auth/inbound` when
  the host already authenticated the caller)
- `gateway.Observer`: telemetry

Import it the way any Go dependency is imported:

```sh
go get github.com/hoophq/mcpproxy@v0.1.0
```

## Releases

Releases are cut by CI from merged PRs; nobody tags by hand. Every PR needs
exactly one label, which `PR Release Label Check` enforces before merge:

| Label | Effect on merge to `main` |
|---|---|
| `major` | `vX.Y.Z` → `v(X+1).0.0` |
| `minor` | `vX.Y.Z` → `vX.(Y+1).0` |
| `patch` | `vX.Y.Z` → `vX.Y.(Z+1)` |
| `skip-release` | no tag, no release (docs, CI, refactors) |

`Auto Release` then creates the `vX.Y.Z` tag and GitHub release — that tag
is what `go get github.com/hoophq/mcpproxy@vX.Y.Z` resolves. `Binary Release`
chains off it and attaches `mcpproxy_X.Y.Z_<os>_<arch>.tar.gz` (`.zip` on
Windows) for darwin/linux/windows on amd64 and arm64, plus `checksums.txt`.
Each archive holds all four commands, `README.md`, `config.example.yaml` and
`examples/`. Re-publish binaries for an existing tag with the `Binary Release`
workflow's manual trigger.

Going to `v2` requires the major suffix in the module path
(`github.com/hoophq/mcpproxy/v2`); `Auto Release` refuses to tag until
`go.mod` matches.
