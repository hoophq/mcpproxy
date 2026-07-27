# Running mcpproxy

## Build

```sh
go build -o bin/mcpproxyd   ./cmd/mcpproxyd    # the gateway daemon
go build -o bin/mcpsmoke    ./cmd/mcpsmoke     # scripted MCP test client
go build -o bin/configcheck ./cmd/configcheck  # config validator
```

Requires Go 1.26+. For stdio backends using `npx`/`uvx`, Node/Python must
be on the daemon's PATH.

## First run

```sh
bin/mcpproxyd -config examples/01-minimal-stdio.yaml -debug
```

```sh
# another terminal — full round-trip: initialize → tools/list → tools/call
bin/mcpsmoke -url http://127.0.0.1:8000/mcp -tool echo -args '{"message":"hi"}'

# or just the catalog
bin/mcpsmoke -url http://127.0.0.1:8000/mcp -list-only
```

Connect a real client (Claude Code, Cursor, MCP Inspector) by adding a
streamable-HTTP MCP server pointing at `http://127.0.0.1:8000/mcp`.

## Configuration

One YAML file; `${VAR}` expands from the environment (keep secrets out of
files). Validate without starting:

```sh
bin/configcheck examples/*.yaml
```

Start from an example (see [`examples/`](../../examples) — 01 to 13 cover
every option; `examples/remote/` lists known public remote MCP servers).

Flags: `-config <path>` (default `config.yaml`), `-debug`.

## Operating

### Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /mcp` | one JSON-RPC message |
| `GET /mcp` | SSE stream (server-initiated messages) |
| `DELETE /mcp` | end session |
| `GET /healthz` | liveness |
| `GET /metrics` | Prometheus (if configured) |
| `GET /approvals/` + `POST /approvals/{id}/approve\|reject` | review API |

### Approvals

```sh
export T=$MCPPROXY_APPROVAL_TOKEN
curl -s -H "Authorization: Bearer $T" http://127.0.0.1:8000/approvals/ | jq
curl -X POST -H "Authorization: Bearer $T" http://127.0.0.1:8000/approvals/<id>/approve
```

Held calls block the client until resolved; `approvals.timeout`
auto-rejects.

### Sessions on disk

With `wal_dir` set, each session appends JSONL audit events:

```sh
jq -r '[.time, .event, .tool // "", .reason // ""] | @tsv' sessions/<sid>.jsonl
```

### State

- `$MCPPROXY_STATE_DIR` (default `~/.mcpproxy`): OAuth tokens + DCR client
  registrations, AES-256-GCM encrypted (`tokens.key` is the keyfile —
  protect and back it up together with `tokens.enc`).
- Embedded auth-server sessions/codes are memory-only; restarts require
  clients to re-authenticate.

### Lifecycle

- SIGINT/SIGTERM → graceful shutdown: HTTP drain, then every session's
  backends closed (stdio children process-group killed).
- Idle sessions are reaped after 30 minutes without traffic.
- A backend dying (stdio child exit, remote failure) ends that session;
  the client re-initializes to get a fresh one.

## Debugging

- `-debug` logs every gateway decision plus stdio children's stderr.
- `tool_denied` in logs but the tool looks allowed? Remember deny wins
  over allow, and overrides un-alias before policy — check the REAL tool
  name in the audit event's `rule`/`reason`.
- OAuth backend stuck? Watch the daemon log for the authorize URL; grants
  land in `~/.mcpproxy`. Delete that dir to force re-authorization.
- `mcpsmoke` prints raw JSON-RPC for every exchange — fastest way to see
  what the gateway actually returned.
- Orphan check after hard kills: `pgrep -f <your mcp server command>`
  should return nothing once the daemon is down.

## Production notes

- Run one daemon per trust boundary; a single instance multiplexes many
  sessions and backends.
- Put TLS in front (reverse proxy) — the daemon listens plaintext.
- Set `inbound.mode` to something real (`oidc`, `github`, `awssts`) before
  exposing beyond localhost; `approvals.api_token` must be set or the
  review API is open.
- Alert on `mcp.session_killed` (rug pull), `mcp.guardrail_block`, and
  `mcpproxy_messages_total{decision="kill"}`.
