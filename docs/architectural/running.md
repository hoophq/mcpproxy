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
# another terminal: full round-trip, initialize → tools/list → tools/call
bin/mcpsmoke -url http://127.0.0.1:8000/mcp -tool echo -args '{"message":"hi"}'

# or only the catalog
bin/mcpsmoke -url http://127.0.0.1:8000/mcp -list-only
```

Connect a real client (Claude Code, Cursor, MCP Inspector) by adding a
streamable-HTTP MCP server pointing at `http://127.0.0.1:8000/mcp`.

## Configuration

One YAML file; `${VAR}` expands from the environment, which keeps secrets
out of the file. Validate without starting:

```sh
bin/configcheck examples/*.yaml
```

Start from an example in [`examples/`](../../examples), numbered 01 to 13
across every option; `examples/remote/` lists known public remote MCP
servers.

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

A held call blocks its client until a reviewer resolves it, or until
`approvals.timeout` auto-rejects.

### Sessions on disk

With `wal_dir` set, each session appends JSONL audit events:

```sh
jq -r '[.time, .event, .tool // "", .reason // ""] | @tsv' sessions/<sid>.jsonl
```

### State

- `$MCPPROXY_STATE_DIR` (default `~/.mcpproxy`): outbound OAuth tokens,
  AES-256-GCM encrypted. `tokens.key` is the keyfile, so protect it and
  back it up alongside `tokens.enc`. Losing the key while keeping the
  ciphertext makes the daemon fail to start.
- DCR client registrations are **not** persisted: the daemon leaves the
  client store unset, so each restart re-registers with the upstream
  authorization server.
- The embedded auth server keeps sessions and codes in memory, so clients
  re-authenticate after a restart.

### Lifecycle

- SIGINT/SIGTERM starts a graceful shutdown: HTTP drains, then the gateway
  closes every session's backends and process-group kills stdio children.
- The reaper ends sessions idle for 30 minutes.
- A dying backend (stdio child exit, remote failure) ends that session,
  and the client re-initializes to get a fresh one.

## Debugging

- `-debug` logs every gateway decision plus stdio children's stderr.
- Seeing `tool_denied` on a tool that looks allowed points at two causes:
  deny beat allow, or overrides un-aliased the name before policy ran.
  Check the REAL tool name in the audit event's `rule` and `reason`.
- For a stuck OAuth backend, watch the daemon log for the authorize URL;
  grants land in `~/.mcpproxy`. Delete that directory to force
  re-authorization.
- `mcpsmoke` prints raw JSON-RPC for every exchange, which is the quickest
  way to see what the gateway returned.
- Orphan check after hard kills: `pgrep -f <your mcp server command>`
  should return nothing once the daemon is down.

## Production notes

- Run one daemon per trust boundary; a single instance multiplexes many
  sessions and backends.
- Put TLS in front with a reverse proxy; the daemon listens plaintext.
- Set `inbound.mode` to something real (`oidc`, `github`, `awssts`) before
  exposing beyond localhost. Set `approvals.api_token` too, or the review
  API is open.
- Alert on `mcp.session_killed` (rug pull), `mcp.guardrail_block`, and
  `mcpproxy_messages_total{decision="kill"}`.
