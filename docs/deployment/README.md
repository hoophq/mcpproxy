# Deploying mcpproxy

Guides for running the standalone daemon outside hoop:

- [gcp.md](gcp.md): Cloud Run and GKE
- [aws.md](aws.md): ECS Fargate and EKS
- [container.md](container.md): the image every cloud guide builds on

Read this page first. Every constraint below applies to both clouds, and
each one has bitten a plausible deployment plan.

## The daemon is single-replica by construction

All mutable state lives in Go maps in one process. Nothing is shared,
coordinated, or externalized:

| State | Where | Consequence |
|---|---|---|
| MCP sessions | `sess map[string]*conn` ([gateway/gateway.go](../../gateway/gateway.go)) | a session is served by exactly one process |
| Held approvals | in-memory, holds live channels and timers ([approval/store.go](../../approval/store.go)) | a restart drops pending approvals |
| Embedded auth server | five maps plus the signing key ([auth/authserver/store.go](../../auth/authserver/store.go)) | a restart logs everyone out |
| stdio children | one process group per session ([backend/stdio.go](../../backend/stdio.go)) | pinned to the process that spawned them |

Start with **one replica** and scale vertically. That is not a placeholder
recommendation; the sections below are what you must solve before a second
replica is correct.

### Sessions require affinity, and the failure is a 404

`initialize` mints a random session id and stores the connection in a
process-local map. Every later request presents `Mcp-Session-Id`, and the
lookup is a bare map read: a miss returns `404 unknown session`
([gateway/http.go](../../gateway/http.go)).

Two daemons, a session opened on the first, one request sent to the second:

```
initialize on A -> 200 session: 456561d29fc6354bb20940410b314428
A's session -> A  : 200 OK
A's session -> B  : 404 Not Found      <-- round-robin LB
   body: unknown session
```

Behind a round-robin load balancer with N replicas, roughly (N-1)/N of
post-initialize requests fail this way. Clients see intermittent 404s, not
a clean outage, which is the worst kind of failure to debug.

If you must run more than one replica, the load balancer has to hash on the
`Mcp-Session-Id` **request header**. Cookie-based stickiness does not help:
MCP clients are not browsers and will not return a cookie. This rules out
AWS ALB's built-in stickiness, which is cookie-based in both its
duration-based and application-based forms. GCP can do it with
`HEADER_FIELD` affinity; see [gcp.md](gcp.md).

### Approvals cannot be load balanced at all

Session affinity does not rescue the review API. A reviewer is a different
client, on a different path, with no session header, and the approval id
lives in the URL. No routing rule can send `POST /approvals/{id}/approve`
to the replica holding that call, and the wrong replica returns 404.

Run one replica if you use approvals.

### The embedded auth server is worse

Its OAuth legs arrive from three different user agents (the MCP client
registers, a browser authorizes and hits the callback, the client redeems
the code) with no shared routing key. Register on A and authorize on B and
you get `400 invalid_client`. Each replica also publishes a different JWKS,
cached for an hour.

Do not run `auth_server` with more than one replica. Set
`auth_server.signing_key_file` to a mounted path, or the key is regenerated
on every restart and every previously issued token breaks.

## Storage

Two directories, with opposite sharing rules.

**`$MCPPROXY_STATE_DIR`** (default `~/.mcpproxy`, created `0700`) holds
exactly two files: `tokens.enc`, the AES-256-GCM sealed outbound OAuth
grants, and `tokens.key`, the raw 32-byte key at `0600`.

- Give each replica its **own** state dir. The write path is atomic
  (temp + rename) but the mutex is process-local with no file lock, so
  concurrent replicas clobber each other's grants last-writer-wins, and
  each runs its own refresh loop against the same rotating refresh token.
- Persist it if any backend uses `auth: oauth`. If the key is regenerated
  against a surviving `tokens.enc`, the daemon **fails to boot** with a
  wrong-key error rather than starting fresh.
- Re-authorizing an OAuth backend needs the loopback browser flow, which is
  impossible in a headless container. Seed the grant locally and mount the
  resulting files, or use `auth: static` / token exchange instead.
- The default depends on `$HOME`. A container without `HOME` set resolves
  the state dir to `/.mcpproxy` at the filesystem root. Always set
  `MCPPROXY_STATE_DIR` explicitly.

**`wal_dir`** is the one thing that is safe to share. Session ids are
128-bit random and each session owns its own `<sid>.jsonl`, so filenames
never collide. Records are buffered (32 KiB) and fsynced when the session
ends, so a `SIGKILL` loses the tail of every live session. Give the daemon
at least 60s to shut down.

## Base image

The daemon spawns `command:` directly, so a `scratch` or `distroless` image
fails for stdio backends with `exec: not found`, surfacing as
`502 failed to start session`. All ten stdio examples in this repo use
`npx`, so the image needs Node (and Python if you use `uvx`). Remote-only
configs (`transport: streamable-http`) have no such requirement and can use
a minimal image.

`npx -y` also downloads from the npm registry on the session hot path. Bake
your MCP servers into the image instead; see [container.md](container.md).

## Sizing

Live child processes = sessions × stdio backends. They are not pooled. Size
`pids` limits and memory accordingly, and budget about 3 fds per child.

## Shutdown

`SIGTERM` drains HTTP for up to 10s, then closes every session, which
process-group kills stdio children (`SIGTERM`, then `SIGKILL` after a 3s
grace). Worst case is roughly 6.25s per backend after the drain. Allow
**at least 60s** of termination grace; a shorter window truncates WAL
records and can orphan children.

Verified locally: three live sessions, `SIGTERM`, zero orphaned children.

## Exposure checklist

The daemon serves **plaintext HTTP only**. There is no TLS field in the
config. Terminate TLS at the load balancer.

Before exposing it beyond localhost:

- [ ] `listen: 0.0.0.0:<port>` — the default `127.0.0.1:8000` accepts no
      external traffic. `${PORT}` expands, which Cloud Run needs.
- [ ] `inbound.mode` set to `oidc`, `github`, `awssts`, or `static`. The
      default is `anonymous`, and `local` resolves the OS user once at
      startup, which is meaningless in a container.
- [ ] `approvals.api_token` set. Empty means the review API is
      unauthenticated: `GET /approvals/` returns `200 []` to anyone.
- [ ] `MCPPROXY_STATE_DIR` set explicitly.
- [ ] `auth_server.signing_key_file` set if `auth_server` is enabled.

### Known rough edge

With `inbound.mode: oidc` and no `auth_server`, the daemon advertises its
RFC 9728 resource identifier as `"http://" + listen`
([cmd/mcpproxyd/main.go](../../cmd/mcpproxyd/main.go)). Behind a
TLS-terminating load balancer that publishes something like
`http://0.0.0.0:8080` to clients, and there is no config override. Clients
that rely on protected-resource discovery will not find the gateway; point
them at the issuer directly.

## Health checks

`GET /healthz` returns `200 ok` and is always registered. It reports
process liveness only — not backend health — which is what you want for a
liveness probe, since a dead backend should end one session, not restart
the daemon.

## Metrics

Set `telemetry.prometheus_path` to expose `/metrics`. Useful series:

- `mcpproxy_messages_total{direction,method,tool,decision,backend}`
- `mcpproxy_message_duration_seconds{direction,backend,method}`

Alert on `decision="kill"` (rug pull) and on `mcp.guardrail_block` in the
logs.

`mcpproxy_sessions_active` is exported but **always reads 0**. The
increment and decrement calls exist in `telemetry` but nothing in the
daemon or gateway invokes them. Do not build an alert on it.
`examples/12-observability.yaml` advertises the gauge; that comment is
misleading.

The `tool` label is unbounded by design. A backend exposing many tools
gives you one series per tool.
