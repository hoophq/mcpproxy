# Container image

This repo ships no Dockerfile. Both cloud guides build on the image below.

Read [README.md](README.md) first for the constraints that shape it.

## Choosing a base

The daemon `exec`s each stdio backend's `command:` directly, so the image
must contain that command's runtime. This is the single most common
deployment failure.

| Backends | Base | Notes |
|---|---|---|
| remote only (`transport: streamable-http`) | `gcr.io/distroless/static` | nothing is spawned |
| stdio via `npx` | `node:22-slim` | all ten stdio examples here |
| stdio via `uvx` | `python:3.13-slim` + `uv` | |

Get this wrong and the daemon starts, passes health checks, and fails every
`initialize` with `502 failed to start session`.

## Dockerfile

```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0: no cgo in the daemon, and a static binary runs on any base.
RUN CGO_ENABLED=0 go build -trimpath -o /out/mcpproxyd ./cmd/mcpproxyd
RUN CGO_ENABLED=0 go build -trimpath -o /out/configcheck ./cmd/configcheck

# node:22-slim because the stdio backends below run under npx. Use
# gcr.io/distroless/static for a remote-only config.
FROM node:22-slim
RUN useradd --create-home --uid 10001 mcpproxy
COPY --from=build /out/mcpproxyd /usr/local/bin/
COPY --from=build /out/configcheck /usr/local/bin/

# Pre-install the MCP servers you actually use. Without this, `npx -y`
# reaches registry.npmjs.org on the session hot path: every initialize
# pays the download, and an npm outage becomes your outage.
RUN npm install -g @modelcontextprotocol/server-everything@2026.7.4

# HOME matters: the default state dir is $HOME/.mcpproxy, and an unset HOME
# resolves it to /.mcpproxy at the filesystem root. Set it explicitly anyway.
# The VOLUME below is created root-owned, so a non-root USER cannot write
# to it. Create and chown it first, or the daemon dies at startup with
# "wal: create dir ...: permission denied".
RUN mkdir -p /var/lib/mcpproxy && chown 10001:10001 /var/lib/mcpproxy
USER 10001
ENV HOME=/home/mcpproxy \
    MCPPROXY_STATE_DIR=/var/lib/mcpproxy
VOLUME /var/lib/mcpproxy

COPY config.yaml /etc/mcpproxy/config.yaml
EXPOSE 8080
ENTRYPOINT ["mcpproxyd", "-config", "/etc/mcpproxy/config.yaml"]
```

Pin the MCP server version. `npx -y some-server` resolves to whatever is
latest at session start, which is a live dependency on third-party code
inside your security gateway. Rug-pull detection catches a catalog that
changes mid-session, not one that changed between deploys.

## Config

`listen` must bind `0.0.0.0`; the `127.0.0.1:8000` default accepts no
traffic from outside the container. `${VAR}` expands anywhere in the file,
so `${PORT}` works where the platform assigns a port.

```yaml
listen: 0.0.0.0:${PORT}

inbound:
  mode: oidc
  issuer: https://your-idp.example.com
  audience: mcpproxy

backends:
  everything:
    transport: stdio
    command: ["npx", "-y", "@modelcontextprotocol/server-everything"]

approvals:
  api_token: ${MCPPROXY_APPROVAL_TOKEN}

telemetry:
  prometheus_path: /metrics

wal_dir: /var/lib/mcpproxy/sessions
```

Validate before shipping — `configcheck` is in the image for exactly this:

```sh
docker run --rm --entrypoint configcheck -e PORT=8080 \
  -v "$PWD/config.yaml:/c.yaml" your-image /c.yaml
```

`--entrypoint` is required: the image's ENTRYPOINT is `mcpproxyd`, so a
bare `docker run your-image configcheck /c.yaml` passes `configcheck` to
the daemon as an argument and starts the server instead.

## Verify the image

Do not trust a container that merely starts. Exercise a real MCP session,
which is what proves the stdio runtime is present:

```sh
docker run -d --name mcpproxy -p 8080:8080 -e PORT=8080 your-image

curl -fsS localhost:8080/healthz            # -> ok

SID=$(curl -sD- -o/dev/null -X POST localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2025-11-25","capabilities":{},
       "clientInfo":{"name":"probe","version":"1"}}}' \
  | awk -F': ' '/[Mm]cp-[Ss]ession-[Ii]d/{print $2}' | tr -d '\r')

curl -sS -X POST localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

A `tools/list` that returns tools means the backend spawned. A `502` on
`initialize` means the runtime is missing from the base image.

Check that shutdown reaps children, since an orphaned MCP server outliving
its session is a credential-holding process nobody is watching. `node:22-slim`
ships no `ps`, so read `/proc` directly:

```sh
# one leaf MCP server per live session
docker exec mcpproxy sh -c \
  'c=0; for d in /proc/[0-9]*; do
     tr "\0" " " < $d/cmdline 2>/dev/null \
       | grep -q "^node /usr/local/bin/mcp-server-everything" && c=$((c+1))
   done; echo $c'

docker stop -t 60 mcpproxy
```

Each session actually spawns a three-process tree (`npm exec` → `sh` →
`node`), which is why teardown signals the whole process group rather than
the direct child.

## Image hygiene

- Run as non-root. The daemon needs no privileges; it binds an unprivileged
  port and spawns children as the same user.
- Do not bake secrets. `${VAR}` expansion at config load is the intended
  path; inject through the platform's secret manager.
- `mcpproxyd -version` prints the build tag, `dev` unless you set
  `-ldflags "-X main.version=vX.Y.Z"`.
- A read-only root filesystem works if `MCPPROXY_STATE_DIR` and `wal_dir`
  are writable mounts.
