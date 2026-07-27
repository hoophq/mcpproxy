# Embedding the gateway

`cmd/mcpproxyd` is thin wiring over library packages. A host application
such as hoop's agent embeds the same gateway and swaps the seams. Nothing
in `gateway/` or `checks/` knows about the daemon.

## Minimal embedding

```go
factories := map[string]backend.Factory{
    "files": backend.NewFactory("files", config.Backend{
        Transport: "stdio",
        Command:   []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", dir},
    }, nil),
}

gw, err := gateway.New(gateway.Options{
    Backends: factories,
    Pipeline: checks.Assemble(pol, hooks, sink, true),
    Resolver: resolver,   // identity
    Sink:     sink,       // audit
    Held:     heldStore,  // approvals
    Observer: observer,   // telemetry
})
// gw.Handler() is an http.Handler serving /mcp. Mount it anywhere:
// a real listener, an in-memory net.Pipe listener, a mux under a path.
defer gw.Close()          // tears down every session + subprocess
```

## The seams

### `inspect.Hooks`: guardrails, masking, AI analysis

```go
hooks := inspect.Hooks{
    // Validate free text flowing toward a backend (tool args, catalog
    // descriptions). Error => request denied / catalog killed.
    GuardInput: func(ctx context.Context, dir inspect.Direction, text string) error { … },

    // Mask sensitive content in result text leaves. Returns redacted
    // text + count (count>0 emits mcp.redacted).
    Redact: func(ctx context.Context, text string) (string, int, error) { … },

    // Classify a tool call pre-flight; block=true denies THIS request
    // only. Errors are fail-open by design.
    Analyze: func(ctx context.Context, tool string, args json.RawMessage) (block bool, reason string, err error) { … },
}
```

`checks.Assemble` omits the guardrails and redact stages when the hook is
nil, so a nil hook costs nothing at runtime. A host with a fail-closed
requirement (guard rules configured, no engine available) must refuse
construction itself, because the library does not guess policy.

### `audit.Sink`: the event stream

```go
type Sink interface{ Emit(ctx context.Context, ev audit.Event) }
```

An implementation must return without blocking. `audit.MultiSink` fans
out, and the `wal` package gives you a per-session JSONL sink. Bridge this
to your own session storage to surface the tool-call timeline in your UI.

### `gateway.HeldStore`: approvals

```go
type HeldStore interface {
    Hold(ctx context.Context, h HeldCall) (id string, resolved <-chan bool, err error)
}
```

The gateway parks the call and waits on the channel (true=approved).
`approval.Store` plus `approval.NewAPI` is the standalone implementation.
A host replaces it with its own review workflow: create a review record,
resolve the channel once a human decides. Pass `Held: nil` and holds
degrade to deny, failing closed.

### `gateway.IdentityResolver`: identity

```go
Resolver: func(r *http.Request) (inspect.Identity, error) { … }
```

If your host already authenticated the caller, with the gateway sitting
behind it, return the known identity and skip `auth/inbound`. Identity
lands in every audit event, review, and per-user token grant.

### `gateway.Observer`: telemetry

```go
type Observer interface {
    ObserveMessage(dir inspect.Direction, backend, method, tool, decision string, dur time.Duration)
}
```

`telemetry.New` provides Prometheus + OTLP; any implementation works.

### `outbound.TokenSource`: backend credentials

`backend.NewFactory(name, cfg, tokenSource)` takes a token source that
supplies the per-request Authorization value. `auth/outbound` ships
static, passthrough, OAuth (discovery/DCR/PKCE/refresh), RFC 8693
exchange, and `authserver.NewUpstreamSwapSource`. A host can inject
anything matching `func(ctx) (string, error)`.

Context carriers matter when composing. Set `outbound.WithUser` (per-user
grant keys), `outbound.WithClientToken` (passthrough), and
`outbound.WithInboundToken` (token exchange subject) on the request
context before the gateway handles it. Do this in the resolver, which
runs first and may rewrite the request context.

## Custom checks

A check is one interface:

```go
type Check interface {
    Name() string
    Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision
}
```

Append to the `Pipeline` slice; order matters, so read
[inspection-pipeline.md](inspection-pipeline.md) first. `optimizer.New`
works as a complete example: it mutates `tools/list` results in place and
always allows.

## Byte-stream hosts

A host whose transport hands you raw bytes rather than HTTP requests
(hoop's agent protocol) bridges with an in-memory listener: feed the byte
stream into one end of a `net.Pipe`-backed `net.Listener`, then run
`http.Serve(listener, gw.Handler())` on the other. The gateway never sees
the underlying transport, and the bridge owns framing.
