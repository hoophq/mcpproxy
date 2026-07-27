# Embedding the gateway

`cmd/mcpproxyd` is thin wiring over library packages; a host application
(e.g. hoop's agent) embeds the same gateway and swaps the seams. Nothing in
`gateway/` or `checks/` knows about the daemon.

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
// gw.Handler() is an http.Handler serving /mcp — mount it anywhere:
// a real listener, an in-memory net.Pipe listener, a mux under a path.
defer gw.Close()          // tears down every session + subprocess
```

## The seams

### `inspect.Hooks` — guardrails, masking, AI analysis

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

Nil hooks cost nothing: `checks.Assemble` omits the guardrails/redact
stages entirely when the hook is nil. Hosts with a fail-closed requirement
(guard rules configured but no engine available) must refuse construction
themselves — the library does not guess policy.

### `audit.Sink` — the event stream

```go
type Sink interface{ Emit(ctx context.Context, ev audit.Event) }
```

Implementations must not block. `audit.MultiSink` fans out; the `wal`
package is a ready-made per-session JSONL sink. A host bridges this to its
own session storage to get the tool-call timeline in its UI.

### `gateway.HeldStore` — approvals

```go
type HeldStore interface {
    Hold(ctx context.Context, h HeldCall) (id string, resolved <-chan bool, err error)
}
```

The gateway parks the call and waits on the channel (true=approved).
`approval.Store` + `approval.NewAPI` is the standalone implementation; a
host replaces it with its own review workflow (create a review record,
resolve the channel when a human decides). Pass `Held: nil` and holds
degrade to deny — fail closed.

### `gateway.IdentityResolver` — identity

```go
Resolver: func(r *http.Request) (inspect.Identity, error) { … }
```

If the host already authenticated the caller (gateway in front), return
the known identity and skip `auth/inbound` entirely. Identity lands in
every audit event, review, and per-user token grant.

### `gateway.Observer` — telemetry

```go
type Observer interface {
    ObserveMessage(dir inspect.Direction, backend, method, tool, decision string, dur time.Duration)
}
```

`telemetry.New` provides Prometheus + OTLP; any implementation works.

### `outbound.TokenSource` — backend credentials

`backend.NewFactory(name, cfg, tokenSource)` — the token source supplies
the per-request Authorization value. `auth/outbound` ships static,
passthrough, OAuth (discovery/DCR/PKCE/refresh), RFC 8693 exchange, and
`authserver.NewUpstreamSwapSource`. A host can inject anything matching
`func(ctx) (string, error)`.

Context carriers matter when composing: `outbound.WithUser` (per-user
grant keys), `outbound.WithClientToken` (passthrough), and
`outbound.WithInboundToken` (token exchange subject) must be set on the
request context before the gateway handles it — do this in the resolver,
which runs first and may rewrite the request context.

## Custom checks

A check is one interface:

```go
type Check interface {
    Name() string
    Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision
}
```

Append to the `Pipeline` slice (order matters — see
[inspection-pipeline.md](inspection-pipeline.md)). `optimizer.New` is a
complete worked example: it mutates `tools/list` results in place and
always allows.

## Byte-stream hosts

Hosts whose transport hands you raw bytes rather than HTTP requests (hoop's
agent protocol) bridge with an in-memory listener: feed the byte stream
into one end of a `net.Pipe`-backed `net.Listener`, run
`http.Serve(listener, gw.Handler())` on the other. The gateway stays
transport-agnostic; the bridge owns framing.
