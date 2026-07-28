package outbound

import (
	"context"
	"fmt"
	"strings"
)

// UpstreamAuthHeader carries a client-supplied upstream credential on the
// inbound MCP request.
//
// The name avoids "Authorization" because that header authenticates the client
// to the gateway. A client talking to a passthrough backend presents two
// credentials, one for the gateway and one for the MCP server behind it, so
// the second gets its own header instead of overloading the first.
const UpstreamAuthHeader = "X-Mcpproxy-Upstream-Authorization"

type clientTokenCtxKey struct{}

// WithClientToken records the client-supplied upstream credential on ctx.
//
// The daemon's HTTP middleware reads [UpstreamAuthHeader], strips any "Bearer "
// prefix, and calls this; [NewPassthrough] is the other half. The split keeps
// the token source free of any HTTP dependency, so stdio backends and tests
// can inject a credential without faking a request.
func WithClientToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, clientTokenCtxKey{}, token)
}

// ClientTokenFrom returns the credential recorded by [WithClientToken].
func ClientTokenFrom(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(clientTokenCtxKey{}).(string)
	return t, ok && t != ""
}

// TrimBearer strips a case-insensitive "Bearer " prefix from a header value.
// Clients disagree on whether to include it; the token source needs the bare
// credential either way.
func TrimBearer(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return v
}

// NewPassthrough returns a source that forwards the client-supplied upstream
// credential from the request context.
//
// A missing credential returns an error instead of a silent empty token. The
// backend requires the caller's own identity, so an anonymous call would fail
// upstream with a worse message or succeed as some other principal.
func NewPassthrough() TokenSource {
	return func(ctx context.Context) (string, error) {
		tok, ok := ClientTokenFrom(ctx)
		if !ok {
			return "", fmt.Errorf("outbound: passthrough backend requires header %s", UpstreamAuthHeader)
		}
		return tok, nil
	}
}
