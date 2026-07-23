package outbound

import (
	"context"
	"log/slog"
	"testing"

	"github.com/hoophq/mcpproxy/config"
)

// TestDaemonAPISurface pins the exact call shapes cmd/mcpproxyd depends on, so
// a signature change here fails in this package rather than in the daemon.
func TestDaemonAPISurface(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir+"/tokens.enc", dir+"/tokens.key")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	deps := Deps{Store: store, Authorizer: NewLoopbackAuthorizer(slog.Default())}
	deps.UpstreamSwap = NewStatic("swap")

	ctx := context.Background()
	ctx = WithClientToken(ctx, "up")
	ctx = WithInboundToken(ctx, "in")
	ctx = WithUser(ctx, "alice")

	var ts TokenSource
	ts, err = Resolve(ctx, "b", config.Backend{Transport: "stdio"}, deps)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := ts(ctx); err != nil {
		t.Fatalf("token: %v", err)
	}
	_ = UpstreamAuthHeader
}
