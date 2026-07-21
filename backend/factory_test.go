package backend

import (
	"context"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/config"
)

func TestNewFactoryTransportSelection(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Backend
		wantErr string
		verify  func(t *testing.T, b Backend)
	}{
		{
			name: "stdio",
			cfg:  config.Backend{Transport: TransportStdio, Command: []string{"cat"}},
			verify: func(t *testing.T, b Backend) {
				if _, ok := b.(*StdioBackend); !ok {
					t.Fatalf("got %T, want *StdioBackend", b)
				}
			},
		},
		{
			name: "streamable-http carries the token source",
			cfg:  config.Backend{Transport: TransportStreamableHTTP, URL: "https://example.com/mcp"},
			verify: func(t *testing.T, b Backend) {
				rb, ok := b.(*RemoteBackend)
				if !ok {
					t.Fatalf("got %T, want *RemoteBackend", b)
				}
				if rb.TokenSource == nil {
					t.Fatal("TokenSource not wired through")
				}
				tok, err := rb.TokenSource(context.Background())
				if err != nil || tok != "tok" {
					t.Errorf("TokenSource() = %q, %v", tok, err)
				}
			},
		},
		{
			name:    "stdio without a command",
			cfg:     config.Backend{Transport: TransportStdio},
			wantErr: "needs a command",
		},
		{
			name:    "streamable-http without a url",
			cfg:     config.Backend{Transport: TransportStreamableHTTP},
			wantErr: "needs a url",
		},
		{
			name:    "unknown transport",
			cfg:     config.Backend{Transport: "carrier-pigeon"},
			wantErr: `unknown transport "carrier-pigeon"`,
		},
	}
	ts := func(context.Context) (string, error) { return "tok", nil }
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFactory("bk", tc.cfg, ts)
			b, err := f(context.Background())
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("got backend %T, want error containing %q", b, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), "bk") {
					t.Errorf("err = %v, want the backend name for diagnosis", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("factory: %v", err)
			}
			if b.Name() != "bk" {
				t.Errorf("Name = %q, want bk", b.Name())
			}
			tc.verify(t, b)
			_ = b.Close()
		})
	}
}

// TestNewFactoryBuildsIndependentBackends: one Backend serves one session, so
// two calls must not share state.
func TestNewFactoryBuildsIndependentBackends(t *testing.T) {
	f := NewFactory("bk", config.Backend{Transport: TransportStdio, Command: []string{"cat"}}, nil)
	ctx := context.Background()
	first, err := f(ctx)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := f(ctx)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first == second {
		t.Fatal("factory returned the same Backend twice")
	}
	_ = first.Close()
	select {
	case <-second.Done():
		t.Fatal("closing one backend terminated the other")
	default:
	}
	_ = second.Close()
}

// Compile-time proof that both transports satisfy the interface the gateway
// programs against.
var (
	_ Backend = (*StdioBackend)(nil)
	_ Backend = (*RemoteBackend)(nil)
)
