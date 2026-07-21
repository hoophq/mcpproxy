package backend

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hoophq/mcpproxy/config"
)

// Transport identifiers accepted in config.Backend.Transport.
const (
	TransportStdio          = "stdio"
	TransportStreamableHTTP = "streamable-http"
)

// NewFactory returns a Factory building one unstarted Backend per session
// from cfg.
//
// ts, when non-nil, mints the outbound bearer token for each request to a
// remote backend — the seam where static/passthrough/OAuth outbound auth
// plugs in. It is ignored for stdio backends, which inherit credentials
// through their environment instead.
//
// Configuration errors (unknown transport, missing command/url) surface from
// the returned Factory rather than from NewFactory, so a misconfigured
// backend fails its own session instead of the whole daemon's wiring. The
// same conditions are already rejected by config.Validate.
func NewFactory(name string, cfg config.Backend, ts func(ctx context.Context) (string, error)) Factory {
	return func(_ context.Context) (Backend, error) {
		switch cfg.Transport {
		case TransportStdio:
			if len(cfg.Command) == 0 {
				return nil, fmt.Errorf("backend %s: stdio transport needs a command", name)
			}
			return NewStdio(name, cfg, slog.Default()), nil
		case TransportStreamableHTTP:
			if cfg.URL == "" {
				return nil, fmt.Errorf("backend %s: streamable-http transport needs a url", name)
			}
			b := NewRemote(name, cfg, slog.Default())
			b.TokenSource = ts
			return b, nil
		default:
			return nil, fmt.Errorf("backend %s: unknown transport %q", name, cfg.Transport)
		}
	}
}
