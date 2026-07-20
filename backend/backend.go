// Package backend defines the transport-agnostic connection to one MCP
// server (stdio subprocess or remote streamable-http endpoint).
package backend

import (
	"context"
	"errors"
)

// ErrClosed is returned by Send after the backend terminated.
var ErrClosed = errors.New("backend closed")

// Backend is one live connection to an MCP server. One instance serves one
// MCP session; the gateway serializes Send calls per session.
type Backend interface {
	// Name is the configured backend name (used as tool prefix in
	// aggregation and as the audit backend label).
	Name() string
	// Start establishes the connection (spawns the child / probes the
	// remote). Must be called once before Send.
	Start(ctx context.Context) error
	// Send delivers one JSON-RPC message (a complete envelope) to the
	// server.
	Send(ctx context.Context, msg []byte) error
	// Recv yields messages from the server. The channel closes when the
	// backend terminates.
	Recv() <-chan []byte
	// Done closes when the backend has terminated for any reason.
	Done() <-chan struct{}
	// Err reports the termination cause after Done closes; nil on clean
	// shutdown.
	Err() error
	// Close terminates the connection and reaps any subprocess. Idempotent.
	Close() error
}

// Factory builds a Backend for one session from its configuration.
type Factory func(ctx context.Context) (Backend, error)
