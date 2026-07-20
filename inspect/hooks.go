package inspect

import (
	"context"
	"encoding/json"
)

// Hooks are the host-integration seams (hoop supplies these later; the
// standalone daemon wires its own implementations). All fields are optional;
// nil means the capability is absent.
type Hooks struct {
	// GuardInput validates free text (tool arguments, descriptions) flowing
	// toward a backend. A non-nil error blocks the message.
	GuardInput func(ctx context.Context, dir Direction, text string) error
	// Redact masks sensitive content in result text leaves, returning the
	// redacted text and the number of redactions applied.
	Redact func(ctx context.Context, text string) (string, int, error)
	// Analyze classifies a tool call before it reaches the backend.
	// block=true rejects this single request.
	Analyze func(ctx context.Context, tool string, args json.RawMessage) (block bool, reason string, err error)
}
