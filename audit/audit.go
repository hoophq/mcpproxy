// Package audit defines the structured event stream the gateway emits: one
// event per protocol-level occurrence. Loggers and the WAL consume it today,
// and hoop's session review will consume it later.
package audit

import (
	"context"
	"time"
)

// EventType enumerates the audit vocabulary. The strings are stable, since
// review tooling queries against them.
type EventType string

const (
	EventSessionStart     EventType = "mcp.session_start"
	EventSessionEnd       EventType = "mcp.session_end"
	EventInitialize       EventType = "mcp.initialize"
	EventToolsListed      EventType = "mcp.tools_listed"
	EventToolCall         EventType = "mcp.tool_call"
	EventToolResult       EventType = "mcp.tool_result"
	EventToolDenied       EventType = "mcp.tool_denied"
	EventToolsChanged     EventType = "mcp.tools_changed"
	EventServerRequest    EventType = "mcp.server_request"
	EventServerReqDenied  EventType = "mcp.server_request_denied"
	EventApprovalPending  EventType = "mcp.approval_pending"
	EventApprovalResolved EventType = "mcp.approval_resolved"
	EventBudgetExceeded   EventType = "mcp.budget_exceeded"
	EventRedacted         EventType = "mcp.redacted"
	EventGuardrailBlock   EventType = "mcp.guardrail_block"
	EventSessionKilled    EventType = "mcp.session_killed"
	EventError            EventType = "mcp.error"
	EventSessionRefused   EventType = "mcp.session_refused"
)

// Event is one structured audit record.
type Event struct {
	Time    time.Time      `json:"time"`
	Type    EventType      `json:"event"`
	Session string         `json:"sid"`
	User    string         `json:"user,omitempty"`
	Backend string         `json:"backend,omitempty"`
	Tool    string         `json:"tool,omitempty"`
	Rule    string         `json:"rule,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// Sink consumes events. Implementations must be safe for concurrent use and
// must not block: slow sinks buffer or drop.
type Sink interface {
	Emit(ctx context.Context, ev Event)
}

// MultiSink fans out to several sinks.
type MultiSink []Sink

// Emit sends ev to every sink.
func (ms MultiSink) Emit(ctx context.Context, ev Event) {
	for _, s := range ms {
		s.Emit(ctx, ev)
	}
}

// Discard drops all events.
var Discard Sink = discard{}

type discard struct{}

func (discard) Emit(context.Context, Event) {}
