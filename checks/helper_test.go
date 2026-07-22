package checks

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
	"github.com/hoophq/mcpproxy/session"
)

// recorder is an audit.Sink that keeps every event for assertions.
type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) types() []audit.EventType {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.EventType, len(r.events))
	for i, e := range r.events {
		out[i] = e.Type
	}
	return out
}

func (r *recorder) count(t audit.EventType) int {
	n := 0
	for _, got := range r.types() {
		if got == t {
			n++
		}
	}
	return n
}

func (r *recorder) last(t audit.EventType) (audit.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Type == t {
			return r.events[i], true
		}
	}
	return audit.Event{}, false
}

func newSession(t *testing.T) *session.State {
	t.Helper()
	return session.New("sid-1", inspect.Identity{Subject: "alice@example.com"})
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func rawID(s string) jsonrpc.ID { return jsonrpc.ID{Raw: json.RawMessage(s)} }

// callMsg builds a C2S tools/call request.
func callMsg(t *testing.T, backend, tool string, args any) *inspect.Msg {
	t.Helper()
	params := map[string]any{"name": tool}
	if args != nil {
		params["arguments"] = args
	}
	return &inspect.Msg{
		Dir:     inspect.C2S,
		Backend: backend,
		Env: &jsonrpc.Message{
			JSONRPC: "2.0", ID: rawID("1"),
			Method: mcp.MethodToolsCall, Params: mustJSON(t, params),
		},
	}
}

// listMsg builds an S2C tools/list response carrying raw tool entries.
func listMsg(t *testing.T, backend string, tools ...any) *inspect.Msg {
	t.Helper()
	raws := make([]json.RawMessage, len(tools))
	for i, tl := range tools {
		raws[i] = mustJSON(t, tl)
	}
	return &inspect.Msg{
		Dir: inspect.S2C, Backend: backend,
		CorrelatedMethod: mcp.MethodToolsList,
		Env: &jsonrpc.Message{
			JSONRPC: "2.0", ID: rawID("7"),
			Result: mustJSON(t, mcp.ToolsListResult{Tools: raws}),
		},
	}
}

// resultMsg builds an S2C tools/call response with the given content array.
func resultMsg(t *testing.T, tool string, content []any) *inspect.Msg {
	t.Helper()
	return &inspect.Msg{
		Dir: inspect.S2C, CorrelatedMethod: mcp.MethodToolsCall, CorrelatedTool: tool,
		Env: &jsonrpc.Message{
			JSONRPC: "2.0", ID: rawID("3"),
			Result: mustJSON(t, map[string]any{"content": content, "isError": false}),
		},
	}
}

func textItem(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

// tool builds a raw tools/list entry.
func tool(name, desc string, schema any) map[string]any {
	m := map[string]any{"name": name, "description": desc}
	if schema != nil {
		m["inputSchema"] = schema
	}
	return m
}

// contentTexts extracts the text leaves of a result envelope.
func contentTexts(t *testing.T, result json.RawMessage, field string) []string {
	t.Helper()
	var res map[string]json.RawMessage
	if err := json.Unmarshal(result, &res); err != nil {
		t.Fatalf("result is not a JSON object: %v", err)
	}
	var items []mcp.ContentItem
	if err := json.Unmarshal(res[field], &items); err != nil {
		t.Fatalf("%s is not a content array: %v", field, err)
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Text
	}
	return out
}

// toolNames extracts names from a tools/list result envelope.
func toolNames(t *testing.T, result json.RawMessage) []string {
	t.Helper()
	var res mcp.ToolsListResult
	if err := json.Unmarshal(result, &res); err != nil {
		t.Fatalf("bad tools/list result: %v", err)
	}
	out := make([]string, len(res.Tools))
	for i, raw := range res.Tools {
		out[i] = rawName(raw)
	}
	return out
}

func verdictString(v inspect.Verdict) string {
	switch v {
	case inspect.Allow:
		return "Allow"
	case inspect.Deny:
		return "Deny"
	case inspect.Hold:
		return "Hold"
	case inspect.Kill:
		return "Kill"
	}
	return "?"
}
