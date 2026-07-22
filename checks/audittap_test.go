package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

func TestAuditTapRecordsToolCallDigest(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	a := NewAuditTap(rec)
	msg := callMsg(t, "be", "read_file", map[string]any{"path": "/etc/passwd"})

	if got := a.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("audit tap must always allow, got %s", verdictString(got.Verdict))
	}
	ev, ok := rec.last(audit.EventToolCall)
	if !ok {
		t.Fatal("no tool_call event emitted")
	}
	if ev.Tool != "read_file" || ev.Backend != "be" {
		t.Errorf("event = %+v, want tool read_file on backend be", ev)
	}
	if ev.Session != "sid-1" || ev.User != "alice@example.com" {
		t.Errorf("event identity = (%q, %q), want the session's", ev.Session, ev.User)
	}

	var p mcp.ToolsCallParams
	_ = json.Unmarshal(msg.Env.Params, &p)
	sum := sha256.Sum256(p.Arguments)
	if got := ev.Fields["args_sha256"]; got != hex.EncodeToString(sum[:]) {
		t.Errorf("args_sha256 = %v, want the digest of the arguments", got)
	}
	if got := ev.Fields["args_bytes"]; got != len(p.Arguments) {
		t.Errorf("args_bytes = %v, want %d", got, len(p.Arguments))
	}
	// Arguments must never appear verbatim in the audit record.
	b, _ := json.Marshal(ev.Fields)
	if strings.Contains(string(b), "/etc/passwd") {
		t.Errorf("audit fields leaked raw arguments: %s", b)
	}
}

func TestAuditTapIdenticalCallsShareADigest(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	a := NewAuditTap(rec)
	a.Inspect(ctx, s, callMsg(t, "be", "read_file", map[string]any{"path": "/tmp/a"}))
	first, _ := rec.last(audit.EventToolCall)
	a.Inspect(ctx, s, callMsg(t, "be", "read_file", map[string]any{"path": "/tmp/a"}))
	second, _ := rec.last(audit.EventToolCall)
	if first.Fields["args_sha256"] != second.Fields["args_sha256"] {
		t.Error("identical arguments must hash identically")
	}
	a.Inspect(ctx, s, callMsg(t, "be", "read_file", map[string]any{"path": "/tmp/b"}))
	third, _ := rec.last(audit.EventToolCall)
	if first.Fields["args_sha256"] == third.Fields["args_sha256"] {
		t.Error("different arguments must hash differently")
	}
}

func TestAuditTapRecordsAlias(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	rememberRename(s, "fs_read", "read_file")
	NewAuditTap(rec).Inspect(ctx, s, callMsg(t, "be", "fs_read", nil))
	ev, _ := rec.last(audit.EventToolCall)
	if ev.Tool != "read_file" {
		t.Errorf("event tool = %q, want the real name read_file", ev.Tool)
	}
	if ev.Fields["exposed_tool"] != "fs_read" {
		t.Errorf("exposed_tool = %v, want fs_read", ev.Fields["exposed_tool"])
	}
}

func TestAuditTapRecordsToolsListed(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	msg := listMsg(t, "be", tool("a", "d", nil), tool("b", "d", nil))
	NewAuditTap(rec).Inspect(ctx, s, msg)

	ev, ok := rec.last(audit.EventToolsListed)
	if !ok {
		t.Fatal("no tools_listed event emitted")
	}
	if ev.Fields["count"] != 2 {
		t.Errorf("count = %v, want 2", ev.Fields["count"])
	}
	names, _ := ev.Fields["names"].([]string)
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Errorf("names = %v, want [a b]", names)
	}
}

// initialize is audited by the gateway; the tap must not double-count it.
func TestAuditTapSkipsInitialize(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	msg := &inspect.Msg{Dir: inspect.C2S, Env: &jsonrpc.Message{
		JSONRPC: "2.0", ID: rawID("1"), Method: mcp.MethodInitialize,
	}}
	NewAuditTap(rec).Inspect(ctx, s, msg)
	if n := len(rec.types()); n != 0 {
		t.Errorf("emitted %d events for initialize (%v), want 0", n, rec.types())
	}
}
