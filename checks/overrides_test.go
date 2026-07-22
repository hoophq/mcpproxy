package checks

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
)

func overrideCheck(m map[string]config.ToolOverride) *Overrides {
	return NewOverrides(config.Policy{Overrides: m})
}

func TestOverridesRenamesAndRedescribes(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	o := overrideCheck(map[string]config.ToolOverride{
		"read_file":  {Name: "fs_read", Description: "Read a file from the sandbox."},
		"write_file": {Description: "Write a file."},
	})
	msg := listMsg(t, "be",
		tool("read_file", "orig desc", map[string]any{"type": "object"}),
		tool("write_file", "orig desc", nil),
		tool("untouched", "orig desc", nil),
	)
	if got := o.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("overrides must allow, got %s", verdictString(got.Verdict))
	}

	var res mcp.ToolsListResult
	if err := json.Unmarshal(msg.Env.Result, &res); err != nil {
		t.Fatalf("result no longer decodes: %v", err)
	}
	var tools []mcp.Tool
	for _, raw := range res.Tools {
		var tl mcp.Tool
		if err := json.Unmarshal(raw, &tl); err != nil {
			t.Fatalf("tool entry no longer decodes: %v", err)
		}
		tools = append(tools, tl)
	}
	if tools[0].Name != "fs_read" {
		t.Errorf("tool[0].Name = %q, want fs_read", tools[0].Name)
	}
	if tools[0].Description != "Read a file from the sandbox." {
		t.Errorf("tool[0].Description = %q, want the override", tools[0].Description)
	}
	if string(tools[0].InputSchema) == "" {
		t.Error("rename dropped inputSchema; unmodeled fields must survive")
	}
	if tools[1].Name != "write_file" {
		t.Errorf("description-only override renamed the tool to %q", tools[1].Name)
	}
	if tools[1].Description != "Write a file." {
		t.Errorf("tool[1].Description = %q, want the override", tools[1].Description)
	}
	if tools[2].Name != "untouched" || tools[2].Description != "orig desc" {
		t.Errorf("tool[2] = %+v, want it untouched", tools[2])
	}
}

// The exposed name must round-trip: the client calls the alias, the backend
// sees the real tool.
func TestOverridesRenameRoundTrip(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	o := overrideCheck(map[string]config.ToolOverride{"read_file": {Name: "fs_read"}})
	o.Inspect(ctx, s, listMsg(t, "be", tool("read_file", "d", nil)))

	if got := RealToolName(s, "fs_read"); got != "read_file" {
		t.Fatalf("RealToolName(fs_read) = %q, want read_file", got)
	}

	call := callMsg(t, "be", "fs_read", map[string]any{"path": "/etc/hosts"})
	if got := o.Inspect(ctx, s, call); got.Verdict != inspect.Allow {
		t.Fatalf("call must be allowed, got %s", verdictString(got.Verdict))
	}
	var p mcp.ToolsCallParams
	if err := json.Unmarshal(call.Env.Params, &p); err != nil {
		t.Fatalf("params no longer decode: %v", err)
	}
	if p.Name != "read_file" {
		t.Errorf("forwarded name = %q, want the real name read_file", p.Name)
	}
	var args map[string]string
	if err := json.Unmarshal(p.Arguments, &args); err != nil || args["path"] != "/etc/hosts" {
		t.Errorf("arguments were mangled: %s (%v)", p.Arguments, err)
	}
}

func TestOverridesLeavesUnrenamedCallsAlone(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	o := overrideCheck(map[string]config.ToolOverride{"read_file": {Name: "fs_read"}})
	call := callMsg(t, "be", "write_file", map[string]any{"path": "/tmp/x"})
	before := string(call.Env.Params)
	o.Inspect(ctx, s, call)
	if string(call.Env.Params) != before {
		t.Errorf("params changed to %s, want %s", call.Env.Params, before)
	}
}

func TestOverridesEmptyConfigIsNoOp(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	msg := listMsg(t, "be", tool("read_file", "d", nil))
	before := string(msg.Env.Result)
	NewOverrides(config.Policy{}).Inspect(ctx, s, msg)
	if string(msg.Env.Result) != before {
		t.Errorf("result changed with no overrides configured")
	}
}

// Under aggregation the catalog carries prefixed names while calls arrive
// bare; both spellings must un-rename.
func TestOverridesUnrenamesBarePrefixedAlias(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	o := overrideCheck(map[string]config.ToolOverride{"fs_read_file": {Name: "fs_reader"}})
	o.Inspect(ctx, s, listMsg(t, "fs", tool("fs_read_file", "d", nil)))
	if got := RealToolName(s, "reader"); got != "read_file" {
		t.Fatalf("RealToolName(reader) = %q, want read_file", got)
	}
}

func TestOverridesToolNamesVisible(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	o := overrideCheck(map[string]config.ToolOverride{"a": {Name: "z"}})
	msg := listMsg(t, "be", tool("a", "d", nil), tool("b", "d", nil))
	o.Inspect(ctx, s, msg)
	got := toolNames(t, msg.Env.Result)
	if len(got) != 2 || got[0] != "z" || got[1] != "b" {
		t.Errorf("names = %v, want [z b]", got)
	}
}
