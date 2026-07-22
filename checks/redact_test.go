package checks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// maskSecret replaces every occurrence of "SECRET" with "[REDACTED]".
func maskSecret(_ context.Context, text string) (string, int, error) {
	n := strings.Count(text, "SECRET")
	if n == 0 {
		return text, 0, nil
	}
	return strings.ReplaceAll(text, "SECRET", "[REDACTED]"), n, nil
}

func TestRedactToolResultContent(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	msg := resultMsg(t, "read_file", []any{
		textItem("token=SECRET and SECRET"),
		map[string]any{"type": "image", "data": "AAA"},
		textItem("nothing here"),
	})

	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("redaction must allow, got %s", verdictString(got.Verdict))
	}
	texts := contentTexts(t, msg.Env.Result, "content")
	if texts[0] != "token=[REDACTED] and [REDACTED]" {
		t.Errorf("text[0] = %q, want both occurrences masked", texts[0])
	}
	if texts[2] != "nothing here" {
		t.Errorf("text[2] = %q, want it untouched", texts[2])
	}

	// The image entry keeps its fields.
	var res map[string]json.RawMessage
	if err := json.Unmarshal(msg.Env.Result, &res); err != nil {
		t.Fatalf("result is no longer valid JSON: %v", err)
	}
	if string(res["isError"]) != "false" {
		t.Errorf("isError = %s, want the original false", res["isError"])
	}
	var items []map[string]any
	_ = json.Unmarshal(res["content"], &items)
	if items[1]["data"] != "AAA" {
		t.Errorf("non-text entry was mutated: %v", items[1])
	}

	ev, ok := rec.last(audit.EventRedacted)
	if !ok {
		t.Fatal("redactions must be audited")
	}
	if got := ev.Fields["redactions"]; got != 2 {
		t.Errorf("redactions = %v, want 2", got)
	}
	if ev.Tool != "read_file" {
		t.Errorf("event tool = %q, want read_file", ev.Tool)
	}
}

func TestRedactResourcesRead(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	msg := &inspect.Msg{
		Dir: inspect.S2C, CorrelatedMethod: mcp.MethodResourcesRead,
		Env: &jsonrpc.Message{JSONRPC: "2.0", ID: rawID("5"), Result: mustJSON(t, map[string]any{
			"contents": []any{map[string]any{"uri": "file:///x", "text": "pw=SECRET"}},
		})},
	}
	r.Inspect(ctx, s, msg)

	texts := contentTexts(t, msg.Env.Result, "contents")
	if texts[0] != "pw=[REDACTED]" {
		t.Errorf("contents[0].text = %q, want it masked", texts[0])
	}
	// The uri field survives.
	var res map[string]json.RawMessage
	_ = json.Unmarshal(msg.Env.Result, &res)
	var items []map[string]any
	_ = json.Unmarshal(res["contents"], &items)
	if items[0]["uri"] != "file:///x" {
		t.Errorf("uri was dropped: %v", items[0])
	}
	if n := rec.count(audit.EventRedacted); n != 1 {
		t.Errorf("emitted %d redaction events, want 1", n)
	}
}

func TestRedactNoMatchLeavesResultByteIdentical(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	msg := resultMsg(t, "read_file", []any{textItem("all clear")})
	before := string(msg.Env.Result)
	r.Inspect(ctx, s, msg)
	if string(msg.Env.Result) != before {
		t.Errorf("result was rewritten with nothing to redact: %s", msg.Env.Result)
	}
	if n := rec.count(audit.EventRedacted); n != 0 {
		t.Errorf("emitted %d redaction events with no matches, want 0", n)
	}
}

func TestRedactIgnoresUncorrelatedMethods(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, nil)
	msg := listMsg(t, "be", tool("t", "SECRET in a description", nil))
	before := string(msg.Env.Result)
	r.Inspect(ctx, s, msg)
	if string(msg.Env.Result) != before {
		t.Error("tools/list results must not be redacted; descriptions are structural")
	}
}

// A failing redactor must not corrupt the payload or invent an audit count.
func TestRedactHookErrorLeavesTextIntact(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: func(context.Context, string) (string, int, error) {
		return "", 3, errors.New("redactor down")
	}}, rec)
	msg := resultMsg(t, "read_file", []any{textItem("token=SECRET")})
	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("verdict = %s, want Allow", verdictString(got.Verdict))
	}
	if texts := contentTexts(t, msg.Env.Result, "content"); texts[0] != "token=SECRET" {
		t.Errorf("text = %q, want it unchanged after a hook error", texts[0])
	}
	if n := rec.count(audit.EventRedacted); n != 0 {
		t.Errorf("emitted %d redaction events after a hook error, want 0", n)
	}
}

func TestRedactSkipsErrorResponses(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, nil)
	msg := &inspect.Msg{
		Dir: inspect.S2C, CorrelatedMethod: mcp.MethodToolsCall,
		Env: jsonrpc.NewError(rawID("3"), jsonrpc.CodeInternalError, "boom"),
	}
	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("verdict = %s, want Allow", verdictString(got.Verdict))
	}
}
