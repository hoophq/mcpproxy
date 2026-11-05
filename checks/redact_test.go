package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// responseMsg builds an S2C response to method carrying result.
func responseMsg(t *testing.T, method, tool string, result any) *inspect.Msg {
	t.Helper()
	return &inspect.Msg{
		Dir: inspect.S2C, CorrelatedMethod: method, CorrelatedTool: tool,
		Env: &jsonrpc.Message{JSONRPC: "2.0", ID: rawID("9"), Result: mustJSON(t, result)},
	}
}

// maskOrFail masks like maskSecret and fails on any text holding "BOOM", with
// an error that quotes the text, as some engines do.
func maskOrFail(ctx context.Context, text string) (string, int, error) {
	if strings.Contains(text, "BOOM") {
		return "", 1, fmt.Errorf("cannot mask %q", text)
	}
	return maskSecret(ctx, text)
}

func TestRedactStructuredContentEveryString(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	in := `{"id":12345678901234567890,"a<b&c":1.50e+2,"esc":"caf\u00e9 <x>",` +
		`"user":{"name":"SECRET","age":42,"tags":["a SECRET","plain",true,null]},` +
		`"SECRET":"keys are structure","SECRET":"dup SECRET"}`
	want := `{"id":12345678901234567890,"a<b&c":1.50e+2,"esc":"caf\u00e9 <x>",` +
		`"user":{"name":"[REDACTED]","age":42,"tags":["a [REDACTED]","plain",true,null]},` +
		`"SECRET":"keys are structure","SECRET":"dup [REDACTED]"}`
	msg := responseMsg(t, mcp.MethodToolsCall, "lookup", nil)
	msg.Env.Result = json.RawMessage(`{"content":[{"type":"text","text":"see structuredContent"}],"structuredContent":` + in + `}`)
	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("verdict = %s, want Allow", verdictString(got.Verdict))
	}
	var res map[string]json.RawMessage
	_ = json.Unmarshal(msg.Env.Result, &res)
	if got := string(res["structuredContent"]); got != want {
		t.Errorf("structuredContent =\n%s\nwant only the string values masked, keys and numbers byte for byte:\n%s", got, want)
	}
	if ev, _ := rec.last(audit.EventRedacted); ev.Fields["redactions"] != 3 {
		t.Errorf("redactions = %v, want 3", ev.Fields["redactions"])
	}
}

// Nesting past the cap is denied before any hook call, and fast. A result at
// the cap is still masked.
func TestRedactStructuredContentDepthCap(t *testing.T) {
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + `"ana SECRET"` + strings.Repeat("]", depth)
	}
	var calls atomic.Int64
	count := func(ctx context.Context, text string) (string, int, error) {
		calls.Add(1)
		return maskSecret(ctx, text)
	}

	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: count}, rec)
	msg := responseMsg(t, mcp.MethodToolsCall, "deep", map[string]any{"structuredContent": json.RawMessage(nested(maxRedactDepth))})
	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("depth %d: verdict = %s, want Allow", maxRedactDepth, verdictString(got.Verdict))
	}
	if !strings.Contains(string(msg.Env.Result), `"ana [REDACTED]"`) {
		t.Fatalf("depth %d: leaf not masked: %.200s", maxRedactDepth, msg.Env.Result)
	}

	for _, depth := range []int{maxRedactDepth + 1, 9000} {
		calls.Store(0)
		msg := responseMsg(t, mcp.MethodToolsCall, "deep", map[string]any{"structuredContent": json.RawMessage(nested(depth))})
		start := time.Now()
		got := r.Inspect(ctx, s, msg)
		took := time.Since(start)
		if got.Verdict != inspect.Deny || !strings.Contains(got.Reason, "nests deeper") {
			t.Fatalf("depth %d: verdict = %s (%q), want Deny for nesting", depth, verdictString(got.Verdict), got.Reason)
		}
		if calls.Load() != 0 {
			t.Errorf("depth %d: hook called %d times before the refusal", depth, calls.Load())
		}
		if took > 100*time.Millisecond {
			t.Errorf("depth %d: took %s", depth, took)
		}
	}
}

// A canceled request stops the walk and withholds the result.
func TestRedactStopsOnCancel(t *testing.T) {
	var calls atomic.Int64
	count := func(ctx context.Context, text string) (string, int, error) {
		calls.Add(1)
		return maskSecret(ctx, text)
	}
	s, rec := newSession(t), &recorder{}
	r := NewRedactor(inspect.Hooks{Redact: count}, rec)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	msg := responseMsg(t, mcp.MethodToolsCall, "t", map[string]any{"structuredContent": map[string]any{"a": "SECRET"}})
	got := r.Inspect(ctx, s, msg)
	if got.Verdict != inspect.Deny || !strings.Contains(got.Reason, "canceled") {
		t.Fatalf("verdict = %s (%q), want Deny on cancel", verdictString(got.Verdict), got.Reason)
	}
	if calls.Load() != 0 {
		t.Errorf("hook called %d times after cancel", calls.Load())
	}
}

func TestRedactNestedResourceText(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	msg := responseMsg(t, mcp.MethodToolsCall, "fetch", map[string]any{
		"content": []any{map[string]any{
			"type":     "resource",
			"resource": map[string]any{"uri": "file:///SECRET.txt", "mimeType": "text/plain", "text": "pw=SECRET"},
		}},
	})
	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("verdict = %s, want Allow", verdictString(got.Verdict))
	}
	var res struct {
		Content []struct {
			Type     string            `json:"type"`
			Resource map[string]string `json:"resource"`
		} `json:"content"`
	}
	if err := json.Unmarshal(msg.Env.Result, &res); err != nil {
		t.Fatalf("result is no longer valid JSON: %v", err)
	}
	item := res.Content[0]
	if item.Resource["text"] != "pw=[REDACTED]" {
		t.Errorf("resource.text = %q, want it masked", item.Resource["text"])
	}
	if item.Type != "resource" || item.Resource["uri"] != "file:///SECRET.txt" || item.Resource["mimeType"] != "text/plain" {
		t.Errorf("structural fields changed: %+v", item)
	}
	if ev, _ := rec.last(audit.EventRedacted); ev.Fields["redactions"] != 1 {
		t.Errorf("redactions = %v, want 1", ev.Fields["redactions"])
	}
}

// A host records masked counts from one event per message.
func TestRedactCountsPerMessage(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	msg := responseMsg(t, mcp.MethodToolsCall, "lookup", map[string]any{
		"content": []any{
			textItem("SECRET and SECRET"),
			map[string]any{"type": "resource", "resource": map[string]any{"uri": "file:///x", "text": "SECRET"}},
		},
		"structuredContent": map[string]any{"a": "SECRET", "b": []any{"SECRET"}},
	})
	r.Inspect(ctx, s, msg)
	if n := rec.count(audit.EventRedacted); n != 1 {
		t.Fatalf("emitted %d redaction events, want 1 per message", n)
	}
	ev, _ := rec.last(audit.EventRedacted)
	if ev.Fields["redactions"] != 5 {
		t.Errorf("redactions = %v, want 5", ev.Fields["redactions"])
	}
	if ev.Fields["field"] != "content,structuredContent" {
		t.Errorf("field = %v, want content,structuredContent", ev.Fields["field"])
	}
}

// A Redact hook error on any field denies the whole result: the client gets
// an error, and the text, masked or not, never leaves. The hook's error quotes
// the text, so it enters neither the reply nor the audit event.
func TestRedactHookErrorDeniesResult(t *testing.T) {
	const pii = "BOOM ana@example.com SSN 123-45-6789"
	cases := []struct {
		name, method string
		result       map[string]any
	}{
		{"content text", mcp.MethodToolsCall, map[string]any{"content": []any{textItem(pii)}}},
		{"nested resource text", mcp.MethodToolsCall, map[string]any{"content": []any{
			map[string]any{"type": "resource", "resource": map[string]any{"uri": "file:///x", "text": pii}},
		}}},
		{"resources/read contents text", mcp.MethodResourcesRead, map[string]any{"contents": []any{
			map[string]any{"uri": "file:///x", "text": pii},
		}}},
		{"structuredContent after a masked field", mcp.MethodToolsCall, map[string]any{
			"content":           []any{textItem("SECRET")},
			"structuredContent": map[string]any{"deep": []any{map[string]any{"v": pii}}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, rec, ctx := newSession(t), &recorder{}, context.Background()
			r := NewRedactor(inspect.Hooks{Redact: maskOrFail}, rec)
			msg := responseMsg(t, tc.method, "read_file", tc.result)
			got := r.Inspect(ctx, s, msg)
			if got.Verdict != inspect.Deny {
				t.Fatalf("verdict = %s, want Deny", verdictString(got.Verdict))
			}
			if got.Reply == nil || got.Reply.Error == nil || got.Reply.Error.Code != jsonrpc.CodePolicyDenied {
				t.Fatalf("reply = %+v, want a policy-denied error", got.Reply)
			}
			if n := rec.count(audit.EventRedacted); n != 0 {
				t.Errorf("emitted %d redaction events for a withheld result, want 0", n)
			}
			ev, ok := rec.last(audit.EventToolDenied)
			if !ok || ev.Rule != NameRedact {
				t.Fatalf("denial audit = %+v, want rule %q", ev, NameRedact)
			}
			for _, leak := range []string{"BOOM", "ana@", "123-45", "cannot mask"} {
				for where, s := range map[string]string{
					"reply": got.Reply.Error.Message, "reason": got.Reason,
					"event": fmt.Sprintf("%+v", ev),
				} {
					if strings.Contains(s, leak) {
						t.Errorf("%s holds %q: %s", where, leak, s)
					}
				}
			}
		})
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
