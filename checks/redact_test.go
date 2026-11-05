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

// responseMsg builds an S2C response to method carrying result.
func responseMsg(t *testing.T, method, tool string, result any) *inspect.Msg {
	t.Helper()
	return &inspect.Msg{
		Dir: inspect.S2C, CorrelatedMethod: method, CorrelatedTool: tool,
		Env: &jsonrpc.Message{JSONRPC: "2.0", ID: rawID("9"), Result: mustJSON(t, result)},
	}
}

// maskOrFail masks like maskSecret and fails on any text holding "BOOM".
func maskOrFail(ctx context.Context, text string) (string, int, error) {
	if strings.Contains(text, "BOOM") {
		return "", 1, errors.New("redactor down")
	}
	return maskSecret(ctx, text)
}

func TestRedactStructuredContentEveryString(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	r := NewRedactor(inspect.Hooks{Redact: maskSecret}, rec)
	msg := responseMsg(t, mcp.MethodToolsCall, "lookup", map[string]any{
		"content": []any{textItem("see structuredContent")},
		"structuredContent": json.RawMessage(`{"id":12345678901234567890,` +
			`"user":{"name":"SECRET","age":42,"tags":["a SECRET","plain",true,null]},` +
			`"SECRET":"keys are structure"}`),
	})
	if got := r.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("verdict = %s, want Allow", verdictString(got.Verdict))
	}
	var res map[string]json.RawMessage
	_ = json.Unmarshal(msg.Env.Result, &res)
	sc := string(res["structuredContent"])
	var got struct {
		ID   json.Number `json:"id"`
		User struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
			Tags []any  `json:"tags"`
		} `json:"user"`
		Key string `json:"SECRET"`
	}
	dec := json.NewDecoder(strings.NewReader(sc))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("structuredContent is no longer valid JSON: %v", err)
	}
	if got.User.Name != "[REDACTED]" || got.User.Tags[0] != "a [REDACTED]" {
		t.Errorf("nested strings not masked: %+v", got.User)
	}
	if got.User.Tags[1] != "plain" || got.User.Tags[2] != true || got.User.Tags[3] != nil || got.User.Age != 42 {
		t.Errorf("non-matching values changed: %+v", got.User)
	}
	if got.ID != "12345678901234567890" {
		t.Errorf("id = %s, want the number byte for byte", got.ID)
	}
	if got.Key != "keys are structure" {
		t.Errorf("object key or its clean value changed: %q", got.Key)
	}
	if ev, _ := rec.last(audit.EventRedacted); ev.Fields["redactions"] != 2 {
		t.Errorf("redactions = %v, want 2", ev.Fields["redactions"])
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
// an error, and the text, masked or not, never leaves.
func TestRedactHookErrorDeniesResult(t *testing.T) {
	cases := []struct {
		name, method string
		result       map[string]any
	}{
		{"content text", mcp.MethodToolsCall, map[string]any{"content": []any{textItem("BOOM")}}},
		{"nested resource text", mcp.MethodToolsCall, map[string]any{"content": []any{
			map[string]any{"type": "resource", "resource": map[string]any{"uri": "file:///x", "text": "BOOM"}},
		}}},
		{"resources/read contents text", mcp.MethodResourcesRead, map[string]any{"contents": []any{
			map[string]any{"uri": "file:///x", "text": "BOOM"},
		}}},
		{"structuredContent after a masked field", mcp.MethodToolsCall, map[string]any{
			"content":           []any{textItem("SECRET")},
			"structuredContent": map[string]any{"deep": []any{map[string]any{"v": "BOOM"}}},
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
			if strings.Contains(got.Reason, "BOOM") || strings.Contains(got.Reply.Error.Message, "BOOM") {
				t.Errorf("the client message quotes the text: %q", got.Reply.Error.Message)
			}
			if n := rec.count(audit.EventRedacted); n != 0 {
				t.Errorf("emitted %d redaction events for a withheld result, want 0", n)
			}
			ev, ok := rec.last(audit.EventToolDenied)
			if !ok || ev.Rule != NameRedact || !strings.Contains(ev.Reason, "redactor down") {
				t.Errorf("denial audit = %+v, want rule %q with the hook error", ev, NameRedact)
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
