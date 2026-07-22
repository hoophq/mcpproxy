package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
)

func TestBudgetSessionCallCap(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	b := NewBudget(config.Policy{MaxCallsPerSess: 2}, rec)

	for i := range 2 {
		if got := b.Inspect(ctx, s, callMsg(t, "be", "read_file", nil)); got.Verdict != inspect.Allow {
			t.Fatalf("call %d = %s, want Allow", i+1, verdictString(got.Verdict))
		}
	}
	got := b.Inspect(ctx, s, callMsg(t, "be", "read_file", nil))
	if got.Verdict != inspect.Deny {
		t.Fatalf("call 3 = %s, want Deny", verdictString(got.Verdict))
	}
	if got.Reply == nil || got.Reply.Error == nil || got.Reply.Error.Code != jsonrpc.CodeBudgetExceeded {
		t.Fatalf("want CodeBudgetExceeded reply, got %+v", got.Reply)
	}
	if n := rec.count(audit.EventBudgetExceeded); n != 1 {
		t.Errorf("emitted %d budget_exceeded events, want 1", n)
	}
}

func TestBudgetUnlimitedByDefault(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	b := NewBudget(config.Policy{}, nil)
	for i := range 50 {
		if got := b.Inspect(ctx, s, callMsg(t, "be", "read_file", nil)); got.Verdict != inspect.Allow {
			t.Fatalf("call %d denied with no limit configured", i+1)
		}
	}
}

func TestBudgetPerToolRateLimit(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	b := NewBudget(config.Policy{ToolRateLimits: map[string]int{"search_*": 2}}, rec)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }

	for i := range 2 {
		if got := b.Inspect(ctx, s, callMsg(t, "be", "search_web", nil)); got.Verdict != inspect.Allow {
			t.Fatalf("call %d = %s, want Allow", i+1, verdictString(got.Verdict))
		}
	}
	got := b.Inspect(ctx, s, callMsg(t, "be", "search_web", nil))
	if got.Verdict != inspect.Deny {
		t.Fatalf("third call in-window = %s, want Deny", verdictString(got.Verdict))
	}
	if !strings.Contains(got.Reason, "rate limit") {
		t.Errorf("reason = %q, want it to mention the rate limit", got.Reason)
	}

	// A non-matching tool has its own (unlimited) budget.
	if got := b.Inspect(ctx, s, callMsg(t, "be", "read_file", nil)); got.Verdict != inspect.Allow {
		t.Fatalf("unrelated tool denied by another tool's rate limit")
	}

	// Window slides: past the minute the same tool is admitted again.
	now = now.Add(61 * time.Second)
	if got := b.Inspect(ctx, s, callMsg(t, "be", "search_web", nil)); got.Verdict != inspect.Allow {
		t.Fatalf("call after the window = %s, want Allow", verdictString(got.Verdict))
	}
}

// Overlapping globs must resolve deterministically to the strictest limit,
// independent of map iteration order.
func TestBudgetStrictestRateLimitWins(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	b := NewBudget(config.Policy{ToolRateLimits: map[string]int{"*": 10, "search_*": 1}}, nil)
	now := time.Now()
	b.now = func() time.Time { return now }

	if got := b.Inspect(ctx, s, callMsg(t, "be", "search_web", nil)); got.Verdict != inspect.Allow {
		t.Fatal("first call must be admitted")
	}
	if got := b.Inspect(ctx, s, callMsg(t, "be", "search_web", nil)); got.Verdict != inspect.Deny {
		t.Fatalf("second call = %s, want Deny under the 1/min limit", verdictString(got.Verdict))
	}
}

func TestBudgetTruncatesOversizedResult(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	b := NewBudget(config.Policy{MaxResultKB: 1}, rec)
	big := strings.Repeat("x", 3000)
	msg := resultMsg(t, "read_file", []any{textItem(big)})

	if got := b.Inspect(ctx, s, msg); got.Verdict != inspect.Allow {
		t.Fatalf("truncation must allow, got %s", verdictString(got.Verdict))
	}

	// The envelope must still be valid JSON with its non-content fields.
	var res map[string]json.RawMessage
	if err := json.Unmarshal(msg.Env.Result, &res); err != nil {
		t.Fatalf("truncated result is not valid JSON: %v", err)
	}
	if string(res["isError"]) != "false" {
		t.Errorf("isError = %s, want the original false", res["isError"])
	}
	texts := contentTexts(t, msg.Env.Result, "content")
	if len(texts) != 1 {
		t.Fatalf("content has %d items, want 1", len(texts))
	}
	if !strings.HasSuffix(texts[0], truncationMarker) {
		t.Errorf("truncated text does not end with the marker: %q", texts[0][max(0, len(texts[0])-40):])
	}
	body := strings.TrimSuffix(texts[0], truncationMarker)
	if len(body) != 1024 {
		t.Errorf("kept %d bytes, want 1024", len(body))
	}
	if n := rec.count(audit.EventBudgetExceeded); n != 1 {
		t.Errorf("emitted %d budget events, want 1", n)
	}
}

func TestBudgetLeavesSmallResultAlone(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	b := NewBudget(config.Policy{MaxResultKB: 1}, rec)
	msg := resultMsg(t, "read_file", []any{textItem("short")})
	before := string(msg.Env.Result)
	b.Inspect(ctx, s, msg)
	if string(msg.Env.Result) != before {
		t.Errorf("in-budget result was rewritten to %s", msg.Env.Result)
	}
	if n := rec.count(audit.EventBudgetExceeded); n != 0 {
		t.Errorf("emitted %d budget events for an in-budget result, want 0", n)
	}
}

// Truncation spends the budget across leaves in order and never touches
// non-text content.
func TestBudgetTruncatesAcrossLeavesSparingNonText(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	b := NewBudget(config.Policy{MaxResultKB: 1}, nil)
	image := map[string]any{"type": "image", "data": strings.Repeat("A", 2000), "mimeType": "image/png"}
	msg := resultMsg(t, "read_file", []any{
		textItem(strings.Repeat("a", 600)),
		image,
		textItem(strings.Repeat("b", 900)),
	})
	b.Inspect(ctx, s, msg)

	texts := contentTexts(t, msg.Env.Result, "content")
	if len(texts) != 3 {
		t.Fatalf("content has %d items, want 3", len(texts))
	}
	if len(texts[0]) != 600 {
		t.Errorf("first leaf = %d bytes, want the full 600 (it fits)", len(texts[0]))
	}
	third := strings.TrimSuffix(texts[2], truncationMarker)
	if len(third) != 424 {
		t.Errorf("third leaf = %d bytes, want the remaining 424", len(third))
	}
	// The image survives byte-for-byte.
	var res map[string]json.RawMessage
	_ = json.Unmarshal(msg.Env.Result, &res)
	var items []map[string]any
	if err := json.Unmarshal(res["content"], &items); err != nil {
		t.Fatalf("content no longer decodes: %v", err)
	}
	if items[1]["data"] != strings.Repeat("A", 2000) {
		t.Error("non-text content was mutated")
	}
}

func TestBudgetTruncationKeepsRunesIntact(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	b := NewBudget(config.Policy{MaxResultKB: 1}, nil)
	// 1024 is not a rune boundary for a 3-byte rune repeated: 1024 = 341*3+1.
	msg := resultMsg(t, "read_file", []any{textItem(strings.Repeat("あ", 500))})
	b.Inspect(ctx, s, msg)

	texts := contentTexts(t, msg.Env.Result, "content")
	body := strings.TrimSuffix(texts[0], truncationMarker)
	if len(body)%3 != 0 {
		t.Errorf("kept %d bytes, which splits a 3-byte rune", len(body))
	}
	for _, r := range body {
		if r != 'あ' {
			t.Fatalf("truncation corrupted a rune: %q", r)
		}
	}
}

func TestBudgetIgnoresNonToolResults(t *testing.T) {
	s, ctx := newSession(t), context.Background()
	b := NewBudget(config.Policy{MaxResultKB: 1}, nil)
	msg := listMsg(t, "be", tool("read_file", strings.Repeat("d", 4000), nil))
	before := string(msg.Env.Result)
	b.Inspect(ctx, s, msg)
	if string(msg.Env.Result) != before {
		t.Error("tools/list result must not be truncated by the tool-result budget")
	}
}
