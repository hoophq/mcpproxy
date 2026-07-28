package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// CounterToolCalls names the session counter of admitted tool calls.
const CounterToolCalls = "tool_calls"

// truncationMarker is appended to the last surviving text leaf so the model
// can tell an incomplete result from a short one.
const truncationMarker = "\n[truncated by gateway]"

// rateWindow is the sliding-window period for per-tool rate limits.
const rateWindow = time.Minute

// Budget caps what one session may spend: total tool calls, per-tool call
// rate, and the size of results flowing back. Capping result size defends
// the context window. An unbounded tool result is the cheapest way for a
// server to flood the model's context.
type Budget struct {
	maxCalls   int
	maxResult  int            // bytes; 0 = unlimited
	rateLimits map[string]int // tool glob → calls per minute
	sink       audit.Sink

	// now is injectable so the sliding window is testable without sleeping.
	now func() time.Time
}

// NewBudget builds the budget check.
func NewBudget(pol config.Policy, sink audit.Sink) *Budget {
	return &Budget{
		maxCalls:   pol.MaxCallsPerSess,
		maxResult:  pol.MaxResultKB * 1024,
		rateLimits: pol.ToolRateLimits,
		sink:       sink,
		now:        time.Now,
	}
}

// Name implements inspect.Check.
func (b *Budget) Name() string { return NameBudget }

// Inspect implements inspect.Check.
func (b *Budget) Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if exposed, ok := isToolCall(m); ok {
		return b.admitCall(ctx, s, m, RealToolName(s, exposed))
	}
	if b.maxResult > 0 && isToolResult(m) {
		b.truncate(ctx, s, m)
	}
	return inspect.AllowAll
}

func (b *Budget) admitCall(ctx context.Context, s inspect.Session, m *inspect.Msg, tool string) inspect.Decision {
	if b.maxCalls > 0 {
		// Increment first: the counter is the admission ticket, so exactly
		// maxCalls calls get through even under concurrent posts.
		if n := atomic.AddInt64(s.Counter(CounterToolCalls), 1); n > int64(b.maxCalls) {
			reason := fmt.Sprintf("session tool-call budget exhausted (%d calls)", b.maxCalls)
			emit(ctx, b.sink, s, audit.Event{
				Type: audit.EventBudgetExceeded, Backend: m.Backend, Tool: tool,
				Rule: NameBudget, Reason: reason,
				Fields: map[string]any{"limit": b.maxCalls, "calls": n},
			})
			return inspect.Denyf(m.Env, jsonrpc.CodeBudgetExceeded, NameBudget, reason)
		}
	}
	limit, ok := b.rateLimitFor(tool)
	if !ok {
		return inspect.AllowAll
	}
	now := b.now()
	windows := s.Meta(metaKeyWindows, func() any { return map[string][]time.Time{} }).(map[string][]time.Time)
	hits := prune(windows[tool], now.Add(-rateWindow))
	if len(hits) >= limit {
		windows[tool] = hits
		reason := fmt.Sprintf("tool %q rate limit exceeded (%d calls/min)", tool, limit)
		emit(ctx, b.sink, s, audit.Event{
			Type: audit.EventBudgetExceeded, Backend: m.Backend, Tool: tool,
			Rule: NameBudget, Reason: reason,
			Fields: map[string]any{"limit_per_min": limit},
		})
		return inspect.Denyf(m.Env, jsonrpc.CodeBudgetExceeded, NameBudget, reason)
	}
	windows[tool] = append(hits, now)
	return inspect.AllowAll
}

// rateLimitFor returns the strictest limit among matching globs. Taking the
// minimum keeps the result independent of map iteration order.
func (b *Budget) rateLimitFor(tool string) (int, bool) {
	best, found := 0, false
	for pattern, limit := range b.rateLimits {
		if limit <= 0 || !Match(pattern, tool) {
			continue
		}
		if !found || limit < best {
			best, found = limit, true
		}
	}
	return best, found
}

// prune drops timestamps that fell out of the window, reusing the backing
// array so a steady call rate does not allocate.
func prune(hits []time.Time, cutoff time.Time) []time.Time {
	keep := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	return keep
}

// isToolResult reports whether m is a successful response to a tools/call.
func isToolResult(m *inspect.Msg) bool {
	return m != nil && m.Env != nil && m.Dir == inspect.S2C &&
		m.Env.IsResponse() && m.Env.Error == nil && len(m.Env.Result) > 0 &&
		m.CorrelatedMethod == mcp.MethodToolsCall
}

// truncate shortens the text leaves of a tool result to fit maxResult,
// rewriting m.Env.Result in place. It leaves non-text content (images,
// resource links) alone: cutting a base64 payload corrupts it instead of
// shortening it.
func (b *Budget) truncate(ctx context.Context, s inspect.Session, m *inspect.Msg) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(m.Env.Result, &result); err != nil {
		return
	}
	var content []json.RawMessage
	if err := json.Unmarshal(result["content"], &content); err != nil || len(content) == 0 {
		return
	}

	total := 0
	for _, raw := range content {
		var item mcp.ContentItem
		if err := json.Unmarshal(raw, &item); err == nil && item.Type == "text" {
			total += len(item.Text)
		}
	}
	if total <= b.maxResult {
		return
	}

	remaining := b.maxResult
	marked := false
	for i, raw := range content {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			continue
		}
		var item mcp.ContentItem
		if err := json.Unmarshal(raw, &item); err != nil || item.Type != "text" {
			continue
		}
		if len(item.Text) <= remaining {
			remaining -= len(item.Text)
			continue
		}
		cut := clipUTF8(item.Text, remaining)
		remaining = 0
		if !marked {
			cut += truncationMarker
			marked = true
		}
		tb, err := json.Marshal(cut)
		if err != nil {
			continue
		}
		fields["text"] = tb
		if out, err := json.Marshal(fields); err == nil {
			content[i] = out
		}
	}

	cb, err := json.Marshal(content)
	if err != nil {
		return
	}
	result["content"] = cb
	out, err := json.Marshal(result)
	if err != nil {
		return
	}
	m.Env.Result = out
	emit(ctx, b.sink, s, audit.Event{
		Type: audit.EventBudgetExceeded, Backend: m.Backend, Tool: m.CorrelatedTool,
		Rule: NameBudget, Reason: "tool result truncated",
		Fields: map[string]any{"limit_bytes": b.maxResult, "result_text_bytes": total},
	})
}

// clipUTF8 cuts s to at most n bytes without splitting a rune.
func clipUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
