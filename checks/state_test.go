package checks

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
)

// Requests of one session run concurrently. The race detector guards the
// alias table and the listed flag; the counts guard the admission.
func TestRenamesAndListedFlagUnderConcurrentRequests(t *testing.T) {
	s := newSession(t)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			rememberRename(s, fmt.Sprintf("be_alias_%d", i), "be_real")
			markCatalogListed(s)
		}()
		go func() {
			defer wg.Done()
			_ = RealToolName(s, "alias_0")
			_ = catalogListed(s)
		}()
	}
	wg.Wait()
	if RealToolName(s, "alias_3") != "real" || !catalogListed(s) {
		t.Fatalf("state lost under concurrency: %q listed=%v", RealToolName(s, "alias_3"), catalogListed(s))
	}
}

func TestBudgetRateLimitIsExactUnderConcurrentCalls(t *testing.T) {
	s, rec, ctx := newSession(t), &recorder{}, context.Background()
	b := NewBudget(config.Policy{ToolRateLimits: map[string]int{"search_*": 8}}, rec)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }

	msgs := make([]*inspect.Msg, 32)
	for i := range msgs {
		msgs[i] = callMsg(t, "be", "search_code", nil)
	}
	var wg sync.WaitGroup
	var allowed, denied atomic.Int64
	for _, m := range msgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch b.Inspect(ctx, s, m).Verdict {
			case inspect.Allow:
				allowed.Add(1)
			case inspect.Deny:
				denied.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 8 || denied.Load() != 24 {
		t.Fatalf("allowed=%d denied=%d, want 8/24", allowed.Load(), denied.Load())
	}
}
