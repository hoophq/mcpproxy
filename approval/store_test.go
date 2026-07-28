package approval

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/gateway"
)

// recorder is a test audit.Sink.
type recorder struct {
	mu sync.Mutex
	ev []audit.Event
}

func (r *recorder) Emit(_ context.Context, e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
}

func (r *recorder) events() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.ev...)
}

func sampleCall() gateway.HeldCall {
	return gateway.HeldCall{
		Session: "sess-1", User: "alice", Backend: "github",
		Tool: "delete_repo", Args: []byte(`{"repo":"prod"}`), Rule: "destructive",
	}
}

// recv waits for one verdict, failing the test if none arrives.
func recv(t *testing.T, ch <-chan bool) bool {
	t.Helper()
	select {
	case v, ok := <-ch:
		if !ok {
			t.Fatal("resolution channel closed without a verdict")
		}
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolution")
		return false
	}
}

// mustNoVerdict asserts the waiter cannot observe a second decision. A
// closed, drained channel satisfies that; a fresh value does not.
func mustNoVerdict(t *testing.T, ch <-chan bool) {
	t.Helper()
	select {
	case v, ok := <-ch:
		if ok {
			t.Fatalf("unexpected second verdict %v", v)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("channel neither closed nor delivering; waiter would hang")
	}
}

func TestHoldApproveDeliversTrueOnce(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	s := New(time.Minute, rec)

	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if len(id) != 32 { // 16 random bytes, hex-encoded
		t.Fatalf("id = %q, want 32 hex chars", id)
	}

	if err := s.Resolve(id, true); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := recv(t, ch); !got {
		t.Fatal("verdict = false, want true")
	}
	// Exactly once: the channel is drained and closed, so no second verdict
	// reaches the waiter.
	if _, ok := <-ch; ok {
		t.Fatal("channel still open after resolution")
	}

	evs := rec.events()
	if len(evs) != 1 {
		t.Fatalf("emitted %d events, want 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.Type != audit.EventApprovalResolved {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventApprovalResolved)
	}
	if ev.Session != "sess-1" || ev.User != "alice" || ev.Tool != "delete_repo" {
		t.Errorf("event lost call identity: %+v", ev)
	}
	if ev.Fields["approval_id"] != id {
		t.Errorf("approval_id = %v, want %q", ev.Fields["approval_id"], id)
	}
	if ev.Fields["approved"] != true {
		t.Errorf("approved = %v, want true", ev.Fields["approved"])
	}
	if ev.Fields["source"] != sourceAPI {
		t.Errorf("source = %v, want %q", ev.Fields["source"], sourceAPI)
	}
}

func TestHoldRejectDeliversFalse(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)

	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := s.Resolve(id, false); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := recv(t, ch); got {
		t.Fatal("verdict = true, want false")
	}
}

func TestHoldExpiryAutoRejects(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	s := New(20*time.Millisecond, rec)

	_, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if got := recv(t, ch); got {
		t.Fatal("expired call was approved, want auto-reject")
	}
	// Failing closed shows up in the audit trail, distinguishable from a
	// reviewer's deliberate rejection.
	evs := rec.events()
	if len(evs) != 1 {
		t.Fatalf("emitted %d events, want 1", len(evs))
	}
	if evs[0].Fields["source"] != sourceExpiry {
		t.Errorf("source = %v, want %q", evs[0].Fields["source"], sourceExpiry)
	}
	if !strings.Contains(evs[0].Reason, "timed out") {
		t.Errorf("reason = %q, want it to mention the timeout", evs[0].Reason)
	}
}

func TestHoldCallerCancelRejects(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	s := New(time.Minute, rec)

	ctx, cancel := context.WithCancel(t.Context())
	id, ch, err := s.Hold(ctx, sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	cancel()
	if got := recv(t, ch); got {
		t.Fatal("canceled call was approved, want reject")
	}
	// A canceled call must leave the reviewer's queue.
	if len(s.List()) != 0 {
		t.Errorf("List still shows the canceled call: %+v", s.List())
	}
	if err := s.Resolve(id, true); !errors.Is(err, ErrAlreadyResolved) {
		t.Errorf("Resolve after cancel = %v, want ErrAlreadyResolved", err)
	}
	if got := rec.events()[0].Fields["source"]; got != sourceCanceled {
		t.Errorf("source = %v, want %q", got, sourceCanceled)
	}
}

func TestHoldRejectsCanceledContextUpFront(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Hold(ctx, sampleCall()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Hold with dead ctx = %v, want context.Canceled", err)
	}
}

func TestResolveErrors(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)

	if err := s.Resolve("nope", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id = %v, want ErrNotFound", err)
	}

	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := s.Resolve(id, true); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	for _, approve := range []bool{true, false} {
		if err := s.Resolve(id, approve); !errors.Is(err, ErrAlreadyResolved) {
			t.Errorf("Resolve(%v) after resolution = %v, want ErrAlreadyResolved", approve, err)
		}
	}
	// The extra attempts must not push more verdicts at the waiter.
	if got := recv(t, ch); !got {
		t.Fatal("verdict = false, want true")
	}
	mustNoVerdict(t, ch)
}

// TestResolveRaceSingleWinner drives many concurrent resolvers at one call.
// One must succeed, and one verdict must reach the waiter.
func TestResolveRaceSingleWinner(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	id, ch, err := s.Hold(t.Context(), sampleCall())
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = s.Resolve(id, i%2 == 0)
		}()
	}
	close(start)
	wg.Wait()

	winners := 0
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrAlreadyResolved):
		default:
			t.Errorf("resolver %d: unexpected error %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d resolvers succeeded, want exactly 1", winners)
	}
	recv(t, ch)
	mustNoVerdict(t, ch)
}

func TestListReflectsPendingSet(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)

	base := time.Date(2026, 7, 27, 18, 0, 0, 0, time.UTC)
	var clock atomicClock
	clock.set(base)
	s.now = clock.get

	if got := s.List(); len(got) != 0 {
		t.Fatalf("fresh store lists %d calls, want 0", len(got))
	}

	ids := make([]string, 3)
	for i := range ids {
		clock.set(base.Add(time.Duration(i) * time.Second))
		c := sampleCall()
		c.Tool = string(rune('a' + i))
		id, _, err := s.Hold(t.Context(), c)
		if err != nil {
			t.Fatalf("Hold %d: %v", i, err)
		}
		ids[i] = id
	}

	clock.set(base.Add(10 * time.Second))
	got := s.List()
	if len(got) != 3 {
		t.Fatalf("List = %d entries, want 3", len(got))
	}
	// Oldest first, so the reviewer works the queue in arrival order.
	for i, v := range got {
		if v.ID != ids[i] {
			t.Errorf("entry %d id = %q, want %q (unsorted?)", i, v.ID, ids[i])
		}
		wantAge := (10 - float64(i)) // seconds
		if v.AgeSeconds != wantAge {
			t.Errorf("entry %d age = %v, want %v", i, v.AgeSeconds, wantAge)
		}
		if v.Age != time.Duration(wantAge)*time.Second {
			t.Errorf("entry %d Age = %v, want %v", i, v.Age, wantAge)
		}
		if string(v.Args) != `{"repo":"prod"}` {
			t.Errorf("entry %d args = %s, want the raw params", i, v.Args)
		}
		if v.Rule != "destructive" || v.Session != "sess-1" || v.User != "alice" {
			t.Errorf("entry %d lost call metadata: %+v", i, v)
		}
	}

	// Resolving removes it from the pending set at once, even though the
	// record lingers for duplicate detection.
	if err := s.Resolve(ids[1], true); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got = s.List()
	if len(got) != 2 {
		t.Fatalf("after resolve List = %d entries, want 2", len(got))
	}
	for _, v := range got {
		if v.ID == ids[1] {
			t.Error("resolved call still listed as pending")
		}
	}
	if _, ok := s.Get(ids[1]); ok {
		t.Error("Get returned a resolved call")
	}
	if v, ok := s.Get(ids[0]); !ok || v.Tool != "a" {
		t.Errorf("Get(pending) = %+v, %v; want the first call", v, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("Get(unknown) reported ok")
	}
}

// Malformed params must not poison the listing. The view drops them instead
// of emitting invalid JSON to the reviewer.
func TestListDropsInvalidArgs(t *testing.T) {
	t.Parallel()
	s := New(time.Minute, nil)
	c := sampleCall()
	c.Args = []byte(`{not json`)
	if _, _, err := s.Hold(t.Context(), c); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	got := s.List()
	if len(got) != 1 {
		t.Fatalf("List = %d entries, want 1", len(got))
	}
	if got[0].Args != nil {
		t.Errorf("args = %s, want nil for malformed params", got[0].Args)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("listing is unmarshalable: %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	for _, in := range []time.Duration{0, -time.Second} {
		s := New(in, nil)
		if s.timeout != DefaultTimeout {
			t.Errorf("New(%v).timeout = %v, want %v", in, s.timeout, DefaultTimeout)
		}
		if s.sink == nil {
			t.Errorf("New(%v) left a nil sink; Hold would panic on resolve", in)
		}
	}
}

// atomicClock is a mutex-guarded settable clock for deterministic ages.
type atomicClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *atomicClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *atomicClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
