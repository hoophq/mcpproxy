// Package approval implements the hold-and-review parking lot: the place a
// tool call waits while a human decides whether it may run.
//
// # Flow
//
// A check in the inspect pipeline returns inspect.Hold for a call it will not
// decide on its own. The gateway hands that call to a HeldStore
// (gateway.Options.Held) and blocks the client's JSON-RPC request on the
// returned channel:
//
//	pipeline → inspect.Hold → gateway.holdForApproval → Store.Hold
//	                                                      │
//	          reviewer lists pending calls over HTTP  ←────┤ (parked)
//	          reviewer POSTs /approve or /reject      ─────┤
//	                                                      ▼
//	                                          channel yields true/false
//	                          gateway forwards to the backend, or answers
//	                          the client with CodeApprovalRejected
//
// A call resolves once. The reviewer, the expiry timer and the client's own
// cancellation all race for it; the first one through sets the verdict and the
// rest get [ErrAlreadyResolved]. The timer rejects any call nobody reviews
// within the configured timeout, so a forgotten approval fails closed rather
// than hanging a session forever.
//
// # Reviewing
//
// [NewAPI] exposes the store over HTTP. The daemon mounts it under
// /approvals, so a reviewer works with plain curl:
//
//	# list parked calls
//	curl -s -H "Authorization: Bearer $MCPPROXY_APPROVAL_TOKEN" \
//	     http://localhost:8080/approvals/
//	[{"id":"6f1c...","session":"s-1","user":"alice","backend":"github",
//	  "tool":"delete_repo","args":{"repo":"prod"},"rule":"destructive",
//	  "created":"2026-07-27T18:12:04Z","age_seconds":12.4}]
//
//	# let it through
//	curl -s -X POST -H "Authorization: Bearer $MCPPROXY_APPROVAL_TOKEN" \
//	     http://localhost:8080/approvals/6f1c.../approve   # 204
//
//	# or refuse it
//	curl -s -X POST -H "Authorization: Bearer $MCPPROXY_APPROVAL_TOKEN" \
//	     http://localhost:8080/approvals/6f1c.../reject    # 204
//
// # Audit
//
// The store emits [audit.EventApprovalResolved] for every resolution with the
// reason and the source behind it ("api", "expiry" or "canceled"). The gateway
// emits its own pending/resolved pair around the wait; the store's event
// records which of the three paths decided the call.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/gateway"
)

// Errors returned by [Store.Resolve] and surfaced as HTTP status codes by the
// API: ErrNotFound → 404, ErrAlreadyResolved → 409.
var (
	// ErrNotFound means the id was never issued, or its record has aged out
	// of the resolved-retention window.
	ErrNotFound = errors.New("approval: no such pending call")
	// ErrAlreadyResolved means somebody (a reviewer, the expiry timer or the
	// client hanging up) got there first.
	ErrAlreadyResolved = errors.New("approval: call already resolved")
)

// Resolution sources, recorded on the audit event so a reviewer reading the
// log can tell a deliberate decision from a timeout.
const (
	sourceAPI      = "api"
	sourceExpiry   = "expiry"
	sourceCanceled = "canceled"
)

// DefaultTimeout applies when [New] gets a non-positive timeout. It matches
// config.Approvals' default.
const DefaultTimeout = 5 * time.Minute

// entry is one parked call. Its channel is buffered so resolution never blocks
// on a caller that has already given up.
type entry struct {
	id      string
	call    gateway.HeldCall
	created time.Time
	ch      chan bool

	// done flips exactly once, under Store.mu. Resolved entries linger for a
	// retention window so a duplicate resolve reports 409 rather than 404.
	done bool

	expiry  *time.Timer // fires the timeout rejection
	unwatch func() bool // stops the context.AfterFunc watching the caller
}

// Store parks held calls in memory and hands out resolution channels. It
// implements gateway.HeldStore. The zero value is not usable; call [New].
//
// State lives in-process: a restart drops pending approvals, which is the safe
// direction, since the waiting clients are gone too.
type Store struct {
	timeout time.Duration
	sink    audit.Sink
	now     func() time.Time // test seam

	mu      sync.Mutex
	entries map[string]*entry
}

// compile-time proof the store satisfies the gateway seam.
var _ gateway.HeldStore = (*Store)(nil)

// New builds a Store. timeout bounds how long a call may wait before the timer
// rejects it; <= 0 means [DefaultTimeout]. sink may be nil (events are
// discarded). The same duration doubles as the retention window for resolved
// records, so a late duplicate resolve gets a 409 instead of a 404.
func New(timeout time.Duration, sink audit.Sink) *Store {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if sink == nil {
		sink = audit.Discard
	}
	return &Store{
		timeout: timeout,
		sink:    sink,
		now:     time.Now,
		entries: make(map[string]*entry),
	}
}

// Hold parks h and returns its id plus a channel that yields exactly one
// verdict: true if a reviewer approved, false if a reviewer rejected, the
// timeout fired, or ctx was canceled.
//
// The channel is buffered, so the caller may abandon it (the gateway does when
// its request context dies) without leaking a goroutine here.
func (s *Store) Hold(ctx context.Context, h gateway.HeldCall) (string, <-chan bool, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, fmt.Errorf("approval: hold: %w", err)
	}
	id, err := newID()
	if err != nil {
		return "", nil, err
	}

	e := &entry{
		id:      id,
		call:    h,
		created: s.now(),
		ch:      make(chan bool, 1),
	}

	// Registration and timer wiring happen under one lock: either callback can
	// fire before AfterFunc returns, and finish() reads both fields.
	s.mu.Lock()
	s.entries[id] = e
	// Fail closed: the timer rejects an approval no reviewer answers.
	e.expiry = time.AfterFunc(s.timeout, func() {
		_ = s.finish(id, false, "approval timed out", sourceExpiry)
	})
	// A client that hangs up releases its slot in the reviewer's queue.
	e.unwatch = context.AfterFunc(ctx, func() {
		_ = s.finish(id, false, "caller canceled", sourceCanceled)
	})
	s.mu.Unlock()

	return id, e.ch, nil
}

// Resolve records a reviewer's decision. It returns [ErrNotFound] for an
// unknown id and [ErrAlreadyResolved] if the call was already decided.
func (s *Store) Resolve(id string, approve bool) error {
	reason := "rejected by reviewer"
	if approve {
		reason = "approved by reviewer"
	}
	return s.finish(id, approve, reason, sourceAPI)
}

// finish is the single resolution path. Exactly one caller wins the race
// between reviewer, expiry timer and context cancellation.
func (s *Store) finish(id string, approve bool, reason, source string) error {
	s.mu.Lock()
	e, ok := s.entries[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if e.done {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrAlreadyResolved, id)
	}
	e.done = true
	ch := e.ch
	call, created := e.call, e.created
	expiry, unwatch := e.expiry, e.unwatch
	s.mu.Unlock()

	// Release the timers outside the lock. Stop and the context stop func do
	// not run the callback, yet both may race a callback that wants s.mu.
	if expiry != nil {
		expiry.Stop()
	}
	if unwatch != nil {
		unwatch()
	}
	// Keep the record for the retention window so a duplicate resolve is a 409.
	time.AfterFunc(s.timeout, func() { s.forget(id) })

	now := s.now()
	// Audit before unblocking the waiter: the gateway resumes the tool call as
	// soon as it reads the channel, so the record of the decision has to land
	// first. Sinks are non-blocking by contract.
	s.sink.Emit(context.Background(), audit.Event{
		Time:    now,
		Type:    audit.EventApprovalResolved,
		Session: call.Session,
		User:    call.User,
		Backend: call.Backend,
		Tool:    call.Tool,
		Rule:    call.Rule,
		Reason:  reason,
		Fields: map[string]any{
			"approval_id": id,
			"approved":    approve,
			"source":      source,
			"waited_ms":   now.Sub(created).Milliseconds(),
		},
	})

	ch <- approve // buffered(1), never sent twice: guarded by e.done
	close(ch)
	return nil
}

func (s *Store) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
}

// PendingView is the reviewer-facing projection of a parked call.
type PendingView struct {
	ID      string          `json:"id"`
	Session string          `json:"session"`
	User    string          `json:"user,omitempty"`
	Backend string          `json:"backend,omitempty"`
	Tool    string          `json:"tool,omitempty"`
	Args    json.RawMessage `json:"args,omitempty"`
	Rule    string          `json:"rule,omitempty"`
	Created time.Time       `json:"created"`
	// Age is how long the call has been waiting. The wire form is
	// age_seconds, because a raw time.Duration marshals to nanoseconds.
	Age        time.Duration `json:"-"`
	AgeSeconds float64       `json:"age_seconds"`
}

// List returns every still-pending call, oldest first. Resolved records are
// excluded even while they linger for duplicate detection.
func (s *Store) List() []PendingView {
	now := s.now()
	s.mu.Lock()
	out := make([]PendingView, 0, len(s.entries))
	for _, e := range s.entries {
		if e.done {
			continue
		}
		out = append(out, e.view(now))
	}
	s.mu.Unlock()

	slices.SortFunc(out, func(a, b PendingView) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		// Same instant (fake clocks, coarse timers): keep output stable.
		return cmpString(a.ID, b.ID)
	})
	return out
}

// Get returns the view of a single pending call. ok is false for unknown or
// already-resolved ids.
func (s *Store) Get(id string) (PendingView, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok || e.done {
		return PendingView{}, false
	}
	return e.view(now), true
}

// view projects an entry. Caller holds s.mu (or owns the entry).
func (e *entry) view(now time.Time) PendingView {
	age := now.Sub(e.created)
	v := PendingView{
		ID:         e.id,
		Session:    e.call.Session,
		User:       e.call.User,
		Backend:    e.call.Backend,
		Tool:       e.call.Tool,
		Rule:       e.call.Rule,
		Created:    e.created,
		Age:        age,
		AgeSeconds: age.Seconds(),
	}
	// Args arrive as the raw JSON-RPC params. Only pass through what is valid
	// JSON: one malformed blob must not break the whole listing.
	if json.Valid(e.call.Args) {
		v.Args = json.RawMessage(e.call.Args)
	}
	return v
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("approval: generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
