package gateway

import (
	"context"
	"sync"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/session"
)

type eventLog struct {
	mu     sync.Mutex
	events []audit.Event
}

func (l *eventLog) Emit(_ context.Context, ev audit.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
}

// A normal teardown (DELETE, idle reap, gateway close, backend death) that
// wins the race against a kill already decided still ends the session as
// killed, with the kill's reason.
func TestATeardownRacingAKillKeepsTheReason(t *testing.T) {
	log := &eventLog{}
	c := &conn{g: &Gateway{sink: log}, state: session.New("s1", inspect.Identity{}), done: make(chan struct{})}
	reason := "catalog refused"
	c.killReason.Store(&reason)
	c.shutdown(nil)
	c.shutdown(nil)
	if len(log.events) != 1 || log.events[0].Type != audit.EventSessionKilled || log.events[0].Reason != reason {
		t.Fatalf("events = %+v, want one session_killed with %q", log.events, reason)
	}
}
