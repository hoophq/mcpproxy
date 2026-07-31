package gateway

import (
	"strings"
	"testing"
)

// This file guards the invariant that lets the gateway stay on the Legacy
// path: several security controls only work because a session accumulates
// state across requests. Serving MCP 2026-07-28 statelessly without re-keying
// that state does not degrade those controls gracefully — it disables them
// silently, because each one is written to no-op when its state is empty:
//
//   - checks/policy.go gates unadvertised-tool enforcement on catalogListed,
//     which is set by a tools/list. Fresh state per request means the flag is
//     never set and the check never fires.
//   - checks/checks.go RealToolName consults a rename map populated by
//     tools/list. An empty map means an alias reaches the backend unmapped,
//     which is precisely what the map exists to prevent.
//   - checks/budget.go counts tool calls in a session counter. A counter that
//     resets every request enforces no cap at all.
//
// None of these would fail a test or log a warning; the gateway would keep
// answering and stop enforcing. So the blocker list is the load-bearing
// safeguard, and emptying it is a security change, not a feature flag.

func TestStatelessBlockersNotEmpty(t *testing.T) {
	g := &Gateway{}
	blockers := g.statelessBlockers()
	if len(blockers) == 0 {
		t.Fatal(`statelessBlockers() is empty, which enables the stateless path.

Before removing the last blocker, confirm each control below enforces
correctly with no session, because each one FAILS OPEN rather than closed:

  - unadvertised-tool enforcement (checks/policy.go, catalogListed)
  - alias un-renaming           (checks/checks.go, RealToolName)
  - per-session call budgets    (checks/budget.go, CounterToolCalls)

Add a test that exercises a cold tools/call — one with no preceding
tools/list — and asserts each control still denies. The existing gateway
tests all call initialize() and tools/list first, so they pass either way.`)
	}
	for i, b := range blockers {
		if strings.TrimSpace(b) == "" {
			t.Errorf("blocker %d is blank; it must name the control that needs a session", i)
		}
	}
}

// The refusal must stay conformant even as the blocker list changes: a client
// reads the supported list to decide what to retry with.
func TestStatelessBlockersSurfaceInRefusal(t *testing.T) {
	g := &Gateway{log: discardLogger()}
	for _, b := range g.statelessBlockers() {
		if !strings.Contains(b, "session") {
			t.Errorf("blocker %q does not explain the session dependency", b)
		}
	}
}
