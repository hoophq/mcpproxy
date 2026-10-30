// Package inspect defines the gateway's message-inspection pipeline: every
// JSON-RPC message crossing the gateway, in either direction, flows through
// an ordered chain of Checks that may allow, mutate, deny, hold, or kill.
package inspect

import (
	"context"
	"encoding/json"

	"github.com/hoophq/mcpproxy/jsonrpc"
)

// Direction of a message relative to the gateway.
type Direction int

const (
	// C2S is client → server (requests from the agent/LLM side).
	C2S Direction = iota
	// S2C is server → client (responses and server-initiated requests).
	S2C
)

func (d Direction) String() string {
	if d == C2S {
		return "c2s"
	}
	return "s2c"
}

// Verdict is a check's decision for one message.
type Verdict int

const (
	// Allow forwards the (possibly mutated) message.
	Allow Verdict = iota
	// Deny replaces a request with a JSON-RPC error; the session lives.
	Deny
	// Hold parks the message pending an external decision (approvals).
	Hold
	// Kill terminates the entire session.
	Kill
)

// Msg is the unit flowing through the pipeline. A check may mutate Env in
// place; the gateway re-marshals it after the chain runs.
type Msg struct {
	Dir     Direction
	Backend string // backend name (aggregation); "" for single-backend
	Env     *jsonrpc.Message

	// Correlated holds request info when Env is a response: the method and
	// tool name of the request this answers. Empty otherwise.
	CorrelatedMethod string
	CorrelatedTool   string
}

// Decision is the pipeline outcome for one message.
type Decision struct {
	Verdict Verdict
	// Reply carries the synthesized error response on Deny, headed back
	// toward the requester.
	Reply *jsonrpc.Message
	// Reason is a human-readable explanation (audit + error message).
	Reason string
	// Rule names the rule/check that decided (audit).
	Rule string
	// HoldID identifies a held message for later resolution.
	HoldID string
}

// Check is one stage of the pipeline. Checks run in order; the first
// non-Allow verdict wins. Checks may mutate m.Env in place (filtering,
// redaction, overrides) and still return Allow.
type Check interface {
	Name() string
	Inspect(ctx context.Context, s Session, m *Msg) Decision
}

// Identity is the authenticated caller. Inbound auth resolves it, or an
// embedding host like hoop injects it.
type Identity struct {
	Subject string
	Email   string
	// Key is the stable key of the account when Subject alone is not one: a
	// GitHub login can be renamed and reclaimed, so that resolver sets the
	// numeric id here. A session is bound to the subject and the key.
	Key    string
	Claims map[string]any
}

// Session is the per-MCP-session state shared by all checks. Concrete state
// lives in the session package; this interface keeps inspect dependency-free.
type Session interface {
	ID() string
	Identity() Identity
	// ToolKnown reports whether name appeared in a (filtered) tools/list.
	ToolKnown(backend, name string) bool
	// Counter returns a named monotonic counter scoped to the session.
	Counter(name string) *int64
	// Meta returns arbitrary per-session state for a check, creating it
	// with mk on first use. Requests of one session run concurrently, so
	// the value must guard its own state.
	Meta(key string, mk func() any) any
}

// AllowAll is the zero decision.
var AllowAll = Decision{Verdict: Allow}

// Denyf builds a Deny decision answering req with a policy error.
func Denyf(req *jsonrpc.Message, code int, rule, reason string) Decision {
	return Decision{
		Verdict: Deny,
		Reply:   jsonrpc.NewError(req.ID, code, reason),
		Reason:  reason,
		Rule:    rule,
	}
}

// RawTool extracts the tool name from tools/call params without full decode.
func RawTool(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Name
}
