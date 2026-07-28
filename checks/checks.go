// Package checks implements every stage of the gateway's inspection
// pipeline: policy enforcement, approvals, server-request gating, rug-pull
// detection, catalog overrides, budgets, guardrail hooks, redaction, and the
// terminal audit tap.
//
// A check keeps no state beyond what it stores on the session (via
// inspect.Session.Meta / Counter), so you can drop or reorder one without
// touching its neighbours. Assemble fixes the one order that matters for
// security.
package checks

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/mcp"
)

// Check names, used as the audit `rule` when a check does not set a more
// specific one.
const (
	NameBudget     = "budget"
	NamePolicy     = "policy"
	NameApproval   = "approval"
	NameS2CGate    = "s2c_gate"
	NameRugPull    = "rug_pull"
	NameOverrides  = "overrides"
	NameGuardrails = "guardrails"
	NameRedact     = "redact"
	NameAuditTap   = "audit_tap"
)

// Session meta keys. Namespaced so host-supplied checks cannot collide.
const (
	metaKeyRenames = "checks.overrides.renames" // exposed tool name → real name
	metaKeyListed  = "checks.policy.listed"     // *bool: a tools/list has completed
	metaKeyWindows = "checks.budget.windows"    // rate-limit sliding windows
)

// Assemble builds the canonical pipeline. The order is load-bearing:
//
//  1. budget: cheapest refusal first, so an exhausted budget spends no
//     policy evaluation and no approval round-trip.
//  2. policy: allow/deny lists and "tool was never advertised".
//  3. approval: reached only by calls policy already permitted.
//  4. s2c gate: server-initiated sampling and elicitation.
//  5. rug pull: fingerprints the catalog *before* overrides rewrite it, so
//     detection sees what the server sent.
//  6. overrides: renames or redescribes the catalog, and un-renames calls.
//  7. guardrails: inspects the post-override text the backend will receive.
//  8. redaction: masks result text on the way back.
//  9. audit tap: terminal, always allows, records what survived.
//
// Assemble omits guardrails and redaction when their hook is nil. A check
// with no hook cannot fire, and it would still cost a pass over every
// message.
func Assemble(pol config.Policy, hooks inspect.Hooks, sink audit.Sink, heldEnabled bool) []inspect.Check {
	out := make([]inspect.Check, 0, 9)
	out = append(out,
		NewBudget(pol, sink),
		NewPolicy(pol),
		NewApproval(pol, heldEnabled),
		NewS2CGate(pol),
		NewRugPull(pol, sink),
		NewOverrides(pol),
	)
	if hooks.GuardInput != nil {
		out = append(out, NewGuardrails(hooks, sink))
	}
	if hooks.Redact != nil {
		out = append(out, NewRedactor(hooks, sink))
	}
	return append(out, NewAuditTap(sink))
}

// catalog is the slice of session.State the rug-pull check needs.
// inspect.Session omits it to stay free of MCP types, so the check asserts
// for it and degrades to a no-op when the host supplies its own session
// implementation.
type catalog interface {
	ObserveTool(backend string, t mcp.Tool) (prev string, known bool)
	InvalidateTools(backend string)
}

// emit stamps the session-scoped fields every check would otherwise repeat.
func emit(ctx context.Context, sink audit.Sink, s inspect.Session, ev audit.Event) {
	if sink == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ev.Session = s.ID()
	if ev.User == "" {
		ev.User = s.Identity().Subject
	}
	sink.Emit(ctx, ev)
}

// isToolCall reports whether m is a client tools/call request and returns the
// tool name as it appears on the wire.
func isToolCall(m *inspect.Msg) (string, bool) {
	if m == nil || m.Env == nil || m.Dir != inspect.C2S || m.Env.Method != mcp.MethodToolsCall {
		return "", false
	}
	return inspect.RawTool(m.Env.Params), true
}

// toolsListResult decodes a successful tools/list response. It hands back the
// raw tool entries untouched so callers can rewrite individual fields without
// dropping properties the gateway does not model.
func toolsListResult(m *inspect.Msg) (*mcp.ToolsListResult, bool) {
	if m == nil || m.Env == nil || m.Dir != inspect.S2C {
		return nil, false
	}
	if !m.Env.IsResponse() || m.Env.Error != nil || len(m.Env.Result) == 0 {
		return nil, false
	}
	if m.CorrelatedMethod != mcp.MethodToolsList {
		return nil, false
	}
	var res mcp.ToolsListResult
	if err := json.Unmarshal(m.Env.Result, &res); err != nil {
		return nil, false
	}
	return &res, true
}

// rawName reads the "name" field of a raw JSON object.
func rawName(raw json.RawMessage) string {
	var t struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &t)
	return t.Name
}

func metaStrings(s inspect.Session, key string) map[string]string {
	return s.Meta(key, func() any { return map[string]string{} }).(map[string]string)
}

// RealToolName maps a client-visible tool name back to the name the backend
// knows, undoing an override rename. Checks that run before the overrides
// stage must call this so policy, approvals, and budgets evaluate the real
// tool. Otherwise an alias would launder a denied call.
func RealToolName(s inspect.Session, exposed string) string {
	if real, ok := metaStrings(s, metaKeyRenames)[exposed]; ok {
		return real
	}
	return exposed
}

// rememberRename records an exposed→real mapping.
func rememberRename(s inspect.Session, exposed, real string) {
	mm := metaStrings(s, metaKeyRenames)
	mm[exposed] = real
	// Under aggregation the catalog carries "<backend>_<tool>" names but the
	// gateway strips that prefix before a tools/call reaches the pipeline.
	// Index the bare pair too so the un-rename still fires.
	i, j := strings.IndexByte(exposed, '_'), strings.IndexByte(real, '_')
	if i >= 0 && j >= 0 && exposed[:i] == real[:j] {
		mm[exposed[i+1:]] = real[j+1:]
	}
}

// markCatalogListed records that a tools/list completed without a rug pull.
// Only the rug-pull check calls it: that stage populates the catalog via
// ObserveTool, so flag and contents flip together. Splitting the two across
// checks would let the policy check refuse tools against an empty catalog.
func markCatalogListed(s inspect.Session) {
	*s.Meta(metaKeyListed, func() any { return new(bool) }).(*bool) = true
}

func catalogListed(s inspect.Session) bool {
	return *s.Meta(metaKeyListed, func() any { return new(bool) }).(*bool)
}

// toolAdvertised reports whether name appeared in a tools/list the client
// received.
//
// The gateway records the merged catalog under the empty backend name (the
// fan-out has no single origin) while a tools/call is inspected with its
// resolved backend and the aggregation prefix already stripped. Probing all
// three spellings keeps the check correct in both single-backend and
// aggregated deployments.
func toolAdvertised(s inspect.Session, backend, name string) bool {
	return s.ToolKnown(backend, name) ||
		s.ToolKnown("", name) ||
		(backend != "" && s.ToolKnown("", backend+"_"+name))
}
