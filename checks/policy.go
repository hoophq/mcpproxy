package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
)

// Policy enforces the allow/deny tool lists and refuses calls to tools the
// server never advertised.
type Policy struct {
	allowed []string
	denied  []string
}

// NewPolicy builds the allow/deny check.
func NewPolicy(pol config.Policy) *Policy {
	return &Policy{allowed: pol.AllowedTools, denied: pol.DeniedTools}
}

// Name implements inspect.Check.
func (p *Policy) Name() string { return NamePolicy }

// Inspect implements inspect.Check.
func (p *Policy) Inspect(_ context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if m.Dir == inspect.S2C {
		p.filterCatalog(s, m)
		return inspect.AllowAll
	}
	exposed, ok := isToolCall(m)
	if !ok {
		return inspect.AllowAll
	}
	// Evaluate the real (pre-override) name: an alias must not launder a
	// call the operator denied.
	tool := RealToolName(s, exposed)

	// Deny wins over allow, unconditionally.
	if MatchAny(p.denied, tool) {
		return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NamePolicy,
			fmt.Sprintf("tool %q is denied by policy", exposed))
	}
	if len(p.allowed) > 0 && !MatchAny(p.allowed, tool) {
		return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NamePolicy,
			fmt.Sprintf("tool %q is not in the allowed set", exposed))
	}
	// A tool absent from the advertised catalog is either a client guess or
	// a shadowed name. The catalog holds real (pre-override) names, so the
	// un-aliased name is the one to look up. Only enforceable once a
	// tools/list has completed — before that the catalog is legitimately
	// empty and every call would fail.
	if catalogListed(s) && !toolAdvertised(s, m.Backend, tool) {
		return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NamePolicy,
			fmt.Sprintf("tool %q was not advertised by the server", exposed))
	}
	return inspect.AllowAll
}

// filterCatalog removes denied and non-allowlisted tools from a tools/list
// response before the client ever sees them: a tool the model cannot see is
// a tool it can never call. Runs on the real (pre-override) names — the
// overrides check renames later in the chain.
func (p *Policy) filterCatalog(_ inspect.Session, m *inspect.Msg) {
	if len(p.allowed) == 0 && len(p.denied) == 0 {
		return
	}
	res, ok := toolsListResult(m)
	if !ok {
		return
	}
	kept := res.Tools[:0]
	for _, raw := range res.Tools {
		// Aggregated catalogs carry "<backend>_<tool>" names; match both
		// the prefixed and bare spellings so a single policy works in
		// both modes.
		name := rawName(raw)
		bare := name
		if m.Backend != "" {
			bare = strings.TrimPrefix(name, m.Backend+"_")
		}
		if MatchAny(p.denied, name) || MatchAny(p.denied, bare) {
			continue
		}
		if len(p.allowed) > 0 && !MatchAny(p.allowed, name) && !MatchAny(p.allowed, bare) {
			continue
		}
		kept = append(kept, raw)
	}
	if len(kept) == len(res.Tools) {
		return
	}
	res.Tools = kept
	if b, err := json.Marshal(res); err == nil {
		m.Env.Result = b
	}
}
