package checks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// Guardrails routes free text through the host's content inspector. Two
// surfaces matter:
//
//   - tool-call arguments, which carry whatever the model was talked into
//     sending (secrets, injected instructions);
//   - tool descriptions, which are prompt input. A poisoned description
//     attacks the model itself, and it compromises the whole catalog, so
//     the check ends the session instead of the single message.
type Guardrails struct {
	guard func(ctx context.Context, dir inspect.Direction, text string) error
	sink  audit.Sink
}

// NewGuardrails builds the guardrail check. hooks.GuardInput must be non-nil;
// Assemble omits the check otherwise.
func NewGuardrails(hooks inspect.Hooks, sink audit.Sink) *Guardrails {
	return &Guardrails{guard: hooks.GuardInput, sink: sink}
}

// Name implements inspect.Check.
func (g *Guardrails) Name() string { return NameGuardrails }

// Inspect implements inspect.Check.
func (g *Guardrails) Inspect(ctx context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	if g.guard == nil || m == nil || m.Env == nil {
		return inspect.AllowAll
	}
	if exposed, ok := isToolCall(m); ok {
		return g.checkArgs(ctx, s, m, exposed)
	}
	if res, ok := toolsListResult(m); ok {
		return g.checkCatalog(ctx, s, m, res)
	}
	return inspect.AllowAll
}

func (g *Guardrails) checkArgs(ctx context.Context, s inspect.Session, m *inspect.Msg, exposed string) inspect.Decision {
	var p mcp.ToolsCallParams
	if err := json.Unmarshal(m.Env.Params, &p); err != nil || len(p.Arguments) == 0 {
		return inspect.AllowAll
	}
	err := g.guard(ctx, inspect.C2S, string(p.Arguments))
	if err == nil {
		return inspect.AllowAll
	}
	tool := RealToolName(s, exposed)
	reason := fmt.Sprintf("guardrail blocked arguments to %q: %v", exposed, err)
	emit(ctx, g.sink, s, audit.Event{
		Type: audit.EventGuardrailBlock, Backend: m.Backend, Tool: tool,
		Rule: NameGuardrails, Reason: reason,
	})
	return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameGuardrails, reason)
}

func (g *Guardrails) checkCatalog(ctx context.Context, s inspect.Session, m *inspect.Msg, res *mcp.ToolsListResult) inspect.Decision {
	for _, raw := range res.Tools {
		var t mcp.Tool
		if err := json.Unmarshal(raw, &t); err != nil || t.Description == "" {
			continue
		}
		err := g.guard(ctx, inspect.S2C, t.Description)
		if err == nil {
			continue
		}
		reason := fmt.Sprintf("guardrail flagged the description of tool %q as poisoned: %v", t.Name, err)
		emit(ctx, g.sink, s, audit.Event{
			Type: audit.EventGuardrailBlock, Backend: m.Backend, Tool: t.Name,
			Rule: NameGuardrails, Reason: reason,
		})
		return inspect.Decision{Verdict: inspect.Kill, Rule: NameGuardrails, Reason: reason}
	}
	return inspect.AllowAll
}
