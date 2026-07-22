package checks

import (
	"context"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

// S2CGate blocks server-initiated requests that turn the client into a
// resource for the server: sampling (the server asks the client's LLM to
// generate text) and elicitation (the server asks the human for input). Both
// invert the trust direction, so both are denied unless the operator opts in.
type S2CGate struct {
	blockSampling    bool
	blockElicitation bool
}

// NewS2CGate builds the server-request gate. A nil Block* pointer means
// "unset", which resolves to blocked — the safe default documented on
// config.Policy.
func NewS2CGate(pol config.Policy) *S2CGate {
	return &S2CGate{
		blockSampling:    boolOrTrue(pol.BlockSampling),
		blockElicitation: boolOrTrue(pol.BlockElicitation),
	}
}

func boolOrTrue(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

// Name implements inspect.Check.
func (g *S2CGate) Name() string { return NameS2CGate }

// Inspect implements inspect.Check.
func (g *S2CGate) Inspect(_ context.Context, _ inspect.Session, m *inspect.Msg) inspect.Decision {
	if m == nil || m.Env == nil || m.Dir != inspect.S2C || m.Env.Method == "" {
		return inspect.AllowAll
	}
	var blocked bool
	var reason string
	switch m.Env.Method {
	case mcp.MethodSamplingCreateMessage:
		blocked, reason = g.blockSampling, "sampling/createMessage is blocked by policy"
	case mcp.MethodElicitationCreate:
		blocked, reason = g.blockElicitation, "elicitation/create is blocked by policy"
	default:
		return inspect.AllowAll
	}
	if !blocked {
		return inspect.AllowAll
	}
	// The reply answers the *server's* request id, not any client request:
	// the backend is the one left waiting, and the gateway sends this error
	// back down to it.
	return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameS2CGate, reason)
}
