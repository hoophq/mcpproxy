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
// "unset", which resolves to blocked, the safe default documented on
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
	if m == nil || m.Env == nil || m.Dir != inspect.S2C {
		return inspect.AllowAll
	}
	if m.Env.Method == "" {
		return g.inspectResult(m)
	}
	blocked, reason := g.ruleFor(m.Env.Method)
	if !blocked {
		return inspect.AllowAll
	}
	// The reply answers the *server's* request id, not any client request:
	// the backend is the one left waiting, and the gateway sends this error
	// back down to it.
	return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameS2CGate, reason)
}

// inspectResult applies the same policy to a Multi Round-Trip Request interim
// result, the shape that replaced server-initiated requests in MCP
// 2026-07-28.
//
// The server no longer asks the client directly. It answers the client's own
// tools/call with resultType "input_required" and an inputRequests map naming
// the sampling or elicitation it wants. Same inversion of trust, carried on a
// response instead of a request — so the method switch above never sees it,
// and without this arm the gate's default-deny would silently stop applying
// the moment a backend adopts the new revision.
//
// Denying answers the *client's* request id, unlike the request arm: here the
// client is the one waiting, and it must not be handed a prompt the operator
// blocked.
func (g *S2CGate) inspectResult(m *inspect.Msg) inspect.Decision {
	if !mcp.ResultRequiresInput(m.Env.Result) {
		return inspect.AllowAll
	}
	for _, method := range mcp.InputRequestMethods(m.Env.Result) {
		if blocked, reason := g.ruleFor(method); blocked {
			return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameS2CGate, reason)
		}
	}
	return inspect.AllowAll
}

// ruleFor reports whether a server-to-client request method is blocked, and
// why. Shared by both arms so a request and an MRTR input request for the
// same capability can never resolve differently.
func (g *S2CGate) ruleFor(method string) (blocked bool, reason string) {
	switch method {
	case mcp.MethodSamplingCreateMessage:
		return g.blockSampling, "sampling/createMessage is blocked by policy"
	case mcp.MethodElicitationCreate:
		return g.blockElicitation, "elicitation/create is blocked by policy"
	default:
		return false, ""
	}
}
