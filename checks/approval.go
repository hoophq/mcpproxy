package checks

import (
	"context"
	"fmt"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
)

// Approval marks tool calls that need a human decision. The check does not
// wait for anything: it returns Hold and the gateway parks the message in its
// HeldStore, resuming or refusing it when a reviewer answers.
type Approval struct {
	tools []string
	// held reports whether an approval store is wired. Without one a Hold
	// would strand the call forever, so the check refuses instead — failing
	// closed is the only safe reading of "this tool needs approval".
	held bool
}

// NewApproval builds the approval-marker check. heldEnabled must reflect
// whether the gateway has a HeldStore.
func NewApproval(pol config.Policy, heldEnabled bool) *Approval {
	return &Approval{tools: pol.ApprovalTools, held: heldEnabled}
}

// Name implements inspect.Check.
func (a *Approval) Name() string { return NameApproval }

// Inspect implements inspect.Check.
func (a *Approval) Inspect(_ context.Context, s inspect.Session, m *inspect.Msg) inspect.Decision {
	exposed, ok := isToolCall(m)
	if !ok || len(a.tools) == 0 {
		return inspect.AllowAll
	}
	tool := RealToolName(s, exposed)
	if !MatchAny(a.tools, tool) {
		return inspect.AllowAll
	}
	if !a.held {
		return inspect.Denyf(m.Env, jsonrpc.CodePolicyDenied, NameApproval,
			fmt.Sprintf("tool %q requires approval but no approval store is configured", exposed))
	}
	return inspect.Decision{
		Verdict: inspect.Hold,
		Rule:    NameApproval,
		Reason:  fmt.Sprintf("tool %q requires approval", exposed),
	}
}
