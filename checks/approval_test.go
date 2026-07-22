package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
)

func TestApproval(t *testing.T) {
	pol := config.Policy{ApprovalTools: []string{"deploy_*", "delete_file"}}
	cases := []struct {
		name string
		tool string
		held bool
		want inspect.Verdict
	}{
		{"match holds when a store exists", "deploy_prod", true, inspect.Hold},
		{"literal match holds", "delete_file", true, inspect.Hold},
		{"non-match allows", "read_file", true, inspect.Allow},
		{"match denies without a store", "deploy_prod", false, inspect.Deny},
		{"non-match still allows without a store", "read_file", false, inspect.Allow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSession(t)
			got := NewApproval(pol, c.held).Inspect(context.Background(), s, callMsg(t, "be", c.tool, nil))
			if got.Verdict != c.want {
				t.Fatalf("verdict = %s, want %s", verdictString(got.Verdict), verdictString(c.want))
			}
			switch c.want {
			case inspect.Hold:
				if got.Rule != NameApproval {
					t.Errorf("rule = %q, want %q", got.Rule, NameApproval)
				}
				if got.Reply != nil {
					t.Error("hold must not synthesize a reply; the gateway parks the call")
				}
			case inspect.Deny:
				if got.Reply == nil || got.Reply.Error == nil {
					t.Fatal("deny must carry an error reply")
				}
				if got.Reply.Error.Code != jsonrpc.CodePolicyDenied {
					t.Errorf("code = %d, want CodePolicyDenied", got.Reply.Error.Code)
				}
				if !strings.Contains(got.Reason, "approval") {
					t.Errorf("reason = %q, want it to mention approval", got.Reason)
				}
			}
		})
	}
}

func TestApprovalUsesRealName(t *testing.T) {
	s := newSession(t)
	rememberRename(s, "harmless", "deploy_prod")
	a := NewApproval(config.Policy{ApprovalTools: []string{"deploy_*"}}, true)
	if got := a.Inspect(context.Background(), s, callMsg(t, "be", "harmless", nil)); got.Verdict != inspect.Hold {
		t.Fatalf("aliased approval-gated tool must hold, got %s", verdictString(got.Verdict))
	}
}

func TestApprovalNoRulesIsNoOp(t *testing.T) {
	s := newSession(t)
	a := NewApproval(config.Policy{}, false)
	if got := a.Inspect(context.Background(), s, callMsg(t, "be", "anything", nil)); got.Verdict != inspect.Allow {
		t.Fatalf("no approval rules must allow, got %s", verdictString(got.Verdict))
	}
}
