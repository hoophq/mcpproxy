package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

func TestPolicyAllowDeny(t *testing.T) {
	cases := []struct {
		name    string
		pol     config.Policy
		tool    string
		want    inspect.Verdict
		reason  string
		listed  bool
		catalog []string
	}{
		{
			name: "no lists allows",
			pol:  config.Policy{}, tool: "read_file", want: inspect.Allow,
		},
		{
			name: "denied glob blocks",
			pol:  config.Policy{DeniedTools: []string{"admin_*"}},
			tool: "admin_reset", want: inspect.Deny, reason: "denied by policy",
		},
		{
			name: "deny wins over allow",
			pol:  config.Policy{AllowedTools: []string{"*"}, DeniedTools: []string{"rm"}},
			tool: "rm", want: inspect.Deny, reason: "denied by policy",
		},
		{
			name: "allow list excludes unlisted",
			pol:  config.Policy{AllowedTools: []string{"read_*"}},
			tool: "write_file", want: inspect.Deny, reason: "not in the allowed set",
		},
		{
			name: "allow list admits match",
			pol:  config.Policy{AllowedTools: []string{"read_*"}},
			tool: "read_file", want: inspect.Allow,
		},
		{
			name: "unadvertised tool blocked after a list",
			pol:  config.Policy{}, tool: "ghost", listed: true, catalog: []string{"read_file"},
			want: inspect.Deny, reason: "not advertised",
		},
		{
			name: "advertised tool passes",
			pol:  config.Policy{}, tool: "read_file", listed: true, catalog: []string{"read_file"},
			want: inspect.Allow,
		},
		{
			name: "unknown tool passes before the first list",
			pol:  config.Policy{}, tool: "ghost", want: inspect.Allow,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSession(t)
			for _, n := range c.catalog {
				s.ObserveTool("be", mcp.Tool{Name: n})
			}
			if c.listed {
				markCatalogListed(s)
			}
			got := NewPolicy(c.pol).Inspect(context.Background(), s, callMsg(t, "be", c.tool, nil))
			if got.Verdict != c.want {
				t.Fatalf("verdict = %s, want %s (reason %q)", verdictString(got.Verdict), verdictString(c.want), got.Reason)
			}
			if c.want != inspect.Deny {
				return
			}
			if !strings.Contains(got.Reason, c.reason) {
				t.Errorf("reason = %q, want it to contain %q", got.Reason, c.reason)
			}
			if got.Reply == nil || got.Reply.Error == nil {
				t.Fatal("deny must carry an error reply")
			}
			if got.Reply.Error.Code != jsonrpc.CodePolicyDenied {
				t.Errorf("code = %d, want CodePolicyDenied", got.Reply.Error.Code)
			}
			if got.Reply.ID.Key() != `1` {
				t.Errorf("reply id = %s, want the request id", got.Reply.ID.Key())
			}
		})
	}
}

// A rename must not let a denied tool through under an alias.
func TestPolicyEvaluatesRealNameThroughAlias(t *testing.T) {
	s := newSession(t)
	rememberRename(s, "safe_helper", "admin_reset")
	p := NewPolicy(config.Policy{DeniedTools: []string{"admin_*"}})
	got := p.Inspect(context.Background(), s, callMsg(t, "be", "safe_helper", nil))
	if got.Verdict != inspect.Deny {
		t.Fatalf("alias to a denied tool must be denied, got %s", verdictString(got.Verdict))
	}
}

func TestPolicyIgnoresNonToolCalls(t *testing.T) {
	s := newSession(t)
	p := NewPolicy(config.Policy{DeniedTools: []string{"*"}})
	m := &inspect.Msg{Dir: inspect.C2S, Env: &jsonrpc.Message{
		JSONRPC: "2.0", ID: rawID("1"), Method: mcp.MethodToolsList,
	}}
	if got := p.Inspect(context.Background(), s, m); got.Verdict != inspect.Allow {
		t.Fatalf("tools/list must pass the tool policy, got %s", verdictString(got.Verdict))
	}
}
