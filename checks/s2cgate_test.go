package checks

import (
	"context"
	"testing"

	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/jsonrpc"
	"github.com/hoophq/mcpproxy/mcp"
)

func serverReq(method, id string) *inspect.Msg {
	return &inspect.Msg{
		Dir: inspect.S2C, Backend: "be",
		Env: &jsonrpc.Message{JSONRPC: "2.0", ID: rawID(id), Method: method},
	}
}

func TestS2CGate(t *testing.T) {
	cases := []struct {
		name   string
		pol    config.Policy
		method string
		want   inspect.Verdict
	}{
		{"sampling blocked by default", config.Policy{}, mcp.MethodSamplingCreateMessage, inspect.Deny},
		{"elicitation blocked by default", config.Policy{}, mcp.MethodElicitationCreate, inspect.Deny},
		{"sampling allowed when opted in", config.Policy{BlockSampling: new(false)}, mcp.MethodSamplingCreateMessage, inspect.Allow},
		{"elicitation allowed when opted in", config.Policy{BlockElicitation: new(false)}, mcp.MethodElicitationCreate, inspect.Allow},
		{"explicit block stays blocked", config.Policy{BlockSampling: new(true)}, mcp.MethodSamplingCreateMessage, inspect.Deny},
		{"opting into sampling does not open elicitation", config.Policy{BlockSampling: new(false)}, mcp.MethodElicitationCreate, inspect.Deny},
		{"unrelated server request passes", config.Policy{}, mcp.MethodPing, inspect.Allow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewS2CGate(c.pol).Inspect(context.Background(), newSession(t), serverReq(c.method, "42"))
			if got.Verdict != c.want {
				t.Fatalf("verdict = %s, want %s", verdictString(got.Verdict), verdictString(c.want))
			}
		})
	}
}

// The backend is the party left waiting, so the refusal must answer the
// server request's own id, not any client id.
func TestS2CGateRepliesToServerRequestID(t *testing.T) {
	m := serverReq(mcp.MethodSamplingCreateMessage, `"srv-99"`)
	got := NewS2CGate(config.Policy{}).Inspect(context.Background(), newSession(t), m)
	if got.Verdict != inspect.Deny {
		t.Fatalf("want Deny, got %s", verdictString(got.Verdict))
	}
	if got.Reply == nil {
		t.Fatal("deny must carry a reply for the waiting server")
	}
	if got.Reply.ID.Key() != `"srv-99"` {
		t.Errorf("reply id = %s, want the server request id \"srv-99\"", got.Reply.ID.Key())
	}
	if got.Reply.Error == nil || got.Reply.Error.Code != jsonrpc.CodePolicyDenied {
		t.Errorf("reply must be a CodePolicyDenied error, got %+v", got.Reply.Error)
	}
}

// The same method arriving from the client is not a server request.
func TestS2CGateIgnoresC2S(t *testing.T) {
	m := &inspect.Msg{
		Dir: inspect.C2S,
		Env: &jsonrpc.Message{JSONRPC: "2.0", ID: rawID("1"), Method: mcp.MethodSamplingCreateMessage},
	}
	if got := NewS2CGate(config.Policy{}).Inspect(context.Background(), newSession(t), m); got.Verdict != inspect.Allow {
		t.Fatalf("gate must only judge S2C traffic, got %s", verdictString(got.Verdict))
	}
}
