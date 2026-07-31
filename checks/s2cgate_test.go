package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

// mrtrResult builds a tools/call response carrying an MRTR interim result
// that asks the client to satisfy the given server-to-client methods.
func mrtrResult(methods ...string) *inspect.Msg {
	reqs := make([]string, 0, len(methods))
	for i, m := range methods {
		reqs = append(reqs, fmt.Sprintf(`"k%d":{"method":%q,"params":{}}`, i, m))
	}
	body := fmt.Sprintf(`{"resultType":"input_required","inputRequests":{%s}}`,
		strings.Join(reqs, ","))
	return &inspect.Msg{
		Dir: inspect.S2C, Backend: "be",
		CorrelatedMethod: mcp.MethodToolsCall,
		CorrelatedTool:   "echo",
		Env: &jsonrpc.Message{
			JSONRPC: "2.0", ID: rawID("7"), Result: json.RawMessage(body),
		},
	}
}

// Under MCP 2026-07-28 a server no longer sends sampling/elicitation as its
// own request. It answers the client's tools/call with an "input_required"
// result carrying the same ask. The gate's policy must survive that move, or
// adopting the new revision silently disables it.
func TestS2CGateBlocksMRTRInputRequests(t *testing.T) {
	cases := []struct {
		name    string
		pol     config.Policy
		methods []string
		want    inspect.Verdict
	}{
		{"sampling round blocked by default", config.Policy{}, []string{mcp.MethodSamplingCreateMessage}, inspect.Deny},
		{"elicitation round blocked by default", config.Policy{}, []string{mcp.MethodElicitationCreate}, inspect.Deny},
		{"sampling round allowed when opted in", config.Policy{BlockSampling: new(false)}, []string{mcp.MethodSamplingCreateMessage}, inspect.Allow},
		{"one blocked ask in a batch denies the whole round", config.Policy{BlockSampling: new(false)}, []string{mcp.MethodSamplingCreateMessage, mcp.MethodElicitationCreate}, inspect.Deny},
		{"round asking nothing we police passes", config.Policy{}, []string{"roots/list"}, inspect.Allow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewS2CGate(c.pol).Inspect(context.Background(), newSession(t), mrtrResult(c.methods...))
			if got.Verdict != c.want {
				t.Fatalf("verdict = %s, want %s", verdictString(got.Verdict), verdictString(c.want))
			}
		})
	}
}

// Unlike a server-initiated request, an MRTR round is carried on a response
// to the client's own call, so the client is the party waiting and the
// refusal must answer its id.
func TestS2CGateMRTRRepliesToClientRequestID(t *testing.T) {
	got := NewS2CGate(config.Policy{}).Inspect(context.Background(), newSession(t),
		mrtrResult(mcp.MethodSamplingCreateMessage))
	if got.Verdict != inspect.Deny {
		t.Fatalf("want Deny, got %s", verdictString(got.Verdict))
	}
	if got.Reply == nil || got.Reply.ID.Key() != "7" {
		t.Fatalf("reply must answer the client request id 7, got %+v", got.Reply)
	}
}

// An ordinary completed tool result must not be mistaken for a round.
func TestS2CGateAllowsCompleteResults(t *testing.T) {
	m := &inspect.Msg{
		Dir: inspect.S2C, Backend: "be",
		Env: &jsonrpc.Message{
			JSONRPC: "2.0", ID: rawID("7"),
			Result: json.RawMessage(`{"resultType":"complete","content":[{"type":"text","text":"hi"}]}`),
		},
	}
	if got := NewS2CGate(config.Policy{}).Inspect(context.Background(), newSession(t), m); got.Verdict != inspect.Allow {
		t.Fatalf("a complete result must pass, got %s", verdictString(got.Verdict))
	}
}

// A pre-2026 result carries no resultType at all and must pass untouched.
func TestS2CGateAllowsLegacyResults(t *testing.T) {
	m := &inspect.Msg{
		Dir: inspect.S2C, Backend: "be",
		Env: &jsonrpc.Message{
			JSONRPC: "2.0", ID: rawID("7"),
			Result: json.RawMessage(`{"content":[{"type":"text","text":"hi"}]}`),
		},
	}
	if got := NewS2CGate(config.Policy{}).Inspect(context.Background(), newSession(t), m); got.Verdict != inspect.Allow {
		t.Fatalf("a legacy result must pass, got %s", verdictString(got.Verdict))
	}
}
