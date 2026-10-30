package gateway_test

// End-to-end gateway tests over an in-process testmcp backend. They drive
// the full path a client takes (HTTP front → pipeline → backend → response),
// which covers jsonrpc and session along the way.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/internal/testmcp"
)

// newTestGateway wires a gateway over N in-process testmcp HTTP servers.
func newTestGateway(t *testing.T, pol config.Policy, names ...string) (*httptest.Server, func()) {
	t.Helper()
	if len(names) == 0 {
		names = []string{"main"}
	}
	factories := map[string]backend.Factory{}
	var cleanups []func()
	for _, name := range names {
		srv := testmcp.New()
		hs := httptest.NewServer(srv.HTTPHandler())
		cleanups = append(cleanups, hs.Close)
		cfg := config.Backend{Transport: "streamable-http", URL: hs.URL}
		factories[name] = backend.NewFactory(name, cfg, nil)
	}
	gw, err := gateway.New(gateway.Options{
		Backends: factories,
		Pipeline: checks.Assemble(pol, inspect.Hooks{}, audit.Discard, false),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	front := httptest.NewServer(gw.Handler())
	return front, func() {
		front.Close()
		gw.Close()
		for _, c := range cleanups {
			c()
		}
	}
}

type tclient struct {
	t       *testing.T
	url     string
	sid     string
	version string // sent as MCP-Protocol-Version when set
}

func (c *tclient) request(body string) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, c.url+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	if c.version != "" {
		req.Header.Set("MCP-Protocol-Version", c.version)
	}
	return req
}

// postRaw returns the status and the body as sent, error bodies included.
func (c *tclient) postRaw(body string) (int, string) {
	c.t.Helper()
	resp, err := http.DefaultClient.Do(c.request(body))
	if err != nil {
		c.t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *tclient) post(body string) (map[string]any, int) {
	c.t.Helper()
	resp, err := http.DefaultClient.Do(c.request(body))
	if err != nil {
		c.t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sid = sid
	}
	b, _ := io.ReadAll(resp.Body)
	if len(bytes.TrimSpace(b)) == 0 || resp.StatusCode >= 400 {
		// Error statuses carry plain-text bodies (http.Error), not JSON.
		return nil, resp.StatusCode
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatalf("bad response %q: %v", b, err)
	}
	return m, resp.StatusCode
}

func (c *tclient) initialize() {
	c.t.Helper()
	m, _ := c.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`)
	if m["result"] == nil {
		c.t.Fatalf("initialize failed: %v", m)
	}
	if c.sid == "" {
		c.t.Fatal("no session id returned")
	}
	c.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	// Populate the session catalog so unadvertised-tool enforcement has a
	// baseline, matching what a real client does.
	c.post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
}

func toolNames(t *testing.T, m map[string]any) []string {
	t.Helper()
	res, _ := m["result"].(map[string]any)
	raw, _ := res["tools"].([]any)
	var names []string
	for _, ti := range raw {
		tm, _ := ti.(map[string]any)
		names = append(names, tm["name"].(string))
	}
	return names
}

func TestRoundTripSingleBackend(t *testing.T) {
	t.Parallel()
	front, done := newTestGateway(t, config.Policy{})
	defer done()
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"ping"}}}`)
	if m["error"] != nil {
		t.Fatalf("echo failed: %v", m["error"])
	}
	if !strings.Contains(mustJSON(m["result"]), "ping") {
		t.Fatalf("result does not echo input: %v", m["result"])
	}
}

func TestDeniedToolGetsPolicyError(t *testing.T) {
	t.Parallel()
	front, done := newTestGateway(t, config.Policy{DeniedTools: []string{"echo"}})
	defer done()
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`)
	errObj, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected policy error, got %v", m)
	}
	if int(errObj["code"].(float64)) != -32010 {
		t.Fatalf("expected CodePolicyDenied, got %v", errObj)
	}
	// Session must survive the denial.
	m, _ = c.post(`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`)
	if m["result"] == nil {
		t.Fatalf("session died after deny: %v", m)
	}
}

func TestAllowlistFiltersToolsList(t *testing.T) {
	t.Parallel()
	front, done := newTestGateway(t, config.Policy{AllowedTools: []string{"echo"}})
	defer done()
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`)
	names := toolNames(t, m)
	for _, n := range names {
		if n != "echo" {
			t.Fatalf("allowlist leak: %q in %v", n, names)
		}
	}
	if len(names) != 1 {
		t.Fatalf("expected exactly [echo], got %v", names)
	}
}

func TestAggregationPrefixesAndRoutes(t *testing.T) {
	t.Parallel()
	front, done := newTestGateway(t, config.Policy{}, "alpha", "beta")
	defer done()
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`)
	names := toolNames(t, m)
	var sawAlpha, sawBeta bool
	for _, n := range names {
		if strings.HasPrefix(n, "alpha_") {
			sawAlpha = true
		}
		if strings.HasPrefix(n, "beta_") {
			sawBeta = true
		}
	}
	if !sawAlpha || !sawBeta {
		t.Fatalf("expected both prefixes in %v", names)
	}

	m, _ = c.post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"alpha_echo","arguments":{"text":"routed"}}}`)
	if m["error"] != nil {
		t.Fatalf("prefixed call failed: %v", m["error"])
	}
	if !strings.Contains(mustJSON(m["result"]), "routed") {
		t.Fatalf("bad result: %v", m["result"])
	}
}

// testmcp negotiates 2025-06-18. A client that echoes it, as the spec requires
// since that revision, is served; one that echoes another version is refused
// and told which version its session speaks.
func TestEchoedVersionJudgedAgainstNegotiated(t *testing.T) {
	front, stop := newTestGateway(t, config.Policy{})
	defer stop()
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	c.version = testmcp.ProtocolVersion
	if m, code := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`); code != 200 || m["result"] == nil {
		t.Fatalf("echoing the negotiated version: %d %v", code, m)
	}

	c.version = "2025-11-25"
	code, body := c.postRaw(`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, `"code":-32022`) {
		t.Fatalf("echoing another version: %d %s", code, body)
	}
	if !strings.Contains(body, `"supported":["`+testmcp.ProtocolVersion+`"]`) || !strings.Contains(body, `"requested":"2025-11-25"`) {
		t.Fatalf("refusal does not name the session's version: %s", body)
	}

	c.version = ""
	if m, code := c.post(`{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}`); code != 200 || m["result"] == nil {
		t.Fatalf("no header: %d %v", code, m)
	}
}

func TestUnknownSessionRejected(t *testing.T) {
	t.Parallel()
	front, done := newTestGateway(t, config.Policy{})
	defer done()
	c := &tclient{t: t, url: front.URL, sid: "deadbeef"}
	_, status := c.post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown session, got %d", status)
	}
}

func TestBudgetMaxCalls(t *testing.T) {
	t.Parallel()
	front, done := newTestGateway(t, config.Policy{MaxCallsPerSess: 2})
	defer done()
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	for i := range 2 {
		m, _ := c.post(`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"text":"a"}}}`)
		if m["error"] != nil {
			t.Fatalf("call %d unexpectedly denied: %v", i+1, m["error"])
		}
	}
	m, _ := c.post(`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{"text":"a"}}}`)
	errObj, ok := m["error"].(map[string]any)
	if !ok || int(errObj["code"].(float64)) != -32012 {
		t.Fatalf("expected CodeBudgetExceeded on 3rd call, got %v", m)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
