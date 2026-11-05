package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/hoophq/mcpproxy/jsonrpc"
)

// A Redact hook error withholds the result: the client gets a policy error
// that does not quote the text, and the session keeps serving.
func TestRedactHookErrorWithholdsResult(t *testing.T) {
	t.Parallel()
	hs := httptest.NewServer(testmcp.New().HTTPHandler())
	defer hs.Close()
	redact := func(_ context.Context, text string) (string, int, error) {
		if strings.Contains(text, "BOOM") {
			return "", 0, errors.New("masker down")
		}
		n := strings.Count(text, "SECRET")
		return strings.ReplaceAll(text, "SECRET", "[REDACTED]"), n, nil
	}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{Redact: redact}, audit.Discard, false),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()

	c := &tclient{t: t, url: front.URL}
	c.initialize()

	_, body := c.postRaw(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"pw":"BOOM"}}}`)
	if strings.Contains(body, "BOOM") {
		t.Fatalf("withheld text reached the client: %s", body)
	}
	var resp jsonrpc.Message
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("bad response %q: %v", body, err)
	}
	if resp.Error == nil || resp.Error.Code != jsonrpc.CodePolicyDenied || resp.Result != nil {
		t.Fatalf("response = %s, want a %d error and no result", body, jsonrpc.CodePolicyDenied)
	}

	m, _ := c.post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"pw":"SECRET"}}}`)
	if out := mustJSON(m["result"]); !strings.Contains(out, "[REDACTED]") || strings.Contains(out, "SECRET") {
		t.Fatalf("next call on the session: %v, want a masked result", m)
	}
}

// The gateway correlates a tasks/result response, so the redactor masks it.
func TestRedactMasksTasksResult(t *testing.T) {
	t.Parallel()
	be := newFakeBE("main")
	maskOK := func(_ context.Context, text string) (string, int, error) {
		n := strings.Count(text, "ok")
		return strings.ReplaceAll(text, "ok", "[MASKED]"), n, nil
	}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{"main": func(context.Context) (backend.Backend, error) { return be, nil }},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{Redact: maskOK}, audit.Discard, false),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()

	c := &tclient{t: t, url: front.URL}
	c.initialize()
	m, _ := c.post(`{"jsonrpc":"2.0","id":5,"method":"tasks/result","params":{"taskId":"t1"}}`)
	if out := mustJSON(m["result"]); !strings.Contains(out, "[MASKED]") {
		t.Fatalf("tasks/result = %v, want the fake result text masked", m)
	}
}
