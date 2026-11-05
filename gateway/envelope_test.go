package gateway_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
)

// foldingUpstream decodes messages into structs, as mcp-go does, so it
// matches keys without case. It records the tools it runs.
func foldingUpstream(t *testing.T) (string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var ran []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var env struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(b, &env)
		result := map[string]string{
			"initialize": `{"protocolVersion":"2025-06-18","serverInfo":{"name":"f","version":"0"},"capabilities":{}}`,
			"tools/list": `{"tools":[{"name":"echo","inputSchema":{"type":"object"}},{"name":"delete_all","inputSchema":{"type":"object"}}]}`,
			"tools/call": `{"content":[]}`,
		}[env.Method]
		if result == "" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if env.Method == "tools/call" {
			mu.Lock()
			ran = append(ran, env.Params.Name)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, env.ID, result)
	}))
	t.Cleanup(up.Close)
	return up.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), ran...)
	}
}

// A top-level key equal to a JSON-RPC field without case is refused: the
// gateway judges "params" while a server that folds keys reads "paramſ".
func TestAJSONRPCFieldInAnotherCaseIsRefused(t *testing.T) {
	url, ran := foldingUpstream(t)
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: url}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{DeniedTools: []string{"delete_all"}}, inspect.Hooks{}, audit.Discard, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { front.Close(); gw.Close() })
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	for i, msg := range []string{
		`"method":"tools/call","params":{"name":"echo"},"paramſ":{"name":"delete_all"}`,
		`"method":"tools/call","params":{"name":"echo"},"Method":"ping"`,
	} {
		m, code := c.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,%s}`, 10+i, msg))
		if code != http.StatusOK || errorCode(m) != -32600 {
			t.Errorf("%s: %d %v", msg, code, m)
		}
	}
	if got := ran(); len(got) != 0 {
		t.Fatalf("the upstream ran %v, want nothing", got)
	}
	if m, _ := c.post(`{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"echo"}}`); m["result"] == nil {
		t.Fatalf("echo: %v", m)
	}
}
