package gateway_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/internal/testmcp"
)

// A server that sends more related messages than the S2C queue holds, to a
// client with no GET stream open, must still get its response.
func TestToolCallReturnsWhenServerChattersWithoutGETStream(t *testing.T) {
	srv := testmcp.New()
	srv.SSEResponses(true)
	hs := httptest.NewServer(srv.HTTPHandler())
	defer hs.Close()
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
		},
		Pipeline:       checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()

	c := &tclient{t: t, url: front.URL}
	c.initialize()
	m, code := c.post(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"chatty","arguments":{"count":200}}}`)
	if code != 200 || m["result"] == nil {
		t.Fatalf("tools/call with 200 related notifications and no GET stream: %d %v", code, m)
	}
}
