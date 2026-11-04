package gateway_test

import (
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
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`

func newGatewayTo(t *testing.T, url string) (string, *sinkRecorder) {
	t.Helper()
	sink := &sinkRecorder{}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: url}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{}, sink, false),
		Sink:     sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { front.Close(); gw.Close() })
	return front.URL, sink
}

// An initialize the upstream does not answer opens no session: the client
// gets the cause, not a session id on which every later call fails.
func TestAFailedInitializeHandsOutNoSession(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported protocol version"}}`))
	}))
	t.Cleanup(refusing.Close)

	for _, tc := range []struct{ name, url, cause string }{
		{"upstream down", down.URL, "connection refused"},
		{"upstream refuses", refusing.URL, "unsupported protocol version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, sink := newGatewayTo(t, tc.url)
			code, sid, body := call(t, url, http.MethodPost, "", "", initializeBody)
			if sid != "" {
				t.Fatalf("initialize answered session %q: %d %s", sid, code, body)
			}
			if !strings.Contains(body, tc.cause) {
				t.Fatalf("the error does not name the cause: %d %s", code, body)
			}
			if sink.count(audit.EventSessionStart) != sink.count(audit.EventSessionEnd) {
				t.Fatal("the session of the failed initialize is still open")
			}
		})
	}
}
