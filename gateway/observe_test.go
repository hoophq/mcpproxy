package gateway_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

type observed struct {
	mu   sync.Mutex
	msgs []string
}

func (o *observed) ObserveMessage(dir inspect.Direction, _, method, tool, decision string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.msgs = append(o.msgs, fmt.Sprintf("%v|%s|%s|%s", dir, method, tool, decision))
}

func (o *observed) count(msg string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, m := range o.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

// A message refused before the pipeline still reaches the observer as a
// deny, so a host that counts denials from it misses none.
func TestAMessageRefusedBeforeThePipelineIsObserved(t *testing.T) {
	up := httptest.NewServer(testmcp.New().HTTPHandler())
	t.Cleanup(up.Close)
	obs := &observed{}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: up.URL}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		Observer: obs,
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { front.Close(); gw.Close() })
	c := &tclient{t: t, url: front.URL}
	c.initialize()

	for i, tc := range []struct{ msg, code string }{
		{`"method":"tools/call","params":{"name":"slow","arguments":{},"Arguments":{}}`, "-32602"},
		{`"method":"tools/call","params":{"name":"echo"},"Method":"ping"`, "-32600"},
	} {
		m, code := c.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,%s}`, 10+i, tc.msg))
		if code != http.StatusOK || fmt.Sprint(errorCode(m)) != tc.code {
			t.Errorf("%s: %d %v, want %s", tc.msg, code, m, tc.code)
		}
	}
	c2s := fmt.Sprint(inspect.C2S)
	if n := obs.count(c2s + "|tools/call|slow|deny"); n != 1 {
		t.Errorf("invalid params observed %d times, want 1: %v", n, obs.msgs)
	}
	if n := obs.count(c2s + "|tools/call|echo|deny"); n != 1 {
		t.Errorf("folded field observed %d times, want 1: %v", n, obs.msgs)
	}
}
