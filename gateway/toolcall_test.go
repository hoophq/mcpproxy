package gateway_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
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

// upstreamCalls counts the tools/call requests an upstream received.
type upstreamCalls struct {
	mu sync.Mutex
	n  int
}

func (u *upstreamCalls) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.n
}

// newCallGateway is newTestGateway with an audit sink and a count of the
// tools/call requests that reached the upstream.
func newCallGateway(t *testing.T, pol config.Policy) (*tclient, *upstreamCalls, *sinkRecorder) {
	t.Helper()
	calls := &upstreamCalls{}
	srv := testmcp.New().HTTPHandler()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"tools/call"`)) {
			calls.mu.Lock()
			calls.n++
			calls.mu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		srv.ServeHTTP(w, r)
	}))
	t.Cleanup(up.Close)
	sink := &sinkRecorder{}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: up.URL}, nil),
		},
		Pipeline: checks.Assemble(pol, inspect.Hooks{}, sink, false),
		Sink:     sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(gw.Handler())
	t.Cleanup(func() { front.Close(); gw.Close() })
	c := &tclient{t: t, url: front.URL}
	c.initialize()
	return c, calls, sink
}

func errorCode(m map[string]any) int {
	e, _ := m["error"].(map[string]any)
	code, _ := e["code"].(float64)
	return int(code)
}

// The upstream reads params by their exact keys. Params a check would read
// differently, because Go matches keys without case, are refused as invalid
// before any check runs and never reach the upstream.
func TestToolCallParamsEqualWithoutCaseAreRefused(t *testing.T) {
	c, calls, sink := newCallGateway(t, config.Policy{DeniedTools: []string{"echo"}})
	for i, params := range []string{
		`{"name":"echo","Name":"slow","arguments":{}}`,
		`{"Name":"slow","name":"echo","arguments":{}}`,
		`{"name":"slow","arguments":{"ms":1},"argumentſ":{"ms":2}}`,
		`{"Name":"slow","arguments":{}}`,
		`{"name":"slow","ARGUMENTS":{"ms":1}}`,
	} {
		m, code := c.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}`, 10+i, params))
		if code != http.StatusOK || errorCode(m) != -32602 {
			t.Errorf("params %s: %d %v", params, code, m)
		}
	}
	if n := calls.count(); n != 0 {
		t.Fatalf("the upstream received %d calls, want none", n)
	}
	if n := sink.count(audit.EventToolDenied); n != 5 {
		t.Fatalf("audited %d refusals, want 5", n)
	}
}

// A 16 MiB body holds hundreds of thousands of keys, so the duplicate check
// must be linear: a pairwise one is a CPU denial of service.
func TestToolCallParamsWithManyKeysAreCheckedQuickly(t *testing.T) {
	c, calls, _ := newCallGateway(t, config.Policy{})
	var b strings.Builder
	b.WriteString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}`)
	for i := range 200000 {
		fmt.Fprintf(&b, `,"k%d":0`, i)
	}
	b.WriteString(`,"Name":"slow"}}`)
	limit := time.Second
	if raceEnabled() {
		limit *= 10 // the race detector slows encoding/json about tenfold
	}
	start := time.Now()
	m, code := c.post(b.String())
	if d := time.Since(start); d > limit {
		t.Fatalf("200000 keys took %v", d)
	}
	if code != http.StatusOK || errorCode(m) != -32602 {
		t.Fatalf("%d %v", code, m)
	}
	if n := calls.count(); n != 0 {
		t.Fatalf("the upstream received %d calls, want none", n)
	}
}

func TestANormalToolCallStillRuns(t *testing.T) {
	c, calls, _ := newCallGateway(t, config.Policy{DeniedTools: []string{"slow"}})
	m, _ := c.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo", "arguments": {"text":"hi"},"_meta":{"progressToken":1}}}`)
	if m["result"] == nil || !strings.Contains(mustJSON(m["result"]), `\"text\":\"hi\"`) {
		t.Fatalf("echo: %v", m)
	}
	if n := calls.count(); n != 1 {
		t.Fatalf("the upstream received %d calls, want 1", n)
	}
}

func raceEnabled() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
}
