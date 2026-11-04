package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/internal/testmcp"
)

// killList kills the session on tools/list, on the request or on its
// response.
type killList struct{ dir inspect.Direction }

func (killList) Name() string { return "kill_list" }

func (k killList) Inspect(_ context.Context, _ inspect.Session, m *inspect.Msg) inspect.Decision {
	if m.Dir != k.dir {
		return inspect.AllowAll
	}
	if (m.Env != nil && m.Env.Method == "tools/list") || m.CorrelatedMethod == "tools/list" {
		return inspect.Decision{Verdict: inspect.Kill, Rule: "kill_list", Reason: "catalog refused"}
	}
	return inspect.AllowAll
}

// A check that kills a session ends it as killed, with the check's reason,
// and never as a normal end.
func TestAKillIsAuditedWithItsReason(t *testing.T) {
	for _, c := range []struct {
		name string
		dir  inspect.Direction
	}{
		{"request", inspect.C2S},
		{"response", inspect.S2C},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := httptest.NewServer(testmcp.New().HTTPHandler())
			defer hs.Close()
			rec := &sinkRecorder{}
			gw, err := gateway.New(gateway.Options{
				Backends: map[string]backend.Factory{
					"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
				},
				Pipeline: append(checks.Assemble(config.Policy{}, inspect.Hooks{}, rec, false), killList{dir: c.dir}),
				Sink:     rec,
			})
			if err != nil {
				t.Fatalf("gateway.New: %v", err)
			}
			defer gw.Close()
			front := httptest.NewServer(gw.Handler())
			defer front.Close()

			code, sid, body := call(t, front.URL, http.MethodPost, "alice", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`)
			if code != 200 || sid == "" {
				t.Fatalf("initialize: %d %s", code, body)
			}
			call(t, front.URL, http.MethodPost, "alice", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)

			if n := rec.count(audit.EventSessionEnd); n != 0 {
				t.Fatalf("session_end events = %d, want 0", n)
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			var killed []audit.Event
			for _, ev := range rec.events {
				if ev.Type == audit.EventSessionKilled {
					killed = append(killed, ev)
				}
			}
			if len(killed) != 1 || killed[0].Reason != "catalog refused" || killed[0].Session != sid {
				t.Fatalf("session_killed events = %+v, want one for %s with the check's reason", killed, sid)
			}
		})
	}
}
