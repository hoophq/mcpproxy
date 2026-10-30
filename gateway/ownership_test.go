package gateway_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hoophq/mcpproxy/audit"
	"github.com/hoophq/mcpproxy/backend"
	"github.com/hoophq/mcpproxy/checks"
	"github.com/hoophq/mcpproxy/config"
	"github.com/hoophq/mcpproxy/gateway"
	"github.com/hoophq/mcpproxy/inspect"
	"github.com/hoophq/mcpproxy/internal/testmcp"
)

type sinkRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *sinkRecorder) Emit(_ context.Context, ev audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *sinkRecorder) count(t audit.EventType) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, ev := range s.events {
		if ev.Type == t {
			n++
		}
	}
	return n
}

// call sends one request as user, with sid when set, and returns the status,
// the session id the gateway answered and the body.
func call(t *testing.T, url, method, user, sid, body string) (int, string, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", user)
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if method == http.MethodGet {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		req = req.WithContext(ctx)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s as %s: %v", method, user, err)
	}
	defer resp.Body.Close()
	var b []byte
	if method != http.MethodGet || resp.StatusCode != http.StatusOK {
		b, _ = io.ReadAll(resp.Body)
	}
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), string(b)
}

// A session belongs to the caller that opened it. Another caller with the id
// gets 404 on POST and GET, a DELETE that ends nothing, and the owner keeps
// working.
func TestSessionIsBoundToItsOpener(t *testing.T) {
	srv := testmcp.New()
	hs := httptest.NewServer(srv.HTTPHandler())
	defer hs.Close()
	rec := &sinkRecorder{}
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{}, rec, false),
		Resolver: func(r *http.Request) (inspect.Identity, error) {
			return inspect.Identity{Subject: r.Header.Get("X-User")}, nil
		},
		Sink: rec,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()

	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`
	const list = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`

	code, sid, body := call(t, front.URL, http.MethodPost, "alice", "", initialize)
	if code != 200 || sid == "" {
		t.Fatalf("alice initialize: %d %s", code, body)
	}

	if code, _, body := call(t, front.URL, http.MethodPost, "mallory", sid, list); code != http.StatusNotFound {
		t.Fatalf("mallory POST on alice's session: %d %s, want 404", code, body)
	}
	if code, _, body := call(t, front.URL, http.MethodGet, "mallory", sid, ""); code != http.StatusNotFound {
		t.Fatalf("mallory GET on alice's session: %d %s, want 404", code, body)
	}
	if code, _, body := call(t, front.URL, http.MethodDelete, "mallory", sid, ""); code != http.StatusNoContent {
		t.Fatalf("mallory DELETE on alice's session: %d %s, want 204 and no effect", code, body)
	}
	if n := rec.count(audit.EventSessionRefused); n != 3 {
		t.Fatalf("session_refused events = %d, want 3", n)
	}

	if code, _, body := call(t, front.URL, http.MethodPost, "alice", sid, list); code != 200 || !strings.Contains(body, `"tools"`) {
		t.Fatalf("alice after mallory: %d %s, want her tools", code, body)
	}
	if code, _, _ := call(t, front.URL, http.MethodDelete, "alice", sid, ""); code != http.StatusNoContent {
		t.Fatalf("alice DELETE: %d, want 204", code)
	}
	if code, _, _ := call(t, front.URL, http.MethodPost, "alice", sid, list); code != http.StatusNotFound {
		t.Fatalf("alice after her DELETE: %d, want 404", code)
	}
}

// callAs is call with an email the resolver reads from X-Email.
func callAs(t *testing.T, url, method, user, email, sid, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", user)
	req.Header.Set("X-Email", email)
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s as %s: %v", method, user, err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id")
}

// The subject owns the session, not the email: a resolver that re-reads a
// changed email must not lock the owner out.
func TestSessionSurvivesAnEmailChange(t *testing.T) {
	srv := testmcp.New()
	hs := httptest.NewServer(srv.HTTPHandler())
	defer hs.Close()
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		Resolver: func(r *http.Request) (inspect.Identity, error) {
			return inspect.Identity{Subject: r.Header.Get("X-User"), Email: r.Header.Get("X-Email")}, nil
		},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`
	const list = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	code, sid := callAs(t, front.URL, http.MethodPost, "alice", "alice@old.example", "", initialize)
	if code != 200 || sid == "" {
		t.Fatalf("initialize: %d", code)
	}
	if code, _ := callAs(t, front.URL, http.MethodPost, "alice", "alice@new.example", sid, list); code != 200 {
		t.Fatalf("POST after an email change: %d, want 200", code)
	}
	if code, _ := callAs(t, front.URL, http.MethodDelete, "alice", "alice@new.example", sid, ""); code != http.StatusNoContent {
		t.Fatalf("DELETE after an email change: %d", code)
	}
	if code, _ := callAs(t, front.URL, http.MethodPost, "alice", "alice@new.example", sid, list); code != http.StatusNotFound {
		t.Fatalf("POST after DELETE: %d, want 404", code)
	}
}

// callKeyed is call with an account key the resolver reads from X-Key.
func callKeyed(t *testing.T, url, method, user, key, sid, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", user)
	req.Header.Set("X-Key", key)
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s as %s: %v", method, user, err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id")
}

// A session is bound to the login and the account key it was opened with:
// a renamed login starts a new session, and another account that takes the
// old login does not get the old one. One session, one login in the audit.
func TestARenamedOrReclaimedLoginDoesNotKeepTheSession(t *testing.T) {
	srv := testmcp.New()
	hs := httptest.NewServer(srv.HTTPHandler())
	defer hs.Close()
	gw, err := gateway.New(gateway.Options{
		Backends: map[string]backend.Factory{
			"main": backend.NewFactory("main", config.Backend{Transport: "streamable-http", URL: hs.URL}, nil),
		},
		Pipeline: checks.Assemble(config.Policy{}, inspect.Hooks{}, audit.Discard, false),
		Resolver: func(r *http.Request) (inspect.Identity, error) {
			return inspect.Identity{Subject: r.Header.Get("X-User"), Key: r.Header.Get("X-Key")}, nil
		},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()
	front := httptest.NewServer(gw.Handler())
	defer front.Close()
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"},"capabilities":{}}}`
	const list = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	code, sid := callKeyed(t, front.URL, http.MethodPost, "alice", "1001", "", initialize)
	if code != 200 || sid == "" {
		t.Fatalf("initialize: %d", code)
	}
	if code, _ := callKeyed(t, front.URL, http.MethodPost, "alice-renamed", "1001", sid, list); code != http.StatusNotFound {
		t.Fatalf("the renamed login on the old session: %d, want 404", code)
	}
	if code, _ := callKeyed(t, front.URL, http.MethodPost, "alice", "2002", sid, list); code != http.StatusNotFound {
		t.Fatalf("another account with the old login: %d, want 404", code)
	}
	if code, _ := callKeyed(t, front.URL, http.MethodDelete, "alice", "2002", sid, ""); code != http.StatusNoContent {
		t.Fatalf("DELETE by another account: %d", code)
	}
	if code, _ := callKeyed(t, front.URL, http.MethodPost, "alice", "1001", sid, list); code != 200 {
		t.Fatalf("the opener after a foreign DELETE: %d, want 200 (it ended nothing)", code)
	}
	if code, sid2 := callKeyed(t, front.URL, http.MethodPost, "alice-renamed", "1001", "", initialize); code != 200 || sid2 == "" || sid2 == sid {
		t.Fatalf("the renamed login starting over: %d sid=%q", code, sid2)
	}
}
